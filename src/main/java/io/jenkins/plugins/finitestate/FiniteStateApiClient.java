package io.jenkins.plugins.finitestate;

import hudson.model.TaskListener;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import net.sf.json.JSON;
import net.sf.json.JSONArray;
import net.sf.json.JSONNull;
import net.sf.json.JSONObject;
import net.sf.json.JSONSerializer;

/**
 * Thin client for the Finite State public v0 REST API (`/api/public/v0`).
 *
 * <p>Replaces the deprecated CLT jar: every operation the CLT performed (resolve project/version,
 * upload an artifact, trigger processing, poll status) is here as a direct HTTPS call authenticated
 * with the customer's API token via the {@code X-Authorization} header.
 *
 * <p>Instances are created on the build <em>agent</em> (inside {@link FiniteStateScanCallable}) so the
 * artifact bytes stream from the node straight to storage and never transit the controller. Not
 * serializable by design. JSON is handled with {@code net.sf.json} (bundled with Jenkins via
 * Stapler), so no extra plugin dependency is required.
 */
final class FiniteStateApiClient {

    private static final String USER_AGENT = "FiniteState-Jenkins-Plugin";
    private static final int MAX_ATTEMPTS = 3; // NFR-2: up to 3 attempts on transient failures
    private static final long POLL_INTERVAL_MS = 10_000L;

    // Terminal scan statuses (ScanStatusEnum in finite-state-api/src/schemas/common.schema.ts).
    private static final Set<String> SUCCESS_TERMINAL =
            Set.of("COMPLETED", "COMPLETED_WITH_WARNINGS", "NOT_APPLICABLE");
    private static final Set<String> FAILURE_TERMINAL = Set.of("ERROR", "CANCELLED", "UPLOAD_FAILED");

    private final String baseUrl;
    private final String apiToken;
    private final String subdomain;
    private final TaskListener listener;
    private final HttpClient http;

    FiniteStateApiClient(String subdomain, String apiToken, TaskListener listener) {
        this.subdomain = subdomain;
        this.baseUrl = "https://" + subdomain + "/api/public/v0";
        this.apiToken = apiToken;
        this.listener = listener;
        this.http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(30))
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
    }

    // ========================================================================
    // Orchestration — one method per analysis type. Populate the ScanResult.
    // ========================================================================

    /** Binary analysis: create context → upload (put/multipart) → start → (optional) poll. */
    void runBinary(File file, FiniteStateScanRequest req, ScanResult result)
            throws FiniteStateApiException, InterruptedException, IOException {
        String projectId = resolveProjectId(req.getProjectName());
        String versionId = resolveOrCreateVersionId(projectId, req.getVersion(), req.isPreRelease());
        result.setProjectId(projectId);
        result.setVersionId(versionId);
        result.setUiUrl(buildUiUrl(subdomain, projectId, versionId));

        JSONObject scanConfig = buildBinaryScanConfig(req);
        String sha256 = sha256(file);
        BinaryContext ctx = createBinaryScanContext(versionId, file.getName(), file.length(), scanConfig, sha256);

        if ("multipart".equals(ctx.uploadMethod)) {
            log("Uploading binary via multipart (" + ctx.partCount + " parts)...");
            JSONArray parts = uploadMultipart(file, ctx);
            completeBinaryUpload(ctx.scanContextId, parts);
        } else {
            log("Uploading binary...");
            putFile(ctx.uploadUrl, file, "application/octet-stream");
        }

        List<String> scanIds = startBinaryScan(ctx.scanContextId);
        scanIds.forEach(result::addScanId);
        log("Started " + scanIds.size() + " scan(s) for binary analysis.");

        finishWithPolling(req, scanIds, result);
    }

    /** SBOM import: resolve project/version → server-side single-shot upload (auto-detected CycloneDX/SPDX) → poll. */
    void runSbom(File file, FiniteStateScanRequest req, ScanResult result)
            throws FiniteStateApiException, InterruptedException, IOException {
        String projectId = resolveProjectId(req.getProjectName());
        String versionId = resolveOrCreateVersionId(projectId, req.getVersion(), req.isPreRelease());
        result.setProjectId(projectId);
        result.setVersionId(versionId);
        result.setUiUrl(buildUiUrl(subdomain, projectId, versionId));

        String format = detectSbomFormat(file);
        log("Detected SBOM format: " + format);
        // Server-side single-shot upload (the file goes to the API, which uploads to storage and
        // triggers processing). Avoids a client->storage PUT that a WAF can block on scan content.
        String query = "projectVersionId=" + enc(versionId)
                + "&type=" + ("spdx".equals(format) ? "spdx" : "cdx")
                + "&filename=" + enc(file.getName());
        String scanId = ingestSingleShot("/scans/sbom", query, file, "Upload SBOM");
        result.addScanId(scanId);
        log("SBOM import submitted (scan " + scanId + ").");

        finishWithPolling(req, List.of(scanId), result);
    }

    /** Third-party scan import: resolve project/version → server-side single-shot upload (scanner = scanType) → poll. */
    void runThirdParty(File file, FiniteStateScanRequest req, ScanResult result)
            throws FiniteStateApiException, InterruptedException, IOException {
        String projectId = resolveProjectId(req.getProjectName());
        String versionId = resolveOrCreateVersionId(projectId, req.getVersion(), req.isPreRelease());
        result.setProjectId(projectId);
        result.setVersionId(versionId);
        result.setUiUrl(buildUiUrl(subdomain, projectId, versionId));

        // Server-side single-shot upload (see runSbom) — the API uploads the file and triggers
        // third-party processing in one call, so scanner output never transits a client->storage PUT.
        String query = "projectVersionId=" + enc(versionId)
                + "&type=" + enc(req.getScanType())
                + "&filename=" + enc(file.getName());
        String scanId = ingestSingleShot("/scans/third-party", query, file, "Upload third-party scan");
        result.addScanId(scanId);
        log("Third-party scan submitted (scan " + scanId + ", scanner " + req.getScanType() + ").");

        finishWithPolling(req, List.of(scanId), result);
    }

    /**
     * FR-7: when waitForCompletion is set, poll to a terminal state (or timeout) and set the build
     * outcome from the scan status; otherwise return success once processing is accepted.
     */
    private void finishWithPolling(FiniteStateScanRequest req, List<String> scanIds, ScanResult result)
            throws InterruptedException, FiniteStateApiException {
        if (!req.isWaitForCompletion()) {
            result.setFinalStatus("SUBMITTED");
            result.setSuccess(true);
            return;
        }
        log("Waiting for completion (timeout " + req.getPollTimeoutMinutes() + " min)...");
        PollOutcome outcome = pollUntilTerminal(scanIds, req.getPollTimeoutMinutes());
        result.setFinalStatus(outcome.status);
        result.setSuccess(outcome.success);
    }

    // ========================================================================
    // Project / version resolution (FR-3)
    // ========================================================================

    String resolveProjectId(String projectName) throws FiniteStateApiException, InterruptedException {
        HttpResponse<String> resp = execGet(
                apiReq("/projects?filter=" + enc("name==\"" + escapeRsql(projectName) + "\""))
                        .GET()
                        .build(),
                "Projects list");
        JSONObject existing = findByName(parse(resp.body()), projectName);
        if (existing != null) {
            return requireText(existing, "id", "Projects list");
        }
        JSONObject body = new JSONObject();
        body.element("name", projectName);
        body.element("description", projectName);
        body.element("type", "application");
        HttpResponse<String> created = execPost(
                apiReq("/projects")
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(body.toString()))
                        .build(),
                "Project create");
        return requireText(asObject(parse(created.body())), "id", "Project create");
    }

    String resolveOrCreateVersionId(String projectId, String versionName, boolean preRelease)
            throws FiniteStateApiException, InterruptedException {
        String existingId = findVersionIdByName(projectId, versionName);
        if (existingId != null) {
            return existingId;
        }
        JSONObject body = new JSONObject();
        body.element("version", versionName);
        body.element("releaseType", preRelease ? "PRE-RELEASE" : "RELEASE");
        try {
            HttpResponse<String> created = execPost(
                    apiReq("/projects/" + projectId + "/versions")
                            .header("Content-Type", "application/json")
                            .POST(HttpRequest.BodyPublishers.ofString(body.toString()))
                            .build(),
                    "Version create");
            return requireText(asObject(parse(created.body())), "id", "Version create");
        } catch (FiniteStateApiException e) {
            // create_version returns 409 when the name already exists in the branch. The versions
            // list endpoint ignores ?filter, so a pre-existing version beyond our scan window lands
            // here — re-resolve it by name rather than failing the build.
            if (e.getStatusCode() == 409) {
                String found = findVersionIdByName(projectId, versionName);
                if (found != null) {
                    return found;
                }
            }
            throw e;
        }
    }

    /**
     * Resolve a version ID by name. The versions list endpoint silently ignores the RSQL `filter`
     * param (confirmed against the API: the handler reads only offset/limit), so we page through the
     * (newest-first) list and match client-side, bounded by a safety cap.
     */
    private String findVersionIdByName(String projectId, String versionName)
            throws FiniteStateApiException, InterruptedException {
        final int pageSize = 200;
        final int maxScan = 10_000; // bound the scan; rare projects with more versions fall through to 409-recheck
        for (int offset = 0; offset < maxScan; offset += pageSize) {
            HttpResponse<String> resp = execGet(
                    apiReq("/projects/" + projectId + "/versions?offset=" + offset + "&limit=" + pageSize)
                            .GET()
                            .build(),
                    "Versions list");
            JSON parsed = parse(resp.body());
            JSONObject match = findByName(parsed, versionName);
            if (match != null) {
                return requireText(match, "id", "Versions list");
            }
            int size = parsed instanceof JSONArray ? ((JSONArray) parsed).size() : 0;
            if (size < pageSize) {
                break; // last page
            }
        }
        return null;
    }

    // ========================================================================
    // Binary scan endpoints
    // ========================================================================

    BinaryContext createBinaryScanContext(
            String versionId, String filename, long size, JSONObject scanConfig, String sha256)
            throws FiniteStateApiException, InterruptedException {
        JSONObject body = new JSONObject();
        body.element("projectVersionId", versionId);
        body.element("filename", filename);
        body.element("fileSizeBytes", size);
        body.element("contentType", "application/octet-stream");
        if (scanConfig != null) {
            body.element("scanConfig", scanConfig);
        }
        if (sha256 != null) {
            body.element("sha256", sha256);
        }
        HttpResponse<String> resp = execPost(
                apiReq("/scans/binary")
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(body.toString()))
                        .build(),
                "Create binary scan context");
        JSONObject n = asObject(parse(resp.body()));
        BinaryContext ctx = new BinaryContext();
        ctx.scanContextId = requireText(n, "scanContextId", "Create binary scan context");
        ctx.uploadMethod = optString(n, "uploadMethod", "put");
        ctx.uploadUrl = optString(n, "uploadUrl", null);
        ctx.partSize = n.optLong("partSize", 0);
        ctx.partCount = n.optInt("partCount", 0);
        return ctx;
    }

    private JSONArray uploadMultipart(File file, BinaryContext ctx)
            throws FiniteStateApiException, InterruptedException, IOException {
        JSONArray parts = new JSONArray();
        long length = file.length();
        try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
            for (int part = 1; part <= ctx.partCount; part++) {
                long offset = (long) (part - 1) * ctx.partSize;
                int len = (int) Math.min(ctx.partSize, length - offset);
                byte[] buf = new byte[len];
                raf.seek(offset);
                raf.readFully(buf);
                String url = getMultipartPartUrl(ctx.scanContextId, part);
                String etag = putPart(url, buf);
                JSONObject p = new JSONObject();
                p.element("partNumber", part);
                p.element("eTag", etag == null ? "" : etag.replace("\"", ""));
                parts.add(p);
            }
        }
        return parts;
    }

    String getMultipartPartUrl(String scanContextId, int partNumber)
            throws FiniteStateApiException, InterruptedException {
        HttpResponse<String> resp = execGet(
                apiReq("/scans/" + scanContextId + "/multipart/" + partNumber + "/url")
                        .GET()
                        .build(),
                "Get multipart part URL");
        return requireText(asObject(parse(resp.body())), "uploadUrl", "Get multipart part URL");
    }

    void completeBinaryUpload(String scanContextId, JSONArray parts)
            throws FiniteStateApiException, InterruptedException {
        JSONObject body = new JSONObject();
        body.element("parts", parts);
        execPost(
                apiReq("/scans/" + scanContextId + "/complete")
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(body.toString()))
                        .build(),
                "Complete binary upload");
    }

    List<String> startBinaryScan(String scanContextId) throws FiniteStateApiException, InterruptedException {
        HttpResponse<String> resp = execPost(
                apiReq("/scans/" + scanContextId + "/start")
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.noBody())
                        .build(),
                "Start binary scan");
        JSONObject n = asObject(parse(resp.body()));
        List<String> ids = new ArrayList<>();
        if (n.has("scans") && n.get("scans") instanceof JSONArray) {
            JSONArray scans = n.getJSONArray("scans");
            for (int i = 0; i < scans.size(); i++) {
                String id = optString(scans.getJSONObject(i), "id", null);
                if (id != null) {
                    ids.add(id);
                }
            }
        }
        return ids;
    }

    // ========================================================================
    // SBOM / third-party single-shot upload
    // ========================================================================

    /**
     * POST the file bytes (octet-stream) to the API, which uploads to storage server-side and
     * triggers processing in one call. Returns the created scan ID. Used for SBOM and third-party
     * scans so scanner content never transits a client->storage PUT (which a WAF can block).
     *
     * <p>Limitation: the whole file travels in the request body, so this path is bounded by the
     * API's request-body limit (a few MB). Larger SBOM/third-party files are not supported here.
     */
    private String ingestSingleShot(String path, String query, File file, String context)
            throws FiniteStateApiException, InterruptedException {
        HttpResponse<String> resp = execPost(
                apiReq(path + "?" + query)
                        .header("Content-Type", "application/octet-stream")
                        .timeout(Duration.ofMinutes(10))
                        .POST(fileBody(file))
                        .build(),
                context);
        return requireText(asObject(parse(resp.body())), "scanId", context);
    }

    // ========================================================================
    // Status polling (FR-7)
    // ========================================================================

    PollOutcome pollUntilTerminal(List<String> scanIds, int timeoutMinutes)
            throws FiniteStateApiException, InterruptedException {
        long deadline = System.currentTimeMillis() + (long) timeoutMinutes * 60_000L;
        while (true) {
            boolean allTerminal = true;
            boolean anyFailure = false;
            String lastStatus = "UNKNOWN";
            for (String scanId : scanIds) {
                JSONObject s = getScanStatus(scanId);
                String status = optString(s, "status", "UNKNOWN");
                lastStatus = status;
                if (FAILURE_TERMINAL.contains(status)) {
                    anyFailure = true;
                } else if (!SUCCESS_TERMINAL.contains(status)) {
                    allTerminal = false;
                }
            }
            if (anyFailure) {
                return new PollOutcome(lastStatus, false);
            }
            if (allTerminal) {
                return new PollOutcome(scanIds.size() == 1 ? lastStatus : "COMPLETED", true);
            }
            if (System.currentTimeMillis() >= deadline) {
                return new PollOutcome("TIMEOUT", false);
            }
            Thread.sleep(POLL_INTERVAL_MS);
        }
    }

    JSONObject getScanStatus(String scanId) throws FiniteStateApiException, InterruptedException {
        HttpResponse<String> resp =
                execGet(apiReq("/scans/" + scanId + "/status").GET().build(), "Get scan status");
        return asObject(parse(resp.body()));
    }

    // ========================================================================
    // Upload helpers (presigned URLs — no API token)
    // ========================================================================

    void putFile(String url, File file, String contentType) throws FiniteStateApiException, InterruptedException {
        if (url == null || url.isBlank()) {
            throw new FiniteStateApiException(0, "Upload failed: API returned no upload URL");
        }
        HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                .header("Content-Type", contentType)
                .header("x-upsert", "true")
                .header("User-Agent", USER_AGENT)
                .timeout(Duration.ofHours(2))
                .PUT(fileBody(file))
                .build();
        execUpload(req, "Upload binary");
    }

    private String putPart(String url, byte[] chunk) throws FiniteStateApiException, InterruptedException {
        HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                .header("User-Agent", USER_AGENT)
                .timeout(Duration.ofHours(1))
                .PUT(HttpRequest.BodyPublishers.ofByteArray(chunk))
                .build();
        HttpResponse<String> resp = execUpload(req, "Upload part");
        return resp.headers()
                .firstValue("ETag")
                .or(() -> resp.headers().firstValue("etag"))
                .orElse(null);
    }

    private static HttpRequest.BodyPublisher fileBody(File file) throws FiniteStateApiException {
        try {
            return HttpRequest.BodyPublishers.ofFile(file.toPath());
        } catch (java.io.FileNotFoundException e) {
            throw new FiniteStateApiException(0, "Upload failed: file not found: " + file, e);
        }
    }

    // ========================================================================
    // HTTP core: retry with exponential backoff (NFR-2) + FR-9 error mapping
    // ========================================================================

    private HttpRequest.Builder apiReq(String path) {
        return HttpRequest.newBuilder(URI.create(baseUrl + path))
                .header("X-Authorization", apiToken)
                .header("Accept", "application/json")
                .header("User-Agent", USER_AGENT)
                .timeout(Duration.ofMinutes(2));
    }

    /** GET (idempotent, authenticated) — safe to retry on any transient failure. */
    private HttpResponse<String> execGet(HttpRequest req, String context)
            throws FiniteStateApiException, InterruptedException {
        return execWithRetry(req, context, true, true);
    }

    /**
     * POST (authenticated, NOT idempotent) — retried only on failures where the request provably did
     * not reach the server (HTTP 429, or a connect-phase network error), to avoid duplicate
     * creates/triggers if a response is lost after the server already committed.
     */
    private HttpResponse<String> execPost(HttpRequest req, String context)
            throws FiniteStateApiException, InterruptedException {
        return execWithRetry(req, context, true, false);
    }

    /** Presigned storage upload (no token, idempotent PUT) — errors must NOT blame the token. */
    private HttpResponse<String> execUpload(HttpRequest req, String context)
            throws FiniteStateApiException, InterruptedException {
        return execWithRetry(req, context, false, true);
    }

    private HttpResponse<String> execWithRetry(HttpRequest req, String context, boolean apiCall, boolean idempotent)
            throws FiniteStateApiException, InterruptedException {
        IOException lastIo = null;
        for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
            try {
                HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
                int sc = resp.statusCode();
                if (sc >= 200 && sc < 300) {
                    return resp;
                }
                // 429 = rejected before processing (backpressure) → always safe to retry, honoring
                // Retry-After when present (NFR-2). Applies to non-idempotent POSTs too.
                if (sc == 429 && attempt < MAX_ATTEMPTS) {
                    backoff429(resp, attempt, context);
                    continue;
                }
                // A 5xx may have committed server-side → retry only when the call is idempotent.
                if (sc >= 500 && idempotent && attempt < MAX_ATTEMPTS) {
                    backoff(attempt, context, "HTTP " + sc);
                    continue;
                }
                throw toApiException(sc, resp.body(), context, apiCall);
            } catch (IOException e) {
                lastIo = e;
                // For a non-idempotent call, only a connect-phase error proves the request never
                // landed; any other IOException (e.g. a read timeout) might have committed, so do NOT
                // retry — fail loudly rather than risk a duplicate create/trigger.
                if (!idempotent && !isConnectPhase(e)) {
                    throw new FiniteStateApiException(
                            0,
                            context + ": network error after the request was sent (" + e
                                    + "); not retried to avoid a duplicate submission. Check the Finite State"
                                    + " UI for whether it was created.",
                            e);
                }
                if (attempt < MAX_ATTEMPTS) {
                    backoff(attempt, context, e.toString());
                }
            }
        }
        // getMessage() is null for ConnectException/UnknownHostException — use toString() (class +
        // message) and name the host so a DNS/subdomain/VPN problem is diagnosable, not "- null".
        String cause = lastIo != null ? lastIo.toString() : "unknown network error";
        throw new FiniteStateApiException(
                0,
                context + ": cannot reach the Finite State API at https://" + subdomain + " (" + cause
                        + "). Verify the Subdomain is correct and reachable from this Jenkins node (DNS/VPN/proxy).",
                lastIo);
    }

    /** A connect-phase failure proves the request was never delivered (safe to retry even for POST). */
    private static boolean isConnectPhase(IOException e) {
        return e instanceof java.net.ConnectException
                || e instanceof java.net.UnknownHostException
                || e instanceof java.net.http.HttpConnectTimeoutException;
    }

    private void backoff(int attempt, String context, String reason) throws InterruptedException {
        long delayMs = (long) Math.pow(2, attempt) * 500L; // 1s, 2s
        log("WARNING: " + context + " transient failure (" + reason + "); retry " + attempt + "/" + (MAX_ATTEMPTS - 1)
                + " in " + delayMs + "ms");
        Thread.sleep(delayMs);
    }

    /** Backoff for HTTP 429, honoring an integer-seconds Retry-After header when present (capped at 60s). */
    private void backoff429(HttpResponse<String> resp, int attempt, String context) throws InterruptedException {
        long delayMs;
        String retryAfter = resp.headers().firstValue("Retry-After").orElse(null);
        if (retryAfter != null && retryAfter.matches("\\d+")) {
            delayMs = Math.min(Long.parseLong(retryAfter) * 1000L, 60_000L);
        } else {
            delayMs = (long) Math.pow(2, attempt) * 500L;
        }
        log("WARNING: " + context + " rate-limited (429); retry " + attempt + "/" + (MAX_ATTEMPTS - 1) + " in "
                + delayMs + "ms");
        Thread.sleep(delayMs);
    }

    private FiniteStateApiException toApiException(int statusCode, String body, String context, boolean apiCall) {
        // An HTML body means an intermediary (proxy / CDN / WAF) answered, not the API — summarize it
        // instead of dumping the page, and never attribute it to the API token.
        String html = summarizeHtmlBlock(body);
        if (html != null) {
            return new FiniteStateApiException(statusCode, context + ": " + statusCode + " - " + html);
        }

        List<String> messages = new ArrayList<>();
        try {
            JSON json = JSONSerializer.toJSON(body == null || body.isBlank() ? "{}" : body);
            if (json instanceof JSONObject) {
                JSONObject obj = (JSONObject) json;
                if (obj.has("errors") && obj.get("errors") instanceof JSONArray) {
                    JSONArray errors = obj.getJSONArray("errors");
                    for (int i = 0; i < errors.size(); i++) {
                        JSONObject e = errors.getJSONObject(i);
                        String m = optString(e, "error", optString(e, "message", ""));
                        if (m != null && !m.isBlank()) {
                            messages.add(m);
                        }
                    }
                } else if (optString(obj, "error", null) != null) {
                    messages.add(optString(obj, "error", ""));
                } else if (optString(obj, "message", null) != null) {
                    messages.add(optString(obj, "message", ""));
                }
            }
        } catch (RuntimeException ignored) {
            // Non-JSON body; fall back to the raw text below.
        }
        // The token-permission hint only makes sense for authenticated API calls, never for an
        // unauthenticated presigned-storage upload (FR-9 accuracy).
        String hint = apiCall ? hintFor(statusCode) : "";
        String suffix = !messages.isEmpty()
                ? " - " + String.join(" | ", messages)
                : (body != null && !body.isBlank() ? " - " + truncate(body) : "");
        String hintSuffix = hint.isEmpty() ? "" : " - " + hint;
        return new FiniteStateApiException(statusCode, context + ": " + statusCode + suffix + hintSuffix);
    }

    /**
     * If the body is an HTML error page (e.g. a Cloudflare/WAF block), return a one-line summary with
     * the Cloudflare Ray ID when present; otherwise null.
     */
    private static String summarizeHtmlBlock(String body) {
        if (body == null) {
            return null;
        }
        String trimmed = body.stripLeading();
        boolean looksHtml =
                trimmed.regionMatches(true, 0, "<!doctype", 0, 9) || trimmed.regionMatches(true, 0, "<html", 0, 5);
        if (!looksHtml) {
            return null;
        }
        String ray = null;
        int idx = body.indexOf("Cloudflare Ray ID:");
        if (idx >= 0) {
            java.util.regex.Matcher m = java.util.regex.Pattern.compile(
                            "Cloudflare Ray ID:\\s*</span>\\s*<strong[^>]*>([a-z0-9]+)")
                    .matcher(body);
            if (m.find()) {
                ray = m.group(1);
            }
        }
        boolean cloudflare = body.contains("Cloudflare") || body.contains("cf-error");
        StringBuilder sb = new StringBuilder("request blocked by an upstream ");
        sb.append(cloudflare ? "WAF/CDN (Cloudflare)" : "proxy");
        sb.append(" before reaching Finite State storage");
        if (ray != null) {
            sb.append(" [Ray ID ").append(ray).append("]");
        }
        sb.append(". This is not an API-token problem — the scan file content likely tripped a WAF rule;"
                + " contact your Finite State admin to allowlist scan uploads.");
        return sb.toString();
    }

    private static String truncate(String s) {
        String oneLine = s.replaceAll("\\s+", " ").trim();
        return oneLine.length() > 300 ? oneLine.substring(0, 300) + "…" : oneLine;
    }

    private static String hintFor(int statusCode) {
        switch (statusCode) {
            case 401:
                return "Authentication failed. Verify the API token credential and that it's valid for this subdomain.";
            case 403:
                return "The API token does not have the required permissions (read/create projects & versions, create scans, read scan status).";
            case 404:
                return "Not found. Check the project and version identifiers.";
            default:
                return "";
        }
    }

    // ========================================================================
    // Pure helpers (unit-tested)
    // ========================================================================

    /**
     * Maps the four binary checkboxes onto the v0 {@code BinaryScanConfig}. Note: {@code binary_sca}
     * is always enabled server-side, so the SCA checkbox has no field here (see README limitation);
     * Reachability requires SCA and maps to {@code vulnerabilityAnalysis}. All four fields are sent
     * explicitly because the API's defaults differ from the plugin's checkbox defaults.
     */
    static JSONObject buildBinaryScanConfig(FiniteStateScanRequest req) {
        JSONObject cfg = new JSONObject();
        cfg.element("configurationAnalysis", req.isConfigEnabled());
        cfg.element("vulnerabilityAnalysis", req.isReachabilityEnabled() && req.isScaEnabled());
        cfg.element("binarySast", req.isSastEnabled());
        cfg.element("pythonSast", false);
        return cfg;
    }

    /** UI deep link, matching the Azure DevOps extension's pattern. */
    static String buildUiUrl(String subdomain, String projectId, String versionId) {
        return "https://" + subdomain + "/projects/" + projectId + "/versions/" + versionId
                + "/bill-of-materials?view=list";
    }

    /** Best-effort SBOM format detection from extension/content; defaults to cyclonedx. */
    static String detectSbomFormat(File file) {
        String name = file.getName().toLowerCase(Locale.ROOT);
        if (name.contains(".spdx") || name.endsWith(".spdx.json") || name.endsWith(".spdx")) {
            return "spdx";
        }
        if (name.contains("cyclonedx") || name.contains(".cdx")) {
            return "cyclonedx";
        }
        // Limitation: content sniff reads only the head of the file; deeply-nested or unusual SBOMs
        // may be misclassified. Extension hints above take precedence.
        try (InputStream in = new FileInputStream(file)) {
            byte[] buf = new byte[8192];
            int read = in.read(buf);
            String head = read > 0 ? new String(buf, 0, read, StandardCharsets.UTF_8) : "";
            if (head.contains("spdxVersion") || head.contains("SPDXRef") || head.contains("\"SPDXID\"")) {
                return "spdx";
            }
        } catch (IOException ignored) {
            // Fall through to default.
        }
        return "cyclonedx";
    }

    static String escapeRsql(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("*", "\\*");
    }

    static boolean isSuccessTerminal(String status) {
        return SUCCESS_TERMINAL.contains(status);
    }

    static boolean isFailureTerminal(String status) {
        return FAILURE_TERMINAL.contains(status);
    }

    static boolean isTerminal(String status) {
        return SUCCESS_TERMINAL.contains(status) || FAILURE_TERMINAL.contains(status);
    }

    // ========================================================================
    // Internal utilities
    // ========================================================================

    private static String sha256(File file) throws IOException {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            try (InputStream in = new FileInputStream(file)) {
                byte[] buf = new byte[1 << 20];
                int r;
                while ((r = in.read(buf)) > 0) {
                    md.update(buf, 0, r);
                }
            }
            return HexFormat.of().formatHex(md.digest());
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IOException("SHA-256 unavailable", e);
        }
    }

    private JSON parse(String body) throws FiniteStateApiException {
        try {
            return JSONSerializer.toJSON(body == null || body.isBlank() ? "{}" : body);
        } catch (RuntimeException e) {
            throw new FiniteStateApiException(0, "Invalid JSON response from Finite State API: " + e.getMessage(), e);
        }
    }

    private static JSONObject asObject(JSON json) {
        if (json instanceof JSONObject) {
            JSONObject obj = (JSONObject) json;
            if (!obj.isNullObject()) {
                return obj;
            }
        }
        return new JSONObject();
    }

    private static JSONObject findByName(JSON listResp, String name) {
        JSONArray arr = null;
        if (listResp instanceof JSONArray) {
            arr = (JSONArray) listResp;
        } else if (listResp instanceof JSONObject) {
            JSONObject obj = (JSONObject) listResp;
            if (obj.has("items") && obj.get("items") instanceof JSONArray) {
                arr = obj.getJSONArray("items");
            } else if (obj.has("data") && obj.get("data") instanceof JSONArray) {
                arr = obj.getJSONArray("data");
            }
        }
        if (arr == null) {
            return null;
        }
        for (int i = 0; i < arr.size(); i++) {
            if (!(arr.get(i) instanceof JSONObject)) {
                continue;
            }
            JSONObject el = arr.getJSONObject(i);
            String n = optString(el, "name", null);
            String v = optString(el, "version", null);
            if (name.equals(n) || name.equals(v)) {
                return el;
            }
        }
        return null;
    }

    private static String requireText(JSONObject n, String field, String context) throws FiniteStateApiException {
        String v = optString(n, field, null);
        if (v != null && !v.isBlank()) {
            return v;
        }
        throw new FiniteStateApiException(0, context + ": response missing '" + field + "'");
    }

    /** Null-safe string accessor that treats JSONNull and missing keys as the default. */
    private static String optString(JSONObject obj, String key, String def) {
        if (obj == null || !obj.has(key)) {
            return def;
        }
        Object v = obj.get(key);
        if (v == null || v instanceof JSONNull) {
            return def;
        }
        return String.valueOf(v);
    }

    private static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    private void log(String message) {
        listener.getLogger().println("[Finite State] " + message);
    }

    // ========================================================================
    // Small value holders
    // ========================================================================

    static final class BinaryContext {
        String scanContextId;
        String uploadMethod;
        String uploadUrl;
        long partSize;
        int partCount;
    }

    static final class PollOutcome {
        final String status;
        final boolean success;

        PollOutcome(String status, boolean success) {
            this.status = status;
            this.success = success;
        }
    }
}
