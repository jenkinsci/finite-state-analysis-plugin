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

    /** SBOM import: resolve → create sbom scan → PUT → process (CycloneDX) / process-third-party (SPDX). */
    void runSbom(File file, FiniteStateScanRequest req, ScanResult result)
            throws FiniteStateApiException, InterruptedException, IOException {
        String projectId = resolveProjectId(req.getProjectName());
        String versionId = resolveOrCreateVersionId(projectId, req.getVersion(), req.isPreRelease());
        result.setProjectId(projectId);
        result.setVersionId(versionId);
        result.setUiUrl(buildUiUrl(subdomain, projectId, versionId));

        String format = detectSbomFormat(file);
        log("Detected SBOM format: " + format);
        ScanRef ref = createSbomScan(versionId, format, file.getName());
        result.addScanId(ref.scanId);
        putFile(ref.uploadUrl, file, "application/json");
        if ("spdx".equals(format)) {
            processThirdParty(ref.scanId, "spdx");
        } else {
            processScan(ref.scanId);
        }
        log("SBOM import queued (scan " + ref.scanId + ").");

        finishWithPolling(req, List.of(ref.scanId), result);
    }

    /** Third-party scan import: resolve → create third-party scan → PUT → process-third-party. */
    void runThirdParty(File file, FiniteStateScanRequest req, ScanResult result)
            throws FiniteStateApiException, InterruptedException, IOException {
        String projectId = resolveProjectId(req.getProjectName());
        String versionId = resolveOrCreateVersionId(projectId, req.getVersion(), req.isPreRelease());
        result.setProjectId(projectId);
        result.setVersionId(versionId);
        result.setUiUrl(buildUiUrl(subdomain, projectId, versionId));

        ScanRef ref = createThirdPartyScan(versionId, req.getScanType(), file.getName());
        result.addScanId(ref.scanId);
        putFile(ref.uploadUrl, file, "application/json");
        processThirdParty(ref.scanId, req.getScanType());
        log("Third-party scan queued (scan " + ref.scanId + ", scanner " + req.getScanType() + ").");

        finishWithPolling(req, List.of(ref.scanId), result);
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
        HttpResponse<String> resp = execWithRetry(
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
        HttpResponse<String> created = execWithRetry(
                apiReq("/projects")
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(body.toString()))
                        .build(),
                "Project create");
        return requireText(asObject(parse(created.body())), "id", "Project create");
    }

    String resolveOrCreateVersionId(String projectId, String versionName, boolean preRelease)
            throws FiniteStateApiException, InterruptedException {
        HttpResponse<String> resp = execWithRetry(
                apiReq("/projects/" + projectId + "/versions?filter="
                                + enc("name==\"" + escapeRsql(versionName) + "\""))
                        .GET()
                        .build(),
                "Versions list");
        JSONObject existing = findByName(parse(resp.body()), versionName);
        if (existing != null) {
            return requireText(existing, "id", "Versions list");
        }
        JSONObject body = new JSONObject();
        body.element("version", versionName);
        body.element("releaseType", preRelease ? "PRE-RELEASE" : "RELEASE");
        HttpResponse<String> created = execWithRetry(
                apiReq("/projects/" + projectId + "/versions")
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(body.toString()))
                        .build(),
                "Version create");
        return requireText(asObject(parse(created.body())), "id", "Version create");
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
        HttpResponse<String> resp = execWithRetry(
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
        HttpResponse<String> resp = execWithRetry(
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
        execWithRetry(
                apiReq("/scans/" + scanContextId + "/complete")
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(body.toString()))
                        .build(),
                "Complete binary upload");
    }

    List<String> startBinaryScan(String scanContextId) throws FiniteStateApiException, InterruptedException {
        HttpResponse<String> resp = execWithRetry(
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
    // SBOM / third-party endpoints
    // ========================================================================

    ScanRef createSbomScan(String versionId, String sbomFormat, String fileName)
            throws FiniteStateApiException, InterruptedException {
        JSONObject body = new JSONObject();
        body.element("projectVersionId", versionId);
        body.element("sbomFormat", sbomFormat);
        body.element("fileName", fileName);
        HttpResponse<String> resp = execWithRetry(
                apiReq("/scans/sbom")
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(body.toString()))
                        .build(),
                "Create SBOM scan");
        return scanRef(asObject(parse(resp.body())), "Create SBOM scan");
    }

    void processScan(String scanId) throws FiniteStateApiException, InterruptedException {
        execWithRetry(
                apiReq("/scans/" + scanId + "/process")
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString("{}"))
                        .build(),
                "Process scan");
    }

    ScanRef createThirdPartyScan(String versionId, String scanType, String fileName)
            throws FiniteStateApiException, InterruptedException {
        JSONObject body = new JSONObject();
        body.element("projectVersionId", versionId);
        body.element("scanType", scanType);
        body.element("fileName", fileName);
        HttpResponse<String> resp = execWithRetry(
                apiReq("/scans/third-party")
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(body.toString()))
                        .build(),
                "Create third-party scan");
        return scanRef(asObject(parse(resp.body())), "Create third-party scan");
    }

    void processThirdParty(String scanId, String scanner) throws FiniteStateApiException, InterruptedException {
        JSONObject body = new JSONObject();
        body.element("scanner", scanner);
        execWithRetry(
                apiReq("/scans/" + scanId + "/process-third-party")
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(body.toString()))
                        .build(),
                "Process third-party scan");
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
                execWithRetry(apiReq("/scans/" + scanId + "/status").GET().build(), "Get scan status");
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
        execWithRetry(req, "Upload file");
    }

    private String putPart(String url, byte[] chunk) throws FiniteStateApiException, InterruptedException {
        HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                .header("User-Agent", USER_AGENT)
                .timeout(Duration.ofHours(1))
                .PUT(HttpRequest.BodyPublishers.ofByteArray(chunk))
                .build();
        HttpResponse<String> resp = execWithRetry(req, "Upload part");
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

    private HttpResponse<String> execWithRetry(HttpRequest req, String context)
            throws FiniteStateApiException, InterruptedException {
        IOException lastIo = null;
        for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
            try {
                HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
                int sc = resp.statusCode();
                if (sc >= 200 && sc < 300) {
                    return resp;
                }
                if (sc >= 500 && attempt < MAX_ATTEMPTS) {
                    backoff(attempt, context, "HTTP " + sc);
                    continue;
                }
                throw toApiException(sc, resp.body(), context);
            } catch (IOException e) {
                lastIo = e;
                if (attempt < MAX_ATTEMPTS) {
                    backoff(attempt, context, e.toString());
                }
            }
        }
        throw new FiniteStateApiException(
                0,
                context + ": Finite State API is currently unavailable - "
                        + (lastIo != null ? lastIo.getMessage() : "unknown network error"),
                lastIo);
    }

    private void backoff(int attempt, String context, String reason) throws InterruptedException {
        long delayMs = (long) Math.pow(2, attempt) * 500L; // 1s, 2s
        log("WARNING: " + context + " transient failure (" + reason + "); retry " + attempt + "/" + (MAX_ATTEMPTS - 1)
                + " in " + delayMs + "ms");
        Thread.sleep(delayMs);
    }

    private FiniteStateApiException toApiException(int statusCode, String body, String context) {
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
        String hint = hintFor(statusCode);
        String suffix = !messages.isEmpty()
                ? " - " + String.join(" | ", messages)
                : (body != null && !body.isBlank() ? " - " + body : "");
        String hintSuffix = hint.isEmpty() ? "" : " - " + hint;
        return new FiniteStateApiException(statusCode, context + ": " + statusCode + suffix + hintSuffix);
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

    private static ScanRef scanRef(JSONObject n, String context) throws FiniteStateApiException {
        ScanRef ref = new ScanRef();
        ref.scanId = requireText(n, "scanId", context);
        ref.uploadUrl = optString(n, "uploadUrl", null);
        return ref;
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

    static final class ScanRef {
        String scanId;
        String uploadUrl;
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
