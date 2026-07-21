package io.jenkins.plugins.finitestate;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import hudson.util.Secret;
import hudson.util.StreamTaskListener;
import java.io.File;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import net.sf.json.JSONObject;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

/**
 * HTTP-level test of the binary {@code /scans/upload} façade wire format, using a local stub server
 * (no live backend, runs in CI). Guards the shapes the whole PR depends on: the create body, the
 * multipart part-URL path (with {@code s3UploadId}), the {@code eTags} MAP at {@code /complete}, and
 * {@code /start}. Complements the env-gated live e2e test.
 */
public class FiniteStateApiClientHttpTest {

    @Rule
    public JenkinsRule j = new JenkinsRule();

    private HttpServer server;
    private String baseUrl;
    private final List<String[]> requests = new CopyOnWriteArrayList<>(); // [method, path, query, body]

    @Before
    public void startStub() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", this::handle);
        server.start();
        baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();
    }

    @After
    public void stopStub() {
        if (server != null) {
            server.stop(0);
        }
    }

    private void handle(HttpExchange ex) throws IOException {
        String method = ex.getRequestMethod();
        String path = ex.getRequestURI().getPath();
        String query = ex.getRequestURI().getRawQuery();
        String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        requests.add(new String[] {method, path, query, body});

        String resp = "{}";
        int code = 200;
        if (method.equals("GET") && path.equals("/projects")) {
            resp = "[]"; // no existing project → triggers create
        } else if (method.equals("POST") && path.equals("/projects")) {
            resp = "{\"id\":\"proj-1\"}";
        } else if (method.equals("GET") && path.equals("/projects/proj-1/versions")) {
            resp = "[]"; // no existing version → triggers create
        } else if (method.equals("POST") && path.equals("/projects/proj-1/versions")) {
            resp = "{\"id\":\"ver-1\"}";
        } else if (method.equals("GET") && path.equals("/scans")) {
            resp = "{\"items\":[]}"; // baseline version-scan list (empty)
        } else if (method.equals("POST") && path.equals("/scans/upload")) {
            // Force the multipart branch; return a 1-part server plan.
            resp = "{\"scanId\":\"scan-ctx-1\",\"multipartUpload\":true,\"s3UploadId\":\"s3up-1\","
                    + "\"partSize\":16,\"partCount\":1}";
        } else if (method.equals("GET") && path.equals("/scans/scan-ctx-1/multipart/s3up-1/1/url")) {
            resp = "{\"uploadUrl\":\"" + baseUrl + "/storage/put\"}";
        } else if (method.equals("PUT") && path.equals("/storage/put")) {
            ex.getResponseHeaders().add("ETag", "\"etag-1\"");
            resp = "";
        } else if (method.equals("POST") && path.equals("/scans/scan-ctx-1/multipart/s3up-1/complete")) {
            resp = "{\"ok\":true}";
        } else if (method.equals("POST") && path.equals("/scans/scan-ctx-1/start")) {
            resp = "{\"scans\":[{\"id\":\"real-scan-1\"}]}";
        } else {
            code = 404;
            resp = "{\"error\":\"unexpected " + method + " " + path + "\"}";
        }
        byte[] out = resp.getBytes(StandardCharsets.UTF_8);
        ex.sendResponseHeaders(code, out.length == 0 ? -1 : out.length);
        ex.getResponseBody().write(out);
        ex.close();
    }

    private String[] find(String method, String path) {
        return requests.stream()
                .filter(r -> r[0].equals(method) && r[1].equals(path))
                .findFirst()
                .orElse(null);
    }

    @Test
    public void binaryMultipartFacadeWireFormat() throws Exception {
        File bin = File.createTempFile("fs-http-", ".bin");
        Files.write(bin.toPath(), "sixteen-byte-pay".getBytes(StandardCharsets.UTF_8)); // 16 bytes

        FiniteStateApiClient client =
                new FiniteStateApiClient("stub", Secret.fromString("tok"), StreamTaskListener.fromStdout(), baseUrl);
        FiniteStateScanRequest req = new FiniteStateScanRequest();
        req.setKind(FiniteStateScanRequest.Kind.BINARY);
        req.setProjectName("proj");
        req.setVersion("v1");
        req.setScaEnabled(true);
        req.setReachabilityEnabled(true);
        req.setWaitForCompletion(false);

        ScanResult result = new ScanResult();
        client.runBinary(bin, req, result);

        // Create: POST /scans/upload with projectVersionId in query and the mb-api body fields.
        String[] create = find("POST", "/scans/upload");
        assertTrue("create call made", create != null);
        assertEquals("projectVersionId=ver-1", create[2]);
        JSONObject createBody = JSONObject.fromObject(create[3]);
        assertEquals("tplink-style filename echoed", bin.getName(), createBody.getString("filename"));
        assertTrue("types is a list", createBody.get("types").toString().contains("sca"));
        assertTrue("carries fileSizeBytes", createBody.has("fileSizeBytes"));
        assertTrue("carries multipartUpload flag", createBody.has("multipartUpload"));

        // Part URL: GET with s3UploadId embedded in the path.
        assertTrue("part-url path carries s3UploadId", find("GET", "/scans/scan-ctx-1/multipart/s3up-1/1/url") != null);

        // Complete: POST with an eTags MAP (stringified part number -> ETag), NOT a parts array.
        String[] complete = find("POST", "/scans/scan-ctx-1/multipart/s3up-1/complete");
        assertTrue("complete call made", complete != null);
        JSONObject completeBody = JSONObject.fromObject(complete[3]);
        assertTrue("body has eTags map", completeBody.has("eTags"));
        assertFalse("body is not a parts array", completeBody.has("parts"));
        assertEquals("\"etag-1\"", completeBody.getJSONObject("eTags").getString("1"));

        // Start + reported scan id comes from the /start response.
        assertTrue("start call made", find("POST", "/scans/scan-ctx-1/start") != null);
        assertTrue(result.isSuccess());
        assertEquals(List.of("real-scan-1"), result.getScanIds());
    }
}
