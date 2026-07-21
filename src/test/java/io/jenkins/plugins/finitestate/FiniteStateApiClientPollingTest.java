package io.jenkins.plugins.finitestate;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import hudson.util.Secret;
import hudson.util.StreamTaskListener;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

/**
 * Deterministic (no live backend) tests of {@code pollUntilTerminal} — the review fix that must
 * never false-green {@code waitForCompletion}. Covers the current-backend {@code /scans/{id}/status}
 * path, the previous-backend fallback to the version scan list (when {@code /status} 404s), and that
 * a non-terminal status is NOT reported as success.
 */
public class FiniteStateApiClientPollingTest {

    @Rule
    public JenkinsRule j = new JenkinsRule();

    private HttpServer server;
    private String baseUrl;

    // Per-test stub controls.
    private int statusCode = 200;
    private String statusBody = "{}";
    private String versionListBody = "{\"items\":[]}";

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
        String path = ex.getRequestURI().getPath();
        int code = 200;
        String resp = "{}";
        if (path.endsWith("/status")) {
            code = statusCode;
            resp = statusBody;
        } else if (path.equals("/scans")) {
            resp = versionListBody;
        }
        byte[] out = resp.getBytes(StandardCharsets.UTF_8);
        ex.sendResponseHeaders(code, out.length);
        ex.getResponseBody().write(out);
        ex.close();
    }

    private FiniteStateApiClient client() {
        return new FiniteStateApiClient("stub", Secret.fromString("tok"), StreamTaskListener.fromStdout(), baseUrl);
    }

    @Test
    public void currentBackendStatusEndpointReachesTerminal() throws Exception {
        statusCode = 200;
        statusBody = "{\"status\":\"COMPLETED\"}";
        FiniteStateApiClient.PollOutcome o = client().pollUntilTerminal(List.of("s1"), "v1", 5);
        assertTrue(o.success);
        assertEquals("COMPLETED", o.status);
    }

    @Test
    public void previousBackendFallsBackToVersionScanList() throws Exception {
        statusCode = 404; // previous backend: no per-scan status endpoint
        statusBody = "{\"error\":\"not found\"}";
        versionListBody = "{\"items\":[{\"id\":\"s1\",\"status\":\"COMPLETED\"}]}";
        FiniteStateApiClient.PollOutcome o = client().pollUntilTerminal(List.of("s1"), "v1", 5);
        assertTrue("resolved terminal status from the version scan list", o.success);
        assertEquals("COMPLETED", o.status);
    }

    @Test
    public void nonTerminalDoesNotFalseGreen() throws Exception {
        // Status is readable but still running; with a 0-minute budget the poll must return a
        // non-success TIMEOUT — never a green "completed" while the scan is unfinished.
        statusCode = 200;
        statusBody = "{\"status\":\"STARTED\"}";
        FiniteStateApiClient.PollOutcome o = client().pollUntilTerminal(List.of("s1"), "v1", 0);
        assertFalse(o.success);
        assertEquals("TIMEOUT", o.status);
    }

    @Test
    public void failureTerminalIsReportedAsFailure() throws Exception {
        statusCode = 200;
        statusBody = "{\"status\":\"ERROR\"}";
        FiniteStateApiClient.PollOutcome o = client().pollUntilTerminal(List.of("s1"), "v1", 5);
        assertFalse(o.success);
        assertEquals("ERROR", o.status);
    }
}
