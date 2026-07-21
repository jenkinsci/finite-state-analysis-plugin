package io.jenkins.plugins.finitestate;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.List;
import org.junit.Test;

/**
 * Verifies that the binary checkboxes map onto the mb-api {@code types} tokens sent to
 * {@code POST /scans/upload} (see FiniteStateApiClient#buildScanTypes). The façade converts these
 * tokens into the server-side scan config.
 */
public class FiniteStateAnalyzeBinaryRecorderTest {

    private List<String> typesFor(boolean sca, boolean sast, boolean config, boolean reachability) {
        FiniteStateAnalyzeBinaryRecorder recorder =
                new FiniteStateAnalyzeBinaryRecorder("test", "token", "path", "project");
        recorder.setScaEnabled(sca);
        recorder.setSastEnabled(sast);
        recorder.setConfigEnabled(config);
        recorder.setReachabilityEnabled(reachability);
        FiniteStateScanRequest req = new FiniteStateScanRequest();
        recorder.configureRequest(req);
        return FiniteStateApiClient.buildScanTypes(req);
    }

    @Test
    public void allEnabledMapsAllTokens() {
        List<String> types = typesFor(true, true, true, true);
        assertTrue(types.contains("sca"));
        assertTrue(types.contains("sast"));
        assertTrue(types.contains("config"));
        assertTrue(types.contains("vulnerability_analysis"));
        assertEquals(4, types.size());
    }

    @Test
    public void defaultSelectionSendsScaAndVulnerabilityAnalysis() {
        // Defaults: SCA=true, SAST=false, Config=false, Reachability=true.
        List<String> types = typesFor(true, false, false, true);
        assertTrue(types.contains("sca"));
        assertTrue(types.contains("vulnerability_analysis"));
        assertFalse(types.contains("sast"));
        assertFalse(types.contains("config"));
    }

    @Test
    public void reachabilityRequiresSca() {
        // Reachability maps to vulnerability_analysis only when SCA is also on (parity with the prior
        // BinaryScanConfig behavior and the UI coupling). Reachability alone (SCA off) → no token,
        // so it falls back to the sca default.
        assertEquals(List.of("sca"), typesFor(false, false, false, true));
        // With SCA on, reachability contributes vulnerability_analysis.
        assertTrue(typesFor(true, false, false, true).contains("vulnerability_analysis"));
    }

    @Test
    public void sastMapsToSastToken() {
        List<String> types = typesFor(true, true, false, false);
        assertTrue(types.contains("sast"));
        assertFalse(types.contains("config"));
        assertFalse(types.contains("vulnerability_analysis"));
    }

    @Test
    public void emptySelectionDefaultsToSca() {
        List<String> types = typesFor(false, false, false, false);
        assertEquals(List.of("sca"), types);
    }

    @Test
    public void reachabilityDefaultsToTrue() {
        FiniteStateAnalyzeBinaryRecorder recorder =
                new FiniteStateAnalyzeBinaryRecorder("test", "token", "path", "project");
        assertTrue("Reachability should default to true", recorder.getReachabilityEnabled());
    }

    @Test
    public void waitForCompletionDefaultsAreApplied() {
        FiniteStateAnalyzeBinaryRecorder recorder =
                new FiniteStateAnalyzeBinaryRecorder("test", "token", "path", "project");
        assertFalse("waitForCompletion should default to false (submit and return)", recorder.getWaitForCompletion());
        assertEquals(30, recorder.getPollTimeoutMinutes());
    }
}
