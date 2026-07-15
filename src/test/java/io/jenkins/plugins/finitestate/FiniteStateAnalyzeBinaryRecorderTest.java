package io.jenkins.plugins.finitestate;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import net.sf.json.JSONObject;
import org.junit.Test;

/**
 * Verifies that the four binary checkboxes map onto the v0 {@code BinaryScanConfig} exactly as the
 * API expects (see FiniteStateApiClient#buildBinaryScanConfig and binary-scan.service.ts).
 */
public class FiniteStateAnalyzeBinaryRecorderTest {

    private JSONObject configFor(boolean sca, boolean sast, boolean config, boolean reachability) {
        FiniteStateAnalyzeBinaryRecorder recorder =
                new FiniteStateAnalyzeBinaryRecorder("test", "token", "path", "project");
        recorder.setScaEnabled(sca);
        recorder.setSastEnabled(sast);
        recorder.setConfigEnabled(config);
        recorder.setReachabilityEnabled(reachability);
        FiniteStateScanRequest req = new FiniteStateScanRequest();
        recorder.configureRequest(req);
        return FiniteStateApiClient.buildBinaryScanConfig(req);
    }

    @Test
    public void allEnabledMapsAllFields() {
        JSONObject cfg = configFor(true, true, true, true);
        assertTrue(cfg.getBoolean("configurationAnalysis"));
        assertTrue(cfg.getBoolean("vulnerabilityAnalysis"));
        assertTrue(cfg.getBoolean("binarySast"));
        assertFalse("pythonSast is not exposed in the UI and is always false", cfg.getBoolean("pythonSast"));
    }

    @Test
    public void defaultSelectionEnablesVulnerabilityAnalysisOnly() {
        // Defaults: SCA=true, SAST=false, Config=false, Reachability=true.
        JSONObject cfg = configFor(true, false, false, true);
        assertFalse(cfg.getBoolean("configurationAnalysis"));
        assertTrue(cfg.getBoolean("vulnerabilityAnalysis"));
        assertFalse(cfg.getBoolean("binarySast"));
    }

    @Test
    public void reachabilityRequiresSca() {
        // Reachability on but SCA off → vulnerabilityAnalysis must be false.
        JSONObject cfg = configFor(false, false, false, true);
        assertFalse(cfg.getBoolean("vulnerabilityAnalysis"));
    }

    @Test
    public void sastMapsToBinarySast() {
        JSONObject cfg = configFor(true, true, false, false);
        assertTrue(cfg.getBoolean("binarySast"));
        assertFalse(cfg.getBoolean("configurationAnalysis"));
        assertFalse(cfg.getBoolean("vulnerabilityAnalysis"));
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
