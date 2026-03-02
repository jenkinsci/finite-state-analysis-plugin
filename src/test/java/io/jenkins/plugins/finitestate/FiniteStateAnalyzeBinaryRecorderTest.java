package io.jenkins.plugins.finitestate;

import static org.junit.Assert.*;

import java.lang.reflect.Method;
import org.junit.Test;

public class FiniteStateAnalyzeBinaryRecorderTest {

    @Test
    public void testScanTypesConversion() throws Exception {
        // Test with all scan types enabled
        FiniteStateAnalyzeBinaryRecorder recorder =
                new FiniteStateAnalyzeBinaryRecorder("test", "token", "path", "project");
        recorder.setScaEnabled(true);
        recorder.setSastEnabled(true);
        recorder.setConfigEnabled(true);
        recorder.setReachabilityEnabled(true);

        String result = getScanTypesString(recorder);
        assertEquals("sca,sast,config,vulnerability_analysis", result);

        // Test with only SCA enabled (default) - reachability defaults to true
        recorder = new FiniteStateAnalyzeBinaryRecorder("test", "token", "path", "project");
        recorder.setScaEnabled(true);
        recorder.setSastEnabled(false);
        recorder.setConfigEnabled(false);

        result = getScanTypesString(recorder);
        assertEquals("sca,vulnerability_analysis", result);

        // Test with SCA and SAST enabled, reachability disabled
        recorder = new FiniteStateAnalyzeBinaryRecorder("test", "token", "path", "project");
        recorder.setScaEnabled(true);
        recorder.setSastEnabled(true);
        recorder.setConfigEnabled(false);
        recorder.setReachabilityEnabled(false);

        result = getScanTypesString(recorder);
        assertEquals("sca,sast", result);

        // Test with none enabled (should default to sca)
        recorder = new FiniteStateAnalyzeBinaryRecorder("test", "token", "path", "project");
        recorder.setScaEnabled(false);
        recorder.setSastEnabled(false);
        recorder.setConfigEnabled(false);
        recorder.setReachabilityEnabled(false);

        result = getScanTypesString(recorder);
        assertEquals("sca", result);
    }

    @Test
    public void testReachabilityRequiresSca() throws Exception {
        // Reachability enabled but SCA disabled - should NOT include vulnerability_analysis
        FiniteStateAnalyzeBinaryRecorder recorder =
                new FiniteStateAnalyzeBinaryRecorder("test", "token", "path", "project");
        recorder.setScaEnabled(false);
        recorder.setSastEnabled(false);
        recorder.setConfigEnabled(false);
        recorder.setReachabilityEnabled(true);

        String result = getScanTypesString(recorder);
        assertEquals("sca", result);
        assertFalse(result.contains("vulnerability_analysis"));
    }

    @Test
    public void testReachabilityDefaultsToTrue() {
        FiniteStateAnalyzeBinaryRecorder recorder =
                new FiniteStateAnalyzeBinaryRecorder("test", "token", "path", "project");
        assertTrue("Reachability should default to true", recorder.getReachabilityEnabled());
    }

    private String getScanTypesString(FiniteStateAnalyzeBinaryRecorder recorder) throws Exception {
        Method method = FiniteStateAnalyzeBinaryRecorder.class.getDeclaredMethod("buildScanTypesString");
        method.setAccessible(true);
        return (String) method.invoke(recorder);
    }
}
