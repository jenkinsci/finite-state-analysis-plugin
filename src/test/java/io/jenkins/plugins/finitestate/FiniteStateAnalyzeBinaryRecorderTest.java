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

        String result = getScanTypesString(recorder);
        assertEquals("sca,sast,config", result);

        // Test with only SCA enabled (default)
        recorder = new FiniteStateAnalyzeBinaryRecorder("test", "token", "path", "project");
        recorder.setScaEnabled(true);
        recorder.setSastEnabled(false);
        recorder.setConfigEnabled(false);

        result = getScanTypesString(recorder);
        assertEquals("sca", result);

        // Test with SCA and SAST enabled
        recorder = new FiniteStateAnalyzeBinaryRecorder("test", "token", "path", "project");
        recorder.setScaEnabled(true);
        recorder.setSastEnabled(true);
        recorder.setConfigEnabled(false);

        result = getScanTypesString(recorder);
        assertEquals("sca,sast", result);

        // Test with none enabled (should default to sca)
        recorder = new FiniteStateAnalyzeBinaryRecorder("test", "token", "path", "project");
        recorder.setScaEnabled(false);
        recorder.setSastEnabled(false);
        recorder.setConfigEnabled(false);

        result = getScanTypesString(recorder);
        assertEquals("sca", result);
    }

    private String getScanTypesString(FiniteStateAnalyzeBinaryRecorder recorder) throws Exception {
        Method method = FiniteStateAnalyzeBinaryRecorder.class.getDeclaredMethod("buildScanTypesString");
        method.setAccessible(true);
        return (String) method.invoke(recorder);
    }
}
