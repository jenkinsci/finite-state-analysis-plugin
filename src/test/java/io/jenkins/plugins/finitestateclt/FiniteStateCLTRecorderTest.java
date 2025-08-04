package io.jenkins.plugins.finitestateclt;

import org.junit.Test;
import static org.junit.Assert.*;

import java.lang.reflect.Method;

public class FiniteStateCLTRecorderTest {

    @Test
    public void testScanTypesConversion() throws Exception {
        // Test with all scan types enabled
        FiniteStateCLTRecorder recorder = new FiniteStateCLTRecorder(
            "test", "token", "path", "project", "version", "sca,sast,config", true,
            true, true, true
        );
        
        String result = getScanTypesString(recorder);
        assertEquals("sca,sast,config", result);
        
        // Test with only SCA enabled (default)
        recorder = new FiniteStateCLTRecorder(
            "test", "token", "path", "project", "version", "sca", true,
            true, false, false
        );
        
        result = getScanTypesString(recorder);
        assertEquals("sca", result);
        
        // Test with SCA and SAST enabled
        recorder = new FiniteStateCLTRecorder(
            "test", "token", "path", "project", "version", "sca,sast", true,
            true, true, false
        );
        
        result = getScanTypesString(recorder);
        assertEquals("sca,sast", result);
        
        // Test with none enabled (should default to sca)
        recorder = new FiniteStateCLTRecorder(
            "test", "token", "path", "project", "version", "", true,
            false, false, false
        );
        
        result = getScanTypesString(recorder);
        assertEquals("sca", result);
    }
    
    private String getScanTypesString(FiniteStateCLTRecorder recorder) throws Exception {
        Method method = FiniteStateCLTRecorder.class.getDeclaredMethod("buildScanTypesString");
        method.setAccessible(true);
        return (String) method.invoke(recorder);
    }
} 