package io.jenkins.plugins.finitestate;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/**
 * Guards the HELIX-422 backward-compatibility contract: a recorder defaults to the legacy Alloy
 * (CLT) transport, so a job saved before the {@code platform} field existed (its persisted XML has
 * no {@code platform}) keeps running against Alloy after the plugin is upgraded. Helix is opt-in.
 */
public class BaseFiniteStateRecorderPlatformTest {

    private BaseFiniteStateRecorder newRecorder() {
        // Any concrete recorder exercises the shared base behavior.
        return new FiniteStateAnalyzeBinaryRecorder("test", "token", "path", "project");
    }

    @Test
    public void defaultsToAlloyWhenUnset() {
        BaseFiniteStateRecorder recorder = newRecorder();
        assertEquals(BaseFiniteStateRecorder.PLATFORM_ALLOY, recorder.getPlatform());
        assertFalse("unset platform must not route to Helix", recorder.isHelix());
    }

    @Test
    public void blankPlatformFallsBackToAlloy() {
        BaseFiniteStateRecorder recorder = newRecorder();
        recorder.setPlatform("   ");
        assertEquals(BaseFiniteStateRecorder.PLATFORM_ALLOY, recorder.getPlatform());
        assertFalse(recorder.isHelix());
    }

    @Test
    public void helixIsOptIn() {
        BaseFiniteStateRecorder recorder = newRecorder();
        recorder.setPlatform(BaseFiniteStateRecorder.PLATFORM_HELIX);
        assertTrue(recorder.isHelix());
        assertEquals(BaseFiniteStateRecorder.PLATFORM_HELIX, recorder.getPlatform());
    }

    @Test
    public void explicitAlloyStaysAlloy() {
        BaseFiniteStateRecorder recorder = newRecorder();
        recorder.setPlatform(BaseFiniteStateRecorder.PLATFORM_ALLOY);
        assertFalse(recorder.isHelix());
    }

    @Test
    public void platformMatchIsCaseInsensitive() {
        BaseFiniteStateRecorder recorder = newRecorder();
        recorder.setPlatform("HELIX");
        assertTrue(recorder.isHelix());
    }
}
