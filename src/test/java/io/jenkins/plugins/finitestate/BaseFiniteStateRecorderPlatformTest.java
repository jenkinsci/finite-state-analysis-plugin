package io.jenkins.plugins.finitestate;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/**
 * Guards the HELIX-422 backward-compatibility contract: a recorder defaults to the legacy platform
 * (Java CLT), so a job saved before the {@code platform} field existed (its persisted XML has no
 * {@code platform}) keeps running against the legacy platform after the plugin is upgraded. The
 * 2026 platform release (REST API) is opt-in.
 */
public class BaseFiniteStateRecorderPlatformTest {

    private BaseFiniteStateRecorder newRecorder() {
        // Any concrete recorder exercises the shared base behavior.
        return new FiniteStateAnalyzeBinaryRecorder("test", "token", "path", "project");
    }

    @Test
    public void defaultsToLegacyWhenUnset() {
        BaseFiniteStateRecorder recorder = newRecorder();
        assertEquals(BaseFiniteStateRecorder.PLATFORM_LEGACY, recorder.getPlatform());
        assertFalse("unset platform must not route to the REST API", recorder.isRestApi());
    }

    @Test
    public void blankPlatformFallsBackToLegacy() {
        BaseFiniteStateRecorder recorder = newRecorder();
        recorder.setPlatform("   ");
        assertEquals(BaseFiniteStateRecorder.PLATFORM_LEGACY, recorder.getPlatform());
        assertFalse(recorder.isRestApi());
    }

    @Test
    public void restApiIsOptIn() {
        BaseFiniteStateRecorder recorder = newRecorder();
        recorder.setPlatform(BaseFiniteStateRecorder.PLATFORM_2026);
        assertTrue(recorder.isRestApi());
        assertEquals(BaseFiniteStateRecorder.PLATFORM_2026, recorder.getPlatform());
    }

    @Test
    public void explicitLegacyStaysLegacy() {
        BaseFiniteStateRecorder recorder = newRecorder();
        recorder.setPlatform(BaseFiniteStateRecorder.PLATFORM_LEGACY);
        assertFalse(recorder.isRestApi());
    }

    @Test
    public void unknownPlatformIsNotRestApi() {
        // Any value other than the 2026 release resolves to the safe legacy (CLT) path.
        BaseFiniteStateRecorder recorder = newRecorder();
        recorder.setPlatform("some-future-value");
        assertFalse(recorder.isRestApi());
    }
}
