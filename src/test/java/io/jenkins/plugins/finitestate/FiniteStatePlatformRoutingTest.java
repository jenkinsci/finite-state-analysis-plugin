package io.jenkins.plugins.finitestate;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.SystemCredentialsProvider;
import hudson.Launcher;
import hudson.model.AbstractBuild;
import hudson.model.BuildListener;
import hudson.model.FreeStyleProject;
import hudson.util.Secret;
import java.io.IOException;
import org.jenkinsci.plugins.plaincredentials.impl.StringCredentialsImpl;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.TestBuilder;

/**
 * Runs the plugin inside a real Jenkins ({@link JenkinsRule}) and drives a build under each
 * {@code platform} to prove the HELIX-422 transport switch end-to-end: data-binding → perform() →
 * {@link FiniteStateExecutionFramework} dispatch → the correct network boundary.
 *
 * <p>The subdomain points at a reserved {@code .invalid} host (RFC 2606), so both transports fail
 * fast at connect. We assert on which transport was <em>selected and attempted</em> — the Alloy run
 * must reach the CLT download endpoint ({@code /api/config/clt}) and the Helix run must go through
 * the v0 API path — not on scan success (which would require a live backend).
 */
public class FiniteStatePlatformRoutingTest {

    @Rule
    public JenkinsRule j = new JenkinsRule();

    private static final String UNREACHABLE_SUBDOMAIN = "fs-routing-test.invalid";

    private String addTokenCredential() throws Exception {
        StringCredentialsImpl cred = new StringCredentialsImpl(
                CredentialsScope.GLOBAL, "fs-token", "routing test", Secret.fromString("secret-token"));
        SystemCredentialsProvider.getInstance().getCredentials().add(cred);
        SystemCredentialsProvider.getInstance().save();
        return "fs-token";
    }

    /** Writes the artifact the recorder expects, so we reach the transport instead of a file error. */
    private static final class WriteScanFile extends TestBuilder {
        @Override
        public boolean perform(AbstractBuild<?, ?> build, Launcher launcher, BuildListener listener)
                throws InterruptedException, IOException {
            build.getWorkspace().child("scan.bin").write("payload", "UTF-8");
            return true;
        }
    }

    private FiniteStateAnalyzeBinaryRecorder recorder(String platform) throws Exception {
        FiniteStateAnalyzeBinaryRecorder r =
                new FiniteStateAnalyzeBinaryRecorder(UNREACHABLE_SUBDOMAIN, addTokenCredential(), "scan.bin", "proj");
        r.setProjectVersion("1.0");
        r.setPlatform(platform);
        return r;
    }

    private String runAndGetLog(String platform) throws Exception {
        FreeStyleProject p = j.createFreeStyleProject();
        p.getBuildersList().add(new WriteScanFile());
        p.getPublishersList().add(recorder(platform));
        return j.getLog(p.scheduleBuild2(0).get());
    }

    @Test
    public void alloyPlatformUsesCltTransport() throws Exception {
        String log = runAndGetLog(BaseFiniteStateRecorder.PLATFORM_ALLOY);
        assertTrue("should announce the Alloy transport:\n" + log, log.contains("Platform: Alloy (CLT)"));
        assertTrue("should attempt the CLT download endpoint:\n" + log, log.contains("/api/config/clt"));
        assertFalse("must not touch the Helix API path:\n" + log, log.contains("via the Finite State API"));
    }

    @Test
    public void helixPlatformUsesV0Transport() throws Exception {
        String log = runAndGetLog(BaseFiniteStateRecorder.PLATFORM_HELIX);
        assertTrue("should announce the Helix transport:\n" + log, log.contains("Platform: Helix (public v0 API)"));
        assertTrue("should go through the v0 API path:\n" + log, log.contains("via the Finite State API"));
        assertFalse("must not download the CLT:\n" + log, log.contains("/api/config/clt"));
    }

    @Test
    public void defaultPlatformIsAlloy() throws Exception {
        // No setPlatform() call — mirrors a job whose persisted config predates the field.
        FreeStyleProject p = j.createFreeStyleProject();
        p.getBuildersList().add(new WriteScanFile());
        FiniteStateAnalyzeBinaryRecorder r =
                new FiniteStateAnalyzeBinaryRecorder(UNREACHABLE_SUBDOMAIN, addTokenCredential(), "scan.bin", "proj");
        r.setProjectVersion("1.0");
        p.getPublishersList().add(r);
        String log = j.getLog(p.scheduleBuild2(0).get());
        assertTrue("unset platform must default to Alloy:\n" + log, log.contains("Platform: Alloy (CLT)"));
    }
}
