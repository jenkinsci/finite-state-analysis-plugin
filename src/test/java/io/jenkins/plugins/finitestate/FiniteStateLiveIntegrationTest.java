package io.jenkins.plugins.finitestate;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import hudson.model.TaskListener;
import hudson.util.Secret;
import hudson.util.StreamTaskListener;
import java.io.File;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import org.junit.Assume;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

/**
 * Live end-to-end verification of {@link FiniteStateApiClient} against real backends, driving the
 * exact code path the agent runs. GATED on environment variables so it skips in CI and normal runs:
 *
 * <pre>
 *   FS_ALLOY_SUBDOMAIN / FS_ALLOY_TOKEN   → previous backend (serves /scans/upload natively)
 *   FS_HELIX_SUBDOMAIN / FS_HELIX_TOKEN    → current backend (/scans/upload façade)
 * </pre>
 *
 * Run: {@code mvn test -Dtest=FiniteStateLiveIntegrationTest} with those vars set.
 */
public class FiniteStateLiveIntegrationTest {

    @Rule
    public JenkinsRule j = new JenkinsRule();

    private static final long MB = 1024L * 1024L;

    @Test
    public void alloyBackendAllFlows() throws Exception {
        runAllFlows(System.getenv("FS_ALLOY_SUBDOMAIN"), System.getenv("FS_ALLOY_TOKEN"), "alloy");
    }

    @Test
    public void helixBackendAllFlows() throws Exception {
        runAllFlows(System.getenv("FS_HELIX_SUBDOMAIN"), System.getenv("FS_HELIX_TOKEN"), "helix");
    }

    private void runAllFlows(String subdomain, String token, String label) throws Exception {
        Assume.assumeTrue("skipping " + label + " (subdomain/token env not set)", subdomain != null && token != null);

        TaskListener listener = StreamTaskListener.fromStdout();
        FiniteStateApiClient client = new FiniteStateApiClient(subdomain, Secret.fromString(token), listener);
        String version = "e2e-" + label + "-" + System.currentTimeMillis();
        String project = "jenkins-facade-e2e";

        // 1) Binary — single PUT (small file, < 100 MB threshold).
        File small = File.createTempFile("fs-e2e-small-", ".bin");
        Files.write(
                small.toPath(), "finite-state jenkins facade e2e single-put payload".getBytes(StandardCharsets.UTF_8));
        ScanResult r1 = new ScanResult();
        client.runBinary(small, binReq(project, version + "-bin-single"), r1);
        assertTrue(label + " binary single-PUT should succeed", r1.isSuccess());
        assertFalse(
                label + " binary single-PUT should return scan ids",
                r1.getScanIds().isEmpty());
        System.out.println(
                "[" + label + "] binary single-PUT scans=" + r1.getScanIdsDisplay() + " url=" + r1.getUiUrl());

        // 2) Binary — multipart (105 MB forces the > 100 MB multipart branch). Exercises the
        //    s3UploadId part-URL path, the eTags map at /complete, and the part-plan logic
        //    (server-dictated on the current backend, client-computed on the previous backend).
        File big = File.createTempFile("fs-e2e-big-", ".bin");
        try (RandomAccessFile raf = new RandomAccessFile(big, "rw")) {
            raf.setLength(105L * MB);
        }
        ScanResult r2 = new ScanResult();
        client.runBinary(big, binReq(project, version + "-bin-multipart"), r2);
        assertTrue(label + " binary multipart should succeed", r2.isSuccess());
        assertFalse(
                label + " binary multipart should return scan ids",
                r2.getScanIds().isEmpty());
        System.out.println(
                "[" + label + "] binary multipart scans=" + r2.getScanIdsDisplay() + " url=" + r2.getUiUrl());
        big.delete();

        // 3) SBOM — single-shot octet-stream (unchanged path; confirms it still works on both backends).
        File sbom = File.createTempFile("fs-e2e-", ".cdx.json");
        Files.writeString(
                sbom.toPath(),
                "{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.5\",\"version\":1,\"components\":[]}",
                StandardCharsets.UTF_8);
        ScanResult r3 = new ScanResult();
        client.runSbom(sbom, sbomReq(project, version + "-sbom"), r3);
        // SBOM single-shot returns a scanId on the current backend but not on the previous backend
        // (which accepts the upload with a 2xx and no id) — so assert submission succeeded, not an id.
        assertTrue(label + " SBOM import should succeed", r3.isSuccess());
        System.out.println("[" + label + "] SBOM submitted, scans=" + r3.getScanIdsDisplay() + " url=" + r3.getUiUrl());
    }

    private FiniteStateScanRequest binReq(String project, String version) {
        FiniteStateScanRequest req = new FiniteStateScanRequest();
        req.setKind(FiniteStateScanRequest.Kind.BINARY);
        req.setProjectName(project);
        req.setVersion(version);
        req.setPreRelease(true);
        req.setWaitForCompletion(false);
        req.setPollTimeoutMinutes(30);
        req.setScaEnabled(true);
        req.setReachabilityEnabled(true);
        return req;
    }

    private FiniteStateScanRequest sbomReq(String project, String version) {
        FiniteStateScanRequest req = new FiniteStateScanRequest();
        req.setKind(FiniteStateScanRequest.Kind.SBOM);
        req.setProjectName(project);
        req.setVersion(version);
        req.setPreRelease(true);
        req.setWaitForCompletion(false);
        req.setPollTimeoutMinutes(30);
        return req;
    }
}
