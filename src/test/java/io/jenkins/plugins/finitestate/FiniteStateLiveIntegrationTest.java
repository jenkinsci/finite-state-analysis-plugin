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

        // 1) Binary — single PUT, ALL scan types (sca + sast + config + reachability→vuln_analysis).
        File small = File.createTempFile("fs-e2e-small-", ".bin");
        Files.write(
                small.toPath(), "finite-state jenkins facade e2e single-put payload".getBytes(StandardCharsets.UTF_8));
        ScanResult r1 = new ScanResult();
        client.runBinary(small, binReqAllTypes(project, version + "-bin-single-alltypes"), r1);
        assertTrue(label + " binary single-PUT (all types) should succeed", r1.isSuccess());
        assertFalse(
                label + " binary single-PUT should return scan ids",
                r1.getScanIds().isEmpty());
        System.out.println("[" + label + "] binary single-PUT all-types scans=" + r1.getScanIdsDisplay() + " url="
                + r1.getUiUrl());

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

        // 3) SBOM — CycloneDX (single-shot). SBOM single-shot returns a scanId on the current backend
        //    but not on the previous backend (2xx, no id) — assert submission succeeded, not an id.
        File cdx = File.createTempFile("fs-e2e-", ".cdx.json");
        Files.writeString(
                cdx.toPath(),
                "{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.5\",\"version\":1,\"components\":[]}",
                StandardCharsets.UTF_8);
        ScanResult r3 = new ScanResult();
        client.runSbom(cdx, sbomReq(project, version + "-sbom-cdx"), r3);
        assertTrue(label + " SBOM CycloneDX import should succeed", r3.isSuccess());
        System.out.println("[" + label + "] SBOM cdx submitted, scans=" + r3.getScanIdsDisplay());

        // 4) SBOM — SPDX (single-shot); detected as spdx by the .spdx.json name + spdxVersion content.
        File spdx = File.createTempFile("fs-e2e-", ".spdx.json");
        Files.writeString(
                spdx.toPath(),
                "{\"spdxVersion\":\"SPDX-2.3\",\"SPDXID\":\"SPDXRef-DOCUMENT\",\"name\":\"fs-e2e\",\"packages\":[]}",
                StandardCharsets.UTF_8);
        ScanResult r4 = new ScanResult();
        client.runSbom(spdx, sbomReq(project, version + "-sbom-spdx"), r4);
        assertTrue(label + " SBOM SPDX import should succeed", r4.isSuccess());
        System.out.println("[" + label + "] SBOM spdx submitted, scans=" + r4.getScanIdsDisplay());

        // 5) Third-party import (single-shot) — a representative scanner (anchore_grype).
        File tp = File.createTempFile("fs-e2e-tp-", ".json");
        Files.writeString(tp.toPath(), "{\"matches\":[]}", StandardCharsets.UTF_8);
        ScanResult r5 = new ScanResult();
        client.runThirdParty(tp, thirdPartyReq(project, version + "-3p", "anchore_grype"), r5);
        assertTrue(label + " third-party import should succeed", r5.isSuccess());
        System.out.println("[" + label + "] third-party submitted, scans=" + r5.getScanIdsDisplay());
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

    private FiniteStateScanRequest binReqAllTypes(String project, String version) {
        FiniteStateScanRequest req = binReq(project, version);
        req.setSastEnabled(true);
        req.setConfigEnabled(true);
        // sca + reachability already true → types = [sca, sast, config, vulnerability_analysis]
        return req;
    }

    private FiniteStateScanRequest thirdPartyReq(String project, String version, String scanType) {
        FiniteStateScanRequest req = new FiniteStateScanRequest();
        req.setKind(FiniteStateScanRequest.Kind.THIRD_PARTY);
        req.setProjectName(project);
        req.setVersion(version);
        req.setPreRelease(true);
        req.setWaitForCompletion(false);
        req.setPollTimeoutMinutes(30);
        req.setScanType(scanType);
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
