package io.jenkins.plugins.finitestate;

import hudson.Extension;
import hudson.util.FormValidation;
import java.io.IOException;
import javax.servlet.ServletException;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.interceptor.RequirePOST;

/**
 * Refactored SBOM Import Recorder that extends the base class to reduce code duplication.
 * This demonstrates how the new base classes can be used to eliminate repetitive code.
 */
public class FiniteStateSBOMImportRecorder extends BaseFiniteStateRecorder {

    private String sbomFilePath;

    @DataBoundConstructor
    public FiniteStateSBOMImportRecorder(
            String subdomain, String apiTokenCredentialsId, String sbomFilePath, String projectName) {
        this.subdomain = subdomain;
        this.apiTokenCredentialsId = apiTokenCredentialsId;
        this.sbomFilePath = sbomFilePath;
        this.projectName = projectName;
    }

    public String getSbomFilePath() {
        return sbomFilePath;
    }

    @DataBoundSetter
    public void setSbomFilePath(String sbomFilePath) {
        this.sbomFilePath = sbomFilePath;
    }

    @Override
    protected void configureRequest(FiniteStateScanRequest request) {
        request.setKind(FiniteStateScanRequest.Kind.SBOM);
        // CycloneDX vs SPDX is auto-detected from the file (FiniteStateApiClient.detectSbomFormat).
    }

    @Override
    protected String getAnalysisType() {
        return "SBOM Import";
    }

    @Override
    protected String getFilePathFieldName() {
        return "SBOM file";
    }

    @Override
    protected String getFilePathValue() {
        return sbomFilePath;
    }

    @Symbol("finiteStateImportSbom")
    @Extension
    public static final class DescriptorImpl extends BaseFiniteStateDescriptor {

        @RequirePOST
        // lgtm[jenkins/no-permission-check]
        public FormValidation doCheckSbomFilePath(@QueryParameter String value) throws IOException, ServletException {
            return checkRequiredValue(value);
        }

        @Override
        public String getDisplayName() {
            return "Finite State Import SBOM";
        }
    }
}
