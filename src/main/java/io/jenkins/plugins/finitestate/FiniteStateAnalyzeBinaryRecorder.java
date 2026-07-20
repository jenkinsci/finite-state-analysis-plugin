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
 * Refactored Binary Analysis Recorder that extends the base class to reduce code duplication.
 * This demonstrates how the new base classes can be used to eliminate repetitive code.
 */
public class FiniteStateAnalyzeBinaryRecorder extends BaseFiniteStateRecorder {

    private String binaryFilePath;
    private Boolean scaEnabled;
    private Boolean sastEnabled;
    private Boolean configEnabled;
    private Boolean reachabilityEnabled;

    @DataBoundConstructor
    public FiniteStateAnalyzeBinaryRecorder(
            String subdomain, String apiTokenCredentialsId, String binaryFilePath, String projectName) {
        this.subdomain = subdomain;
        this.apiTokenCredentialsId = apiTokenCredentialsId;
        this.binaryFilePath = binaryFilePath;
        this.projectName = projectName;
    }

    public String getBinaryFilePath() {
        return binaryFilePath;
    }

    public boolean getScaEnabled() {
        return scaEnabled != null ? scaEnabled : true; // Default to true as it's required
    }

    public boolean getSastEnabled() {
        return sastEnabled != null ? sastEnabled : false;
    }

    public boolean getConfigEnabled() {
        return configEnabled != null ? configEnabled : false;
    }

    public boolean getReachabilityEnabled() {
        return reachabilityEnabled != null ? reachabilityEnabled : true;
    }

    @DataBoundSetter
    public void setBinaryFilePath(String binaryFilePath) {
        this.binaryFilePath = binaryFilePath;
    }

    @DataBoundSetter
    public void setScaEnabled(boolean scaEnabled) {
        this.scaEnabled = scaEnabled;
    }

    @DataBoundSetter
    public void setSastEnabled(boolean sastEnabled) {
        this.sastEnabled = sastEnabled;
    }

    @DataBoundSetter
    public void setConfigEnabled(boolean configEnabled) {
        this.configEnabled = configEnabled;
    }

    @DataBoundSetter
    public void setReachabilityEnabled(boolean reachabilityEnabled) {
        this.reachabilityEnabled = reachabilityEnabled;
    }

    @Override
    protected void configureRequest(FiniteStateScanRequest request) {
        request.setKind(FiniteStateScanRequest.Kind.BINARY);
        // The four checkboxes map onto the mb-api `types` tokens in FiniteStateApiClient#buildScanTypes
        // (sca→sca, sast→sast, config→config, reachability→vulnerability_analysis). The façade
        // (POST /scans/upload) converts those tokens into the server-side scan config.
        request.setScaEnabled(getScaEnabled());
        request.setSastEnabled(getSastEnabled());
        request.setConfigEnabled(getConfigEnabled());
        request.setReachabilityEnabled(getReachabilityEnabled());
    }

    @Override
    protected String getAnalysisType() {
        return "Binary Analysis";
    }

    @Override
    protected String getFilePathFieldName() {
        return "Binary file";
    }

    @Override
    protected String getFilePathValue() {
        return binaryFilePath;
    }

    @Symbol("finiteStateAnalyzeBinary")
    @Extension
    public static final class DescriptorImpl extends BaseFiniteStateDescriptor {

        @RequirePOST
        // lgtm[jenkins/no-permission-check]
        public FormValidation doCheckBinaryFilePath(@QueryParameter String value) throws IOException, ServletException {
            return checkRequiredValue(value);
        }

        @Override
        public String getDisplayName() {
            return "Finite State Analyze Binary";
        }
    }
}
