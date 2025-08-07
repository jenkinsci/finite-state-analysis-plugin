package io.jenkins.plugins.finitestate;

import hudson.Extension;
import hudson.Launcher;
import hudson.model.AbstractBuild;
import hudson.model.BuildListener;
import hudson.util.FormValidation;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
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
public class FiniteStateAnalyzeBinaryRecorderRefactored extends BaseFiniteStateRecorder {

    private String binaryFilePath;
    private String scanTypes;
    private Boolean scaEnabled;
    private Boolean sastEnabled;
    private Boolean configEnabled;

    @DataBoundConstructor
    public FiniteStateAnalyzeBinaryRecorderRefactored(
            String subdomain,
            String apiToken,
            String binaryFilePath,
            String projectName,
            String projectVersion,
            String scanTypes,
            Boolean externalizableId,
            Boolean scaEnabled,
            Boolean sastEnabled,
            Boolean configEnabled,
            Boolean preRelease) {
        this.subdomain = subdomain;
        this.apiToken = apiToken;
        this.binaryFilePath = binaryFilePath;
        this.projectName = projectName;
        this.projectVersion = projectVersion;
        this.scanTypes = scanTypes;
        this.externalizableId = externalizableId;
        this.scaEnabled = scaEnabled;
        this.sastEnabled = sastEnabled;
        this.configEnabled = configEnabled;
        this.preRelease = preRelease;
    }

    public String getBinaryFilePath() {
        return binaryFilePath;
    }

    public String getScanTypes() {
        return scanTypes;
    }

    public boolean getScaEnabled() {
        return scaEnabled != null ? scaEnabled : false;
    }

    public boolean getSastEnabled() {
        return sastEnabled != null ? sastEnabled : false;
    }

    public boolean getConfigEnabled() {
        return configEnabled != null ? configEnabled : false;
    }

    @DataBoundSetter
    public void setBinaryFilePath(String binaryFilePath) {
        this.binaryFilePath = binaryFilePath;
    }

    @DataBoundSetter
    public void setScanTypes(String scanTypes) {
        this.scanTypes = scanTypes;
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

    @Override
    public boolean perform(AbstractBuild build, Launcher launcher, BuildListener listener)
            throws InterruptedException, IOException {
        return FiniteStateExecutionFramework.executeAnalysis(this, build, launcher, listener);
    }

    @Override
    protected int executeAnalysis(Path cltPath, String filePath, String projectName, 
                                String projectVersion, BuildListener listener) 
                                throws IOException, InterruptedException {
        return executeCLT(cltPath, filePath, projectName, projectVersion, 
                         buildScanTypesString(), getPreRelease(), listener);
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

    /**
     * Build scan types string from checkboxes
     */
    private String buildScanTypesString() {
        List<String> selectedTypes = new ArrayList<>();
        
        if (getScaEnabled()) {
            selectedTypes.add("sca");
        }
        if (getSastEnabled()) {
            selectedTypes.add("sast");
        }
        if (getConfigEnabled()) {
            selectedTypes.add("config");
        }
        
        return String.join(",", selectedTypes);
    }

    /**
     * Execute the CLT command for binary analysis
     */
    private int executeCLT(
            Path cltPath,
            String binaryFile,
            String projectName,
            String projectVersion,
            String scanTypes,
            boolean preRelease,
            BuildListener listener)
            throws IOException, InterruptedException {

        // Build the command
        List<String> command = new ArrayList<>();
        command.add("java");
        command.add("-jar");
        command.add(cltPath.toString());
        command.add("--upload");
        command.add(binaryFile);
        command.add("--name=" + projectName);

        if (projectVersion != null && !projectVersion.trim().isEmpty()) {
            command.add("--version=" + projectVersion);
        }

        if (scanTypes != null && !scanTypes.trim().isEmpty()) {
            command.add("--scan-types=" + scanTypes);
        }

        if (preRelease) {
            command.add("--pre-release");
        }

        listener.getLogger().println("Executing command: " + String.join(" ", command));

        // Execute the process
        ProcessBuilder processBuilder = new ProcessBuilder(command);
        processBuilder.redirectErrorStream(true);

        Process process = processBuilder.start();

        // Read output and look for URL
        String uploadUrl = null;
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                listener.getLogger().println(line);
                // Look for URL in the output
                if (line.contains("https://") && line.contains("finitestate.io")) {
                    uploadUrl = line.trim();
                }
            }
        }

        int exitCode = process.waitFor();

        if (exitCode == 0 && uploadUrl != null) {
            listener.getLogger().println("Finite State scan started successfully");
            listener.getLogger().println("Upload URL: " + uploadUrl);
        } else if (exitCode != 0) {
            listener.getLogger().println("Finite State scan failed with exit code: " + exitCode);
        }

        return exitCode;
    }

    @Symbol("finite-state-analyze-binary")
    @Extension
    public static final class DescriptorImpl extends BaseFiniteStateDescriptor {

        @RequirePOST
        public FormValidation doCheckBinaryFilePath(@QueryParameter String value)
                throws IOException, ServletException {
            return checkRequiredValue(null, value);
        }

        @Override
        public String getDisplayName() {
            return "Finite State Binary Analysis";
        }
    }
}
