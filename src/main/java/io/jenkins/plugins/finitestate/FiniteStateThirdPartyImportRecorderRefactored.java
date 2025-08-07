package io.jenkins.plugins.finitestate;

import hudson.Extension;
import hudson.Launcher;
import hudson.model.AbstractBuild;
import hudson.model.BuildListener;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
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
 * Refactored Third Party Import Recorder that extends the base class to reduce code duplication.
 */
public class FiniteStateThirdPartyImportRecorderRefactored extends BaseFiniteStateRecorder {

    private String scanFilePath;
    private String scanType;

    @DataBoundConstructor
    public FiniteStateThirdPartyImportRecorderRefactored(
            String subdomain,
            String apiToken,
            String scanFilePath,
            String projectName,
            String projectVersion,
            Boolean externalizableId,
            String scanType,
            Boolean preRelease) {
        this.subdomain = subdomain;
        this.apiToken = apiToken;
        this.scanFilePath = scanFilePath;
        this.projectName = projectName;
        this.projectVersion = projectVersion;
        this.externalizableId = externalizableId;
        this.scanType = scanType;
        this.preRelease = preRelease;
    }

    public String getScanFilePath() {
        return scanFilePath;
    }

    public String getScanType() {
        return scanType;
    }

    @DataBoundSetter
    public void setScanFilePath(String scanFilePath) {
        this.scanFilePath = scanFilePath;
    }

    @DataBoundSetter
    public void setScanType(String scanType) {
        this.scanType = scanType;
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
        return executeThirdPartyImport(cltPath, filePath, projectName, projectVersion, 
                                     scanType, getPreRelease(), listener);
    }

    @Override
    protected String getAnalysisType() {
        return "Third Party Import";
    }

    @Override
    protected String getFilePathFieldName() {
        return "Scan file";
    }

    @Override
    protected String getFilePathValue() {
        return scanFilePath;
    }

    /**
     * Execute the third party import command
     */
    private int executeThirdPartyImport(
            Path cltPath,
            String scanFile,
            String projectName,
            String projectVersion,
            String scanType,
            boolean preRelease,
            BuildListener listener)
            throws IOException, InterruptedException {

        // Build the command
        List<String> command = new ArrayList<>();
        command.add("java");
        command.add("-jar");
        command.add(cltPath.toString());
        command.add("--import-third-party");
        command.add(scanFile);
        command.add("--name=" + projectName);

        if (projectVersion != null && !projectVersion.trim().isEmpty()) {
            command.add("--version=" + projectVersion);
        }

        if (scanType != null && !scanType.trim().isEmpty()) {
            command.add("--scan-type=" + scanType);
        }

        if (preRelease) {
            command.add("--pre-release");
        }

        listener.getLogger().println("Executing command: " + String.join(" ", command));

        // Execute the process
        ProcessBuilder processBuilder = new ProcessBuilder(command);
        processBuilder.redirectErrorStream(true);

        Process process = processBuilder.start();

        // Read output
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                listener.getLogger().println(line);
            }
        }

        return process.waitFor();
    }

    @Symbol("finite-state-import-third-party")
    @Extension
    public static final class DescriptorImpl extends BaseFiniteStateDescriptor {

        @RequirePOST
        public FormValidation doCheckScanFilePath(@QueryParameter String value)
                throws IOException, ServletException {
            return checkRequiredValue(null, value);
        }

        @RequirePOST
        public FormValidation doCheckScanType(@QueryParameter String value)
                throws IOException, ServletException {
            return checkRequiredValue(null, value);
        }

        @RequirePOST
        public ListBoxModel doFillScanTypeItems() {
            ListBoxModel items = new ListBoxModel();
            items.add("-- Select Scan Type --", "");
            items.add("SAST", "sast");
            items.add("SCA", "sca");
            items.add("Config", "config");
            items.add("License", "license");
            items.add("Vulnerability", "vulnerability");
            return items;
        }

        @Override
        public String getDisplayName() {
            return "Finite State Third Party Import";
        }
    }
}
