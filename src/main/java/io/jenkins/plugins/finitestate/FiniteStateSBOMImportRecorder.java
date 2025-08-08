package io.jenkins.plugins.finitestate;

import hudson.Extension;
import hudson.Launcher;
import hudson.model.AbstractBuild;
import hudson.model.BuildListener;
import hudson.util.FormValidation;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
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
 * Refactored SBOM Import Recorder that extends the base class to reduce code duplication.
 * This demonstrates how the new base classes can be used to eliminate repetitive code.
 */
public class FiniteStateSBOMImportRecorder extends BaseFiniteStateRecorder {

    private String sbomFilePath;

    @DataBoundConstructor
    public FiniteStateSBOMImportRecorder(
            String subdomain,
            String apiToken,
            String sbomFilePath,
            String projectName,
            String projectVersion,
            Boolean externalizableId,
            Boolean preRelease) {
        this.subdomain = subdomain;
        this.apiToken = apiToken;
        this.sbomFilePath = sbomFilePath;
        this.projectName = projectName;
        this.projectVersion = projectVersion;
        this.externalizableId = externalizableId;
        this.preRelease = preRelease;
    }

    public String getSbomFilePath() {
        return sbomFilePath;
    }

    @DataBoundSetter
    public void setSbomFilePath(String sbomFilePath) {
        this.sbomFilePath = sbomFilePath;
    }

    @Override
    public boolean perform(AbstractBuild build, Launcher launcher, BuildListener listener)
            throws InterruptedException, IOException {
        return FiniteStateExecutionFramework.executeAnalysis(this, build, launcher, listener);
    }

    @Override
    protected int executeAnalysis(
            Path cltPath, String filePath, String projectName, String projectVersion, BuildListener listener)
            throws IOException, InterruptedException {
        return executeSBOMImport(cltPath, filePath, projectName, projectVersion, getPreRelease(), listener);
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

    /**
     * Execute the SBOM import command
     */
    private int executeSBOMImport(
            Path cltPath,
            String sbomFile,
            String projectName,
            String projectVersion,
            boolean preRelease,
            BuildListener listener)
            throws IOException, InterruptedException {

        // Build the command
        List<String> command = new ArrayList<>();
        command.add("java");
        command.add("-jar");
        command.add(cltPath.toString());
        command.add("--import");
        command.add("--name=" + projectName);
        command.add("--version=" + projectVersion);
        command.add(sbomFile);

        if (preRelease) {
            command.add("--pre-release");
        }

        listener.getLogger().println("Executing command: " + String.join(" ", command));

        // Execute the process
        ProcessBuilder processBuilder = new ProcessBuilder(command);
        processBuilder.redirectErrorStream(true);

        Process process = processBuilder.start();

        // Read output
        try (BufferedReader reader =
                new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                listener.getLogger().println(line);
            }
        }

        return process.waitFor();
    }

    @Symbol("finite-state-import-sbom")
    @Extension
    public static final class DescriptorImpl extends BaseFiniteStateDescriptor {

        @RequirePOST
        public FormValidation doCheckSbomFilePath(@QueryParameter String value) throws IOException, ServletException {
            return checkRequiredValue(null, value);
        }

        @Override
        public String getDisplayName() {
            return "Finite State Import SBOM";
        }
    }
}
