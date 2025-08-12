package io.jenkins.plugins.finitestate;

import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.AbstractBuild;
import hudson.model.BuildListener;
import hudson.model.TaskListener;
import hudson.util.FormValidation;
import java.io.IOException;
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
    public boolean perform(AbstractBuild build, Launcher launcher, BuildListener listener)
            throws InterruptedException, IOException {
        return FiniteStateExecutionFramework.executeAnalysis(this, build, launcher, listener);
    }

    @Override
    protected int executeAnalysis(
            FilePath cltPath,
            FilePath filePath,
            String projectName,
            String projectVersion,
            FilePath workspace,
            Launcher launcher,
            TaskListener listener)
            throws IOException, InterruptedException {
        return executeSBOMImport(
                cltPath, filePath, projectName, projectVersion, getPreRelease(), workspace, launcher, listener);
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
            FilePath cltPath,
            FilePath sbomFile,
            String projectName,
            String projectVersion,
            boolean preRelease,
            FilePath workspace,
            Launcher launcher,
            TaskListener listener)
            throws IOException, InterruptedException {

        // Build the command
        List<String> command = new ArrayList<>();
        command.add("java");
        command.add("-jar");
        command.add(cltPath.getRemote());
        command.add("--import");
        command.add("--name=" + projectName);
        command.add("--version=" + projectVersion);
        command.add(sbomFile.getRemote());

        if (preRelease) {
            command.add("--pre-release");
        }

        listener.getLogger().println("Executing command: " + String.join(" ", command));

        Launcher.ProcStarter starter = launcher.launch();
        starter.cmds(command);
        starter.stdout(listener.getLogger());
        starter.stderr(listener.getLogger());
        starter.pwd(workspace);

        return starter.join();
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
