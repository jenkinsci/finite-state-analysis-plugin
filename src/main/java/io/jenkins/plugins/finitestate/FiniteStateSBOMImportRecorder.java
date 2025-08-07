package io.jenkins.plugins.finitestate;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.StandardCredentials;
import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.AbstractBuild;
import hudson.model.AbstractProject;
import hudson.model.BuildListener;
import hudson.model.Item;
import hudson.security.ACL;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.Publisher;
import hudson.tasks.Recorder;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.servlet.ServletException;
import jenkins.model.Jenkins;
import org.jenkinsci.Symbol;
import org.jenkinsci.plugins.plaincredentials.StringCredentials;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.interceptor.RequirePOST;

public class FiniteStateSBOMImportRecorder extends Recorder {

    private String subdomain;
    private String apiToken;
    private String sbomFilePath;
    private String projectName;
    private String projectVersion;
    private Boolean externalizableId;
    private Boolean preRelease;

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

    public String getSubdomain() {
        return subdomain;
    }

    public String getApiToken() {
        return apiToken;
    }

    public String getSbomFilePath() {
        return sbomFilePath;
    }

    public String getProjectName() {
        return projectName;
    }

    public String getProjectVersion() {
        return projectVersion;
    }

    public boolean getExternalizableId() {
        return externalizableId != null ? externalizableId : true;
    }

    public boolean getPreRelease() {
        return preRelease != null ? preRelease : false;
    }

    @DataBoundSetter
    public void setSubdomain(String subdomain) {
        this.subdomain = subdomain;
    }

    @DataBoundSetter
    public void setApiToken(String apiToken) {
        this.apiToken = apiToken;
    }

    @DataBoundSetter
    public void setSbomFilePath(String sbomFilePath) {
        this.sbomFilePath = sbomFilePath;
    }

    @DataBoundSetter
    public void setProjectName(String projectName) {
        this.projectName = projectName;
    }

    @DataBoundSetter
    public void setProjectVersion(String projectVersion) {
        this.projectVersion = projectVersion;
    }

    @DataBoundSetter
    public void setExternalizableId(boolean externalizableId) {
        this.externalizableId = externalizableId;
    }

    @DataBoundSetter
    public void setPreRelease(boolean preRelease) {
        this.preRelease = preRelease;
    }

    private File getFileFromWorkspace(AbstractBuild build, String relativeFilePath, BuildListener listener) {
        try {
            FilePath workspace = build.getWorkspace();
            if (workspace == null) {
                listener.getLogger().println("ERROR: Workspace is null");
                return null;
            }
            FilePath filePath = workspace.child(relativeFilePath);
            return new File(filePath.getRemote());
        } catch (Exception e) {
            listener.getLogger().println("ERROR: Failed to resolve file path: " + e.getMessage());
            return null;
        }
    }

    public String getSecretTextValue(AbstractBuild build, String credentialId) {
        try {
            StringCredentials credential =
                    CredentialsProvider.findCredentialById(credentialId, StringCredentials.class, build);
            if (credential != null) {
                return credential.getSecret().getPlainText();
            }
        } catch (Exception e) {
            // Log error but continue
        }
        return null;
    }

    private int executeSBOMImport(
            Path cltPath,
            String sbomFile,
            String projectName,
            String projectVersion,
            boolean preRelease,
            BuildListener listener)
            throws IOException, InterruptedException {

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

        ProcessBuilder pb = new ProcessBuilder(command);
        pb.redirectErrorStream(true);

        Process process = pb.start();

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                listener.getLogger().println(line);
            }
        }

        return process.waitFor();
    }

    @Override
    public boolean perform(AbstractBuild build, Launcher launcher, BuildListener listener)
            throws InterruptedException, IOException {

        listener.getLogger().println("Starting Finite State SBOM Import...");

        // Get API token from credentials
        String parsedApiToken = getSecretTextValue(build, apiToken);
        if (parsedApiToken == null) {
            String errorMessage = "ERROR: Invalid API token credential";
            listener.getLogger().println(errorMessage);

            // Add error to consolidated results
            String consoleOutput = errorMessage + "\nProject: " + projectName + "\nCredential ID: " + apiToken;
            FiniteStateConsolidatedResultsAction.getOrCreate(build)
                    .addResult("SBOM Import", projectName, consoleOutput, "ERROR", "N/A");

            return false;
        }

        // Parse version
        String parsedVersion = projectVersion;
        if (getExternalizableId()) {
            parsedVersion = projectName + "#" + build.getNumber();
        }

        listener.getLogger().println("Subdomain: " + subdomain);
        listener.getLogger().println("Project name: " + projectName);
        listener.getLogger().println("SBOM file: " + sbomFilePath);
        if (parsedVersion != null && !parsedVersion.trim().isEmpty()) {
            listener.getLogger().println("Project version: " + parsedVersion);
        }

        // Check if CLT already exists, download if not
        String cltUrl = "https://" + subdomain + "/api/config/clt";
        Path cltPath = CLTManager.getOrDownloadCLT(cltUrl, parsedApiToken, listener);

        // Verify SBOM file exists
        File sbomFileObj = getFileFromWorkspace(build, sbomFilePath, listener);
        if (sbomFileObj == null || !sbomFileObj.exists()) {
            String errorMessage = "ERROR: SBOM file not found: " + sbomFilePath;
            listener.getLogger().println(errorMessage);

            // Add error to consolidated results
            String consoleOutput = errorMessage + "\nProject: " + projectName + "\nSBOM File: " + sbomFilePath;
            FiniteStateConsolidatedResultsAction.getOrCreate(build)
                    .addResult("SBOM Import", projectName, consoleOutput, "ERROR", "N/A");

            return false;
        }

        // Execute the SBOM import
        listener.getLogger().println("Executing Finite State SBOM Import...");
        int exitCode = executeSBOMImport(
                cltPath, sbomFileObj.getAbsolutePath(), projectName, parsedVersion, getPreRelease(), listener);

        if (exitCode == 0) {
            // Capture console output for display
            String consoleOutput =
                    "✅ Finite State SBOM import started successfully!\n" + "Access your scan results at: https://"
                            + subdomain + "\n" + "Project: "
                            + projectName + "\n" + "SBOM File: "
                            + sbomFilePath + "\n" + "Project Version: "
                            + parsedVersion + "\n" + "Exit Code: "
                            + exitCode;

            String scanUrl = "https://" + subdomain;
            FiniteStateConsolidatedResultsAction.getOrCreate(build)
                    .addResult("SBOM Import", projectName, consoleOutput, "SUCCESS", scanUrl);

            // Display link to scan results
            listener.getLogger().println("✅ Finite State SBOM import started successfully!");
            listener.getLogger().println("Access your scan results at: " + scanUrl);

            return true;
        } else if (exitCode == 1) {
            // Capture console output for display
            String consoleOutput = "⚠️ Finite State SBOM import completed with vulnerabilities found.\n"
                    + "Access your scan results at: https://"
                    + subdomain + "\n" + "Project: "
                    + projectName + "\n" + "SBOM File: "
                    + sbomFilePath + "\n" + "Project Version: "
                    + parsedVersion + "\n" + "Exit Code: "
                    + exitCode;

            String scanUrl = "https://" + subdomain;
            FiniteStateConsolidatedResultsAction.getOrCreate(build)
                    .addResult("SBOM Import", projectName, consoleOutput, "WARNING", scanUrl);

            // Display link to scan results even when vulnerabilities found
            listener.getLogger().println("⚠️ Finite State SBOM import completed with vulnerabilities found.");
            listener.getLogger().println("Access your scan results at: " + scanUrl);

            return true;
        } else {
            // Capture console output for error cases too
            String consoleOutput = "❌ Finite State SBOM import failed with exit code: " + exitCode + "\n" + "Project: "
                    + projectName + "\n" + "SBOM File: "
                    + sbomFilePath + "\n" + "Project Version: "
                    + parsedVersion + "\n" + "Error Details: ";

            // Handle other error codes
            switch (exitCode) {
                case 2:
                    listener.getLogger()
                            .println(
                                    "❌ Failed to connect to FiniteState service. Please check your credentials and subdomain.");
                    consoleOutput +=
                            "Failed to connect to FiniteState service. Please check your credentials and subdomain.";
                    break;
                case 100:
                    listener.getLogger().println("❌ Invalid command arguments provided to FiniteState CLT.");
                    consoleOutput += "Invalid command arguments provided to FiniteState CLT.";
                    break;
                case 101:
                    listener.getLogger().println("❌ Error with command arguments.");
                    consoleOutput += "Error with command arguments.";
                    break;
                case 200:
                    listener.getLogger().println("❌ Other errors occurred during scan execution.");
                    consoleOutput += "Other errors occurred during scan execution.";
                    break;
                default:
                    if (exitCode >= 1000) {
                        listener.getLogger().println("❌ Tool execution error (exit code: " + exitCode + ").");
                        consoleOutput += "Tool execution error (exit code: " + exitCode + ").";
                    } else {
                        listener.getLogger().println("❌ SBOM import failed with exit code: " + exitCode);
                        consoleOutput += "SBOM import failed with exit code: " + exitCode;
                    }
                    break;
            }

            FiniteStateConsolidatedResultsAction.getOrCreate(build)
                    .addResult("SBOM Import", projectName, consoleOutput, "ERROR", "N/A");
            return false;
        }
    }

    @Symbol("finite-state-import-sbom")
    @Extension
    public static final class DescriptorImpl extends BuildStepDescriptor<Publisher> {

        @RequirePOST
        public ListBoxModel doFillApiTokenItems(@AncestorInPath Item item, @QueryParameter String apiToken) {
            StandardListBoxModel items = new StandardListBoxModel();
            if (item == null) {
                if (!Jenkins.get().hasPermission(Jenkins.ADMINISTER)) {
                    return items.includeCurrentValue(apiToken);
                }
            } else {
                if (!item.hasPermission(Item.EXTENDED_READ) && !item.hasPermission(CredentialsProvider.USE_ITEM)) {
                    return items.includeCurrentValue(apiToken);
                }
            }

            // Add empty option as default
            items.add("-- Select API Token --", "");

            for (StandardCredentials credential : CredentialsProvider.lookupCredentials(
                    StandardCredentials.class, (Item) null, ACL.SYSTEM, Collections.emptyList())) {
                items.add(credential.getId());
            }
            return items;
        }

        private FormValidation checkRequiredValue(Item item, String value) {
            if (item == null
                    || !item.hasPermission(Item.EXTENDED_READ) && !item.hasPermission(CredentialsProvider.USE_ITEM)) {
                return FormValidation.error("You do not have permission to perform this action.");
            }
            if (value == null || value.trim().isEmpty()) {
                return FormValidation.error("This value is required");
            }
            return FormValidation.ok();
        }

        @RequirePOST
        // lgtm[jenkins/no-permission-check]
        public FormValidation doCheckSubdomain(@AncestorInPath Item item, @QueryParameter String value)
                throws IOException, ServletException {
            return checkRequiredValue(item, value);
        }

        @RequirePOST
        // lgtm[jenkins/no-permission-check]
        public FormValidation doCheckApiToken(@AncestorInPath Item item, @QueryParameter String value)
                throws IOException, ServletException {
            return checkRequiredValue(item, value);
        }

        @RequirePOST
        // lgtm[jenkins/no-permission-check]
        public FormValidation doCheckSbomFilePath(@AncestorInPath Item item, @QueryParameter String value)
                throws IOException, ServletException {
            return checkRequiredValue(item, value);
        }

        @RequirePOST
        // lgtm[jenkins/no-permission-check]
        public FormValidation doCheckProjectName(@AncestorInPath Item item, @QueryParameter String value)
                throws IOException, ServletException {
            return checkRequiredValue(item, value);
        }

        @Override
        public boolean isApplicable(Class<? extends AbstractProject> aClass) {
            return true;
        }

        @Override
        public String getDisplayName() {
            return "Finite State Import SBOM";
        }
    }
}
