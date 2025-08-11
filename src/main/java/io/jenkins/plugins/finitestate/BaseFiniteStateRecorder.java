package io.jenkins.plugins.finitestate;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.StandardCredentials;
import hudson.FilePath;
import hudson.model.AbstractBuild;
import hudson.model.BuildListener;
import hudson.tasks.Recorder;
import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import org.jenkinsci.plugins.plaincredentials.StringCredentials;

/**
 * Abstract base class for all Finite State recorders.
 * Contains common functionality shared across different analysis types.
 */
public abstract class BaseFiniteStateRecorder extends Recorder {

    protected String subdomain;
    protected String apiToken;
    protected String projectName;
    protected String projectVersion;
    protected Boolean externalizableId;
    protected Boolean preRelease;

    protected BaseFiniteStateRecorder() {
        // Default constructor for inheritance
    }

    // Common getters
    public String getSubdomain() {
        return subdomain;
    }

    public String getApiToken() {
        return apiToken;
    }

    public String getProjectName() {
        return projectName;
    }

    public String getProjectVersion() {
        return projectVersion;
    }

    public boolean getExternalizableId() {
        return externalizableId != null ? externalizableId : false;
    }

    public boolean getPreRelease() {
        return preRelease != null ? preRelease : false;
    }

    // Common setters
    public void setSubdomain(String subdomain) {
        this.subdomain = subdomain;
    }

    public void setApiToken(String apiToken) {
        this.apiToken = apiToken;
    }

    public void setProjectName(String projectName) {
        this.projectName = projectName;
    }

    public void setProjectVersion(String projectVersion) {
        this.projectVersion = projectVersion;
    }

    public void setExternalizableId(boolean externalizableId) {
        this.externalizableId = externalizableId;
    }

    public void setPreRelease(boolean preRelease) {
        this.preRelease = preRelease;
    }

    /**
     * Get file from workspace - common utility method
     */
    protected File getFileFromWorkspace(AbstractBuild build, String relativeFilePath, BuildListener listener) {
        // Get the workspace directory for the current build
        FilePath workspace = build.getWorkspace();
        if (workspace != null) {
            String workspaceRemote = workspace.getRemote();
            // Construct the absolute path to the file
            File file = new File(workspaceRemote, relativeFilePath);
            listener.getLogger().println("Looking for file at: " + file.getAbsolutePath());
            return file;
        }
        listener.getLogger().println("ERROR: Could not determine workspace path");
        return null;
    }

    /**
     * Get secret values from credentials - common utility method
     */
    protected String getSecretTextValue(AbstractBuild build, String credentialId) {
        StandardCredentials credentials =
                CredentialsProvider.findCredentialById(credentialId, StringCredentials.class, build);

        if (credentials instanceof StringCredentials) {
            StringCredentials stringCredentials = (StringCredentials) credentials;
            return stringCredentials.getSecret().getPlainText();
        }
        return null;
    }

    /**
     * Get CLT path using the shared CLTManager
     */
    protected Path getCLTPath(String subdomain, String apiToken, BuildListener listener) throws IOException {
        String cltUrl = "https://" + subdomain + "/api/config/clt";
        return CLTManager.getOrDownloadCLT(cltUrl, apiToken, subdomain, listener);
    }

    /**
     * Parse version based on externalizableId setting
     */
    protected String parseVersion(AbstractBuild build, String projectVersion) {
        if (getExternalizableId()) {
            return build.getExternalizableId();
        }
        return projectVersion;
    }

    /**
     * Validate common required fields
     */
    protected boolean validateCommonFields(BuildListener listener) {
        if (subdomain == null || subdomain.trim().isEmpty()) {
            listener.getLogger().println("ERROR: Subdomain is required");
            return false;
        }
        if (apiToken == null || apiToken.trim().isEmpty()) {
            listener.getLogger().println("ERROR: API Token is required");
            return false;
        }
        if (projectName == null || projectName.trim().isEmpty()) {
            listener.getLogger().println("ERROR: Project name is required");
            return false;
        }
        return true;
    }

    /**
     * Log common information
     */
    protected void logCommonInfo(AbstractBuild build, BuildListener listener, String filePath) {
        listener.getLogger().println("Subdomain: " + subdomain);
        listener.getLogger().println("Project: " + projectName);
        if (filePath != null) {
            listener.getLogger().println("File: " + filePath);
        }

        String parsedVersion = parseVersion(build, projectVersion);
        if (parsedVersion != null && !parsedVersion.trim().isEmpty()) {
            listener.getLogger().println("Project version: " + parsedVersion);
        }
    }

    /**
     * Add result to consolidated results action
     */
    protected void addConsolidatedResult(
            AbstractBuild build,
            String analysisType,
            String projectName,
            String consoleOutput,
            String status,
            String url) {
        FiniteStateConsolidatedResultsAction.getOrCreate(build)
                .addResult(analysisType, projectName, consoleOutput, status, url);
    }

    /**
     * Abstract method for executing the specific analysis
     */
    protected abstract int executeAnalysis(
            Path cltPath, String filePath, String projectName, String projectVersion, BuildListener listener)
            throws IOException, InterruptedException;

    /**
     * Get the analysis type name for logging and results
     */
    protected abstract String getAnalysisType();

    /**
     * Get the file path field name for validation
     */
    protected abstract String getFilePathFieldName();

    /**
     * Get the file path value
     */
    protected abstract String getFilePathValue();
}
