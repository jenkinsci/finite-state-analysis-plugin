package io.jenkins.plugins.finitestate;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.StandardCredentials;
import hudson.EnvVars;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.tasks.Recorder;
import java.io.IOException;
import jenkins.tasks.SimpleBuildStep;
import org.jenkinsci.plugins.plaincredentials.StringCredentials;
import org.kohsuke.stapler.DataBoundSetter;

/**
 * Abstract base class for all Finite State recorders.
 * Contains common functionality shared across different analysis types.
 *
 * <p>As of the v0 API migration the plugin no longer downloads or executes the CLT jar; each
 * recorder describes its work via {@link #configureRequest(FiniteStateScanRequest)} and the shared
 * {@link FiniteStateExecutionFramework} drives the REST flow.
 */
public abstract class BaseFiniteStateRecorder extends Recorder implements SimpleBuildStep {

    /** Default poll timeout (minutes) when waiting for scan completion (FR-7). */
    public static final int DEFAULT_POLL_TIMEOUT_MINUTES = 30;

    protected String subdomain;
    // Explicit name indicating this is a Jenkins Credentials ID (Secret Text) holding the API token.
    protected String apiTokenCredentialsId;
    protected String projectName;
    protected String projectVersion;
    protected Boolean externalizableId;
    protected Boolean preRelease;
    protected Boolean waitForCompletion;
    protected Integer pollTimeoutMinutes;

    protected BaseFiniteStateRecorder() {
        // Default constructor for inheritance
    }

    // Common getters
    public String getSubdomain() {
        return subdomain;
    }

    public String getApiTokenCredentialsId() {
        return apiTokenCredentialsId;
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

    public boolean getWaitForCompletion() {
        return waitForCompletion != null ? waitForCompletion : true; // FR-7: default true (blocking)
    }

    public int getPollTimeoutMinutes() {
        return pollTimeoutMinutes != null && pollTimeoutMinutes > 0 ? pollTimeoutMinutes : DEFAULT_POLL_TIMEOUT_MINUTES;
    }

    // Common setters
    public void setSubdomain(String subdomain) {
        this.subdomain = subdomain;
    }

    /**
     * Setter to allow Pipeline usage like: apiTokenCredentialsId: 'my-secret-text-id'
     */
    @DataBoundSetter
    public void setApiTokenCredentialsId(String apiTokenCredentialsId) {
        this.apiTokenCredentialsId = apiTokenCredentialsId;
    }

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

    @DataBoundSetter
    public void setWaitForCompletion(boolean waitForCompletion) {
        this.waitForCompletion = waitForCompletion;
    }

    @DataBoundSetter
    public void setPollTimeoutMinutes(int pollTimeoutMinutes) {
        this.pollTimeoutMinutes = pollTimeoutMinutes;
    }

    /**
     * Get file from workspace - common utility method (pipeline and freestyle)
     */
    protected FilePath getFileFromWorkspace(FilePath workspace, String relativeFilePath, TaskListener listener)
            throws IOException, InterruptedException {
        if (workspace != null) {
            FilePath child = workspace.child(relativeFilePath);
            listener.getLogger().println("Looking for file at: " + child.getRemote());
            return child;
        }
        listener.getLogger().println("ERROR: Could not determine workspace path");
        return null;
    }

    /**
     * Get secret values from credentials - common utility method (pipeline and freestyle)
     */
    protected String getSecretTextValue(Run<?, ?> run, String credentialId) {
        StandardCredentials credentials =
                CredentialsProvider.findCredentialById(credentialId, StringCredentials.class, run);

        if (credentials instanceof StringCredentials) {
            StringCredentials stringCredentials = (StringCredentials) credentials;
            return stringCredentials.getSecret().getPlainText();
        }
        return null;
    }

    /**
     * Parse version based on externalizableId setting
     */
    protected String parseVersion(Run<?, ?> run, String projectVersion) {
        if (getExternalizableId()) {
            return run.getExternalizableId();
        }
        return projectVersion;
    }

    /**
     * Validate common required fields
     */
    protected boolean validateCommonFields(TaskListener listener) {
        if (subdomain == null || subdomain.isBlank()) {
            listener.getLogger().println("ERROR: Subdomain is required");
            return false;
        }
        String credentialsId = getApiTokenCredentialsId();
        if (credentialsId == null || credentialsId.isBlank()) {
            listener.getLogger().println("ERROR: API Token credentials ID is required");
            return false;
        }
        if (projectName == null || projectName.isBlank()) {
            listener.getLogger().println("ERROR: Project name is required");
            return false;
        }
        return true;
    }

    /**
     * Log common information
     */
    protected void logCommonInfo(Run<?, ?> run, TaskListener listener, String filePath) {
        listener.getLogger().println("Subdomain: " + subdomain);
        listener.getLogger().println("Project: " + projectName);
        if (filePath != null) {
            listener.getLogger().println("File: " + filePath);
        }

        String parsedVersion = parseVersion(run, projectVersion);
        if (parsedVersion != null && !parsedVersion.isBlank()) {
            listener.getLogger().println("Project version: " + parsedVersion);
        }
    }

    /**
     * Add a successful/structured result (with scan metadata) to the consolidated results action.
     */
    protected void addConsolidatedResult(
            Run<?, ?> run,
            String analysisType,
            String projectName,
            String consoleOutput,
            String status,
            String url,
            String scanIds,
            String scanStatus) {
        FiniteStateConsolidatedResultsAction.getOrCreate(run)
                .addResult(analysisType, projectName, consoleOutput, status, url, scanIds, scanStatus);
    }

    /**
     * Add a minimal result (error/validation paths that have no scan metadata yet).
     */
    protected void addConsolidatedResult(
            Run<?, ?> run, String analysisType, String projectName, String consoleOutput, String status, String url) {
        addConsolidatedResult(run, analysisType, projectName, consoleOutput, status, url, "N/A", status);
    }

    /**
     * Populate the type-specific portion of the scan request (kind + per-analysis fields). The
     * framework fills the common fields (subdomain, token, project, version, polling, etc.).
     */
    protected abstract void configureRequest(FiniteStateScanRequest request);

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

    /**
     * Preferred entry point including environment variables. Marks build as failed on error.
     */
    @Override
    public void perform(Run<?, ?> run, FilePath workspace, EnvVars env, Launcher launcher, TaskListener listener)
            throws InterruptedException, IOException {
        boolean ok = FiniteStateExecutionFramework.executeAnalysis(this, run, workspace, launcher, listener);
        if (!ok) {
            throw new hudson.AbortException("Finite State analysis failed");
        }
    }
}
