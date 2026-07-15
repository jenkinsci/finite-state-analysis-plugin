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
 * <p>The plugin supports two transports, selected per build step via {@link #getPlatform()}:
 *
 * <ul>
 *   <li><b>{@value #PLATFORM_LEGACY}</b> (default) — the legacy platform: download and exec the Java
 *       CLT jar. Kept so existing jobs keep working unchanged after upgrading the plugin.
 *   <li><b>{@value #PLATFORM_2026}</b> — the 2026 platform release: direct calls to the public v0
 *       REST API, described via {@link #configureRequest(FiniteStateScanRequest)}.
 * </ul>
 *
 * <p>{@link FiniteStateExecutionFramework} inspects the selected platform and drives the matching
 * flow. The default is the legacy platform so that a job saved before this field existed (no
 * {@code platform} in its persisted XML) deserializes to the legacy behavior — an upgrade never
 * silently retargets a job at the 2026 REST API. See HELIX-422.
 */
public abstract class BaseFiniteStateRecorder extends Recorder implements SimpleBuildStep {

    /** Default poll timeout (minutes) when waiting for scan completion (FR-7). */
    public static final int DEFAULT_POLL_TIMEOUT_MINUTES = 30;

    /** Legacy platform transport (Java CLT jar download-and-exec). Default for backward compatibility. */
    public static final String PLATFORM_LEGACY = "legacy";

    /** 2026 platform release transport (direct public v0 REST API). */
    public static final String PLATFORM_2026 = "2026";

    protected String subdomain;
    // Explicit name indicating this is a Jenkins Credentials ID (Secret Text) holding the API token.
    protected String apiTokenCredentialsId;
    protected String projectName;
    protected String projectVersion;
    protected Boolean externalizableId;
    protected Boolean preRelease;
    protected Boolean waitForCompletion;
    protected Integer pollTimeoutMinutes;
    // Which platform/transport to use. Null (absent from persisted config) => legacy CLT path.
    protected String platform;

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
        // Default false: submit the scan and return (the CLT-style flow) so the build doesn't block;
        // the user follows progress in the Finite State UI. Enable to block on terminal status.
        return waitForCompletion != null ? waitForCompletion : false;
    }

    public int getPollTimeoutMinutes() {
        return pollTimeoutMinutes != null && pollTimeoutMinutes > 0 ? pollTimeoutMinutes : DEFAULT_POLL_TIMEOUT_MINUTES;
    }

    /**
     * Selected transport. Defaults to {@link #PLATFORM_LEGACY} when unset (including jobs whose
     * persisted config predates this field), so upgrading the plugin never changes an existing
     * job's behavior.
     */
    public String getPlatform() {
        return platform != null && !platform.isBlank() ? platform : PLATFORM_LEGACY;
    }

    /** True when this step targets the 2026 platform's public v0 REST API instead of the legacy CLT. */
    public boolean isRestApi() {
        return PLATFORM_2026.equalsIgnoreCase(getPlatform());
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

    @DataBoundSetter
    public void setPlatform(String platform) {
        this.platform = platform;
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
     * Get CLT path using the shared CLTManager (legacy platform transport only).
     */
    protected FilePath getCLTPath(FilePath workspace, String subdomain, String apiToken, TaskListener listener)
            throws IOException, InterruptedException {
        String cltUrl = "https://" + subdomain + "/api/config/clt";
        return CLTManager.getOrDownloadCLT(cltUrl, apiToken, subdomain, workspace, listener);
    }

    /**
     * Build the environment variables required by the CLT for authentication and domain routing
     * (legacy platform transport only).
     */
    protected String[] buildCLTEnvironment(String apiToken) {
        return new String[] {
            "FINITE_STATE_AUTH_TOKEN=" + apiToken, "FINITE_STATE_DOMAIN=" + subdomain,
        };
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
     * Populate the type-specific portion of the scan request (kind + per-analysis fields), used by
     * the 2026 platform's v0 REST transport. The framework fills the common fields (subdomain, token, project,
     * version, polling, etc.).
     */
    protected abstract void configureRequest(FiniteStateScanRequest request);

    /**
     * Execute the analysis via the legacy platform's CLT transport. Invoked by
     * {@link FiniteStateExecutionFramework} only when {@link #isRestApi()} is {@code false}.
     *
     * @return CLT process exit code (0 = success, 1 = completed with findings, other = error)
     */
    protected abstract int executeAnalysis(
            FilePath cltPath,
            FilePath filePath,
            String projectName,
            String projectVersion,
            String apiToken,
            FilePath workspace,
            Launcher launcher,
            TaskListener listener)
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
