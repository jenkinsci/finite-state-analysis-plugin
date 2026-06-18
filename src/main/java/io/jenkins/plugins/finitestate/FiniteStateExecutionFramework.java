package io.jenkins.plugins.finitestate;

import hudson.FilePath;
import hudson.Launcher;
import hudson.model.AbstractBuild;
import hudson.model.BuildListener;
import hudson.model.Run;
import hudson.model.TaskListener;
import java.io.IOException;

/**
 * Execution framework for Finite State analysis operations.
 *
 * <p>Drives the shared flow against the Finite State public v0 API: validate configuration, resolve
 * the API token, compute the target version, locate the workspace file, then run the per-analysis
 * scan flow on the build agent ({@link FiniteStateScanCallable}) and translate the {@link ScanResult}
 * into a Jenkins build outcome. Replaces the previous CLT-jar download-and-exec path.
 */
public class FiniteStateExecutionFramework {

    private FiniteStateExecutionFramework() {
        // Utility class - no instantiation allowed
    }

    /**
     * Execute a Finite State analysis with common error handling and logging.
     *
     * @param recorder Recorder that encapsulates analysis configuration and helpers
     * @param run Jenkins run/build context used for environment and logging
     * @param workspace Workspace directory where files are accessed
     * @param launcher Jenkins launcher (unused since the v0 migration; retained for call-site compatibility)
     * @param listener Build/task listener for console logging
     * @return true when the scan completed successfully (or was accepted, when not waiting); false on failure
     * @throws InterruptedException if execution is interrupted
     * @throws IOException if file I/O fails
     */
    public static boolean executeAnalysis(
            BaseFiniteStateRecorder recorder,
            Run<?, ?> run,
            FilePath workspace,
            Launcher launcher,
            TaskListener listener)
            throws InterruptedException, IOException {

        String analysisType = recorder.getAnalysisType();
        listener.getLogger().println("Starting Finite State " + analysisType + "...");

        // Validate common fields
        if (!recorder.validateCommonFields(listener)) {
            return false;
        }

        String apiToken = recorder.getSecretTextValue(run, recorder.getApiTokenCredentialsId());
        if (apiToken == null) {
            String errorMessage = "ERROR: Could not retrieve API token from credentials";
            listener.getLogger().println(errorMessage);
            recorder.addConsolidatedResult(
                    run,
                    analysisType,
                    recorder.getProjectName(),
                    errorMessage + "\nProject: " + recorder.getProjectName() + "\nCredential ID: "
                            + recorder.getApiTokenCredentialsId(),
                    "ERROR",
                    "N/A");
            return false;
        }

        // Compute the target version (FR-3): externalizable run ID, else projectVersion; fail if both empty.
        String version = recorder.parseVersion(run, recorder.getProjectVersion());
        if (version == null || version.isBlank()) {
            String errorMessage =
                    "ERROR: Project version is required. Enable 'Use externalized ID as version' or set Project Version.";
            listener.getLogger().println(errorMessage);
            recorder.addConsolidatedResult(run, analysisType, recorder.getProjectName(), errorMessage, "ERROR", "N/A");
            return false;
        }

        recorder.logCommonInfo(run, listener, recorder.getFilePathValue());

        // Verify the file exists (FR-9 file-not-found message format preserved from v1).
        FilePath fileObj = recorder.getFileFromWorkspace(workspace, recorder.getFilePathValue(), listener);
        if (fileObj == null || !fileObj.exists()) {
            String errorMessage =
                    "ERROR: " + recorder.getFilePathFieldName() + " not found: " + recorder.getFilePathValue();
            listener.getLogger().println(errorMessage);
            recorder.addConsolidatedResult(
                    run,
                    analysisType,
                    recorder.getProjectName(),
                    errorMessage + "\nProject: " + recorder.getProjectName() + "\n" + recorder.getFilePathFieldName()
                            + ": " + recorder.getFilePathValue(),
                    "ERROR",
                    "N/A");
            return false;
        }

        // Build the request and run the scan flow on the agent that holds the file.
        FiniteStateScanRequest request = buildRequest(recorder, run, version);
        listener.getLogger().println("Executing Finite State " + analysisType + " via the Finite State API...");
        ScanResult result = fileObj.act(new FiniteStateScanCallable(request, listener));

        return handleResult(recorder, run, listener, result);
    }

    /**
     * Backward-compatible shim for freestyle builds using {@link AbstractBuild} API.
     */
    public static boolean executeAnalysis(
            BaseFiniteStateRecorder recorder, AbstractBuild<?, ?> build, Launcher launcher, BuildListener listener)
            throws InterruptedException, IOException {
        FilePath workspace = build.getWorkspace();
        return executeAnalysis(recorder, (Run<?, ?>) build, workspace, launcher, (TaskListener) listener);
    }

    private static FiniteStateScanRequest buildRequest(
            BaseFiniteStateRecorder recorder, Run<?, ?> run, String version) {
        FiniteStateScanRequest request = new FiniteStateScanRequest();
        request.setSubdomain(recorder.getSubdomain());
        request.setApiToken(recorder.getSecretTextValue(run, recorder.getApiTokenCredentialsId()));
        request.setProjectName(recorder.getProjectName());
        request.setVersion(version);
        request.setPreRelease(recorder.getPreRelease());
        request.setWaitForCompletion(recorder.getWaitForCompletion());
        request.setPollTimeoutMinutes(recorder.getPollTimeoutMinutes());
        request.setAnalysisType(recorder.getAnalysisType());
        request.setRelativeFilePath(recorder.getFilePathValue());
        recorder.configureRequest(request);
        return request;
    }

    /**
     * Translate the scan result into a build outcome.
     *
     * <p>success → SUCCESS; completed/queued failures (ERROR/timeout) → FAILURE. Build gating is
     * based on terminal scan status only — reading findings back is out of scope for this release.
     */
    private static boolean handleResult(
            BaseFiniteStateRecorder recorder, Run<?, ?> run, TaskListener listener, ScanResult result) {

        String analysisType = recorder.getAnalysisType();
        String scanUrl = result.getUiUrl() != null ? result.getUiUrl() : "https://" + recorder.getSubdomain();

        if (result.isSuccess()) {
            recorder.addConsolidatedResult(
                    run,
                    analysisType,
                    recorder.getProjectName(),
                    result.getConsoleSummary(),
                    "SUCCESS",
                    scanUrl,
                    result.getScanIdsDisplay(),
                    result.getFinalStatus());
            listener.getLogger().println("✅ Finite State " + analysisType + " completed: " + result.getFinalStatus());
            return true;
        }

        recorder.addConsolidatedResult(
                run,
                analysisType,
                recorder.getProjectName(),
                result.getConsoleSummary(),
                "FAILURE",
                scanUrl,
                result.getScanIdsDisplay(),
                result.getFinalStatus());
        listener.getLogger().println("❌ Finite State " + analysisType + " failed: " + result.getFinalStatus());
        return false;
    }
}
