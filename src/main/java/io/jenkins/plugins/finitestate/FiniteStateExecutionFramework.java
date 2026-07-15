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
 * <p>Dispatches to one of two transports based on {@link BaseFiniteStateRecorder#isRestApi()}:
 *
 * <ul>
 *   <li><b>2026 platform release</b> — the public v0 REST API flow ({@link #executeViaApi}): resolve
 *       token, compute the target version, locate the workspace file, run the scan on the agent
 *       ({@link FiniteStateScanCallable}) and translate the {@link ScanResult} into a build outcome.
 *   <li><b>Legacy platform</b> (default) — the Java CLT flow ({@link #executeViaClt}): download the
 *       CLT jar and exec it on the agent, mapping the process exit code onto the build outcome.
 * </ul>
 *
 * <p>Keeping both paths lets a single published plugin serve existing legacy-platform jobs unchanged
 * and 2026-platform jobs by flipping the platform selector. See HELIX-422.
 */
public class FiniteStateExecutionFramework {

    private FiniteStateExecutionFramework() {
        // Utility class - no instantiation allowed
    }

    /**
     * Execute a Finite State analysis with common error handling and logging, routing to the 2026
     * platform (v0 API) or legacy platform (CLT) transport based on the recorder's selected platform.
     *
     * @param recorder Recorder that encapsulates analysis configuration and helpers
     * @param run Jenkins run/build context used for environment and logging
     * @param workspace Workspace directory where files (and, for the legacy platform, the CLT) are accessed
     * @param launcher Jenkins launcher (used by the legacy CLT transport to exec the CLT)
     * @param listener Build/task listener for console logging
     * @return true when the analysis succeeded (or was accepted, when not waiting); false on failure
     * @throws InterruptedException if execution is interrupted
     * @throws IOException if file I/O (or CLT download) fails
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

        if (recorder.isRestApi()) {
            listener.getLogger().println("Platform: 2026 Release (REST API)");
            return executeViaApi(recorder, run, workspace, listener, apiToken, analysisType);
        }
        listener.getLogger().println("Platform: Legacy (Java CLT)");
        return executeViaClt(recorder, run, workspace, launcher, listener, apiToken);
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

    // ---------------------------------------------------------------------------------------------
    // 2026 platform transport (public v0 REST API)
    // ---------------------------------------------------------------------------------------------

    private static boolean executeViaApi(
            BaseFiniteStateRecorder recorder,
            Run<?, ?> run,
            FilePath workspace,
            TaskListener listener,
            String apiToken,
            String analysisType)
            throws InterruptedException, IOException {

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
     * Translate the v0 scan result into a build outcome.
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

    // ---------------------------------------------------------------------------------------------
    // Legacy platform transport (Java CLT jar download-and-exec)
    // ---------------------------------------------------------------------------------------------

    private static boolean executeViaClt(
            BaseFiniteStateRecorder recorder,
            Run<?, ?> run,
            FilePath workspace,
            Launcher launcher,
            TaskListener listener,
            String parsedApiToken)
            throws InterruptedException, IOException {

        // Parse version
        String parsedVersion = recorder.parseVersion(run, recorder.getProjectVersion());

        // Log common information
        recorder.logCommonInfo(run, listener, recorder.getFilePathValue());

        // Get CLT path
        FilePath cltPath;
        try {
            cltPath = recorder.getCLTPath(workspace, recorder.getSubdomain(), parsedApiToken, listener);
        } catch (IOException e) {
            String errorMessage = "ERROR: Failed to download CLT: " + e.getMessage();
            listener.getLogger().println(errorMessage);

            String consoleOutput = errorMessage + "\nProject: " + recorder.getProjectName() + "\nSubdomain: "
                    + recorder.getSubdomain() + "\nCredential ID: "
                    + recorder.getApiTokenCredentialsId();
            recorder.addConsolidatedResult(
                    run, recorder.getAnalysisType(), recorder.getProjectName(), consoleOutput, "ERROR", "N/A");

            return false;
        }

        // Verify file exists
        FilePath fileObj = recorder.getFileFromWorkspace(workspace, recorder.getFilePathValue(), listener);
        if (fileObj == null || !fileObj.exists()) {
            String errorMessage =
                    "ERROR: " + recorder.getFilePathFieldName() + " not found: " + recorder.getFilePathValue();
            listener.getLogger().println(errorMessage);

            String consoleOutput = errorMessage + "\nProject: " + recorder.getProjectName() + "\n"
                    + recorder.getFilePathFieldName() + ": " + recorder.getFilePathValue();
            recorder.addConsolidatedResult(
                    run, recorder.getAnalysisType(), recorder.getProjectName(), consoleOutput, "ERROR", "N/A");

            return false;
        }

        // Execute the analysis
        listener.getLogger().println("Executing Finite State " + recorder.getAnalysisType() + "...");
        int exitCode = recorder.executeAnalysis(
                cltPath,
                fileObj,
                recorder.getProjectName(),
                parsedVersion,
                parsedApiToken,
                workspace,
                launcher,
                listener);

        return handleExitCode(recorder, run, listener, exitCode, parsedVersion);
    }

    /**
     * Handle the exit code from the legacy CLT execution.
     *
     * <p>Exit code 0 is treated as success, 1 as a successful run with warnings (vulnerabilities
     * found), and any other code as error.
     */
    private static boolean handleExitCode(
            BaseFiniteStateRecorder recorder,
            Run<?, ?> run,
            TaskListener listener,
            int exitCode,
            String parsedVersion) {

        String scanUrl = "https://" + recorder.getSubdomain();

        if (exitCode == 0) {
            String consoleOutput = buildSuccessMessage(recorder, parsedVersion, exitCode);
            recorder.addConsolidatedResult(
                    run, recorder.getAnalysisType(), recorder.getProjectName(), consoleOutput, "SUCCESS", scanUrl);

            listener.getLogger().println("✅ Finite State " + recorder.getAnalysisType() + " started successfully!");
            return true;

        } else if (exitCode == 1) {
            String consoleOutput = buildWarningMessage(recorder, parsedVersion, exitCode);
            recorder.addConsolidatedResult(
                    run, recorder.getAnalysisType(), recorder.getProjectName(), consoleOutput, "WARNING", scanUrl);

            listener.getLogger()
                    .println(
                            "⚠️ Finite State " + recorder.getAnalysisType() + " completed with vulnerabilities found.");
            return true;

        } else {
            String consoleOutput = buildErrorMessage(recorder, parsedVersion, exitCode);
            recorder.addConsolidatedResult(
                    run, recorder.getAnalysisType(), recorder.getProjectName(), consoleOutput, "ERROR", "N/A");

            listener.getLogger()
                    .println("❌ Finite State " + recorder.getAnalysisType() + " failed with exit code: " + exitCode);
            return false;
        }
    }

    private static String buildSuccessMessage(BaseFiniteStateRecorder recorder, String parsedVersion, int exitCode) {
        return "Finite State " + recorder.getAnalysisType() + " started successfully!\n"
                + recorder.getFilePathFieldName() + ": " + recorder.getFilePathValue() + "\n"
                + "Project Version: " + parsedVersion + "\n"
                + "Exit Code: " + exitCode;
    }

    private static String buildWarningMessage(BaseFiniteStateRecorder recorder, String parsedVersion, int exitCode) {
        return "Finite State " + recorder.getAnalysisType() + " completed with vulnerabilities found.\n"
                + recorder.getFilePathFieldName() + ": " + recorder.getFilePathValue() + "\n"
                + "Project Version: " + parsedVersion + "\n"
                + "Exit Code: " + exitCode;
    }

    private static String buildErrorMessage(BaseFiniteStateRecorder recorder, String parsedVersion, int exitCode) {
        return "Finite State " + recorder.getAnalysisType() + " failed with exit code: " + exitCode + "\n"
                + recorder.getFilePathFieldName() + ": " + recorder.getFilePathValue() + "\n"
                + "Project Version: " + parsedVersion + "\n"
                + "Exit Code: " + exitCode;
    }
}
