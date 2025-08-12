package io.jenkins.plugins.finitestate;

import hudson.FilePath;
import hudson.Launcher;
import hudson.model.AbstractBuild;
import hudson.model.BuildListener;
import hudson.model.Run;
import hudson.model.TaskListener;
import java.io.File;
import java.io.IOException;
import java.nio.file.Path;

/**
 * Execution framework for Finite State analysis operations.
 * Provides common logic for executing different types of analysis.
 */
public class FiniteStateExecutionFramework {

    private FiniteStateExecutionFramework() {
        // Utility class - no instantiation allowed
    }

    /**
     * Execute a Finite State analysis with common error handling and logging.
     *
     * @param recorder The recorder instance
     * @param build The build context
     * @param launcher The launcher
     * @param listener The build listener
     * @return true if successful, false otherwise
     */
    public static boolean executeAnalysis(
            BaseFiniteStateRecorder recorder,
            Run<?, ?> run,
            FilePath workspace,
            Launcher launcher,
            TaskListener listener)
            throws InterruptedException, IOException {

        listener.getLogger().println("Starting Finite State " + recorder.getAnalysisType() + "...");

        // Validate common fields
        if (!recorder.validateCommonFields(listener)) {
            return false;
        }

        // Get API token from credentials
        String parsedApiToken = recorder.getSecretTextValue(run, recorder.getApiToken());
        if (parsedApiToken == null) {
            String errorMessage = "ERROR: Could not retrieve API token from credentials";
            listener.getLogger().println(errorMessage);

            // Add error to consolidated results
            String consoleOutput = errorMessage + "\nProject: " + recorder.getProjectName() + "\nCredential ID: "
                    + recorder.getApiToken();
            recorder.addConsolidatedResult(
                    run, recorder.getAnalysisType(), recorder.getProjectName(), consoleOutput, "ERROR", "N/A");

            return false;
        }

        // Parse version
        String parsedVersion = recorder.parseVersion(run, recorder.getProjectVersion());

        // Log common information
        recorder.logCommonInfo(run, listener, recorder.getFilePathValue());

        // Get CLT path
        Path cltPath;
        try {
            cltPath = recorder.getCLTPath(recorder.getSubdomain(), parsedApiToken, listener);
        } catch (IOException e) {
            String errorMessage = "ERROR: Failed to download CLT: " + e.getMessage();
            listener.getLogger().println(errorMessage);

            // Add error to consolidated results
            String consoleOutput = errorMessage + "\nProject: " + recorder.getProjectName() + "\nSubdomain: "
                    + recorder.getSubdomain() + "\nCredential ID: "
                    + recorder.getApiToken();
            recorder.addConsolidatedResult(
                    run, recorder.getAnalysisType(), recorder.getProjectName(), consoleOutput, "ERROR", "N/A");

            return false;
        }

        // Verify file exists
        File fileObj = recorder.getFileFromWorkspace(workspace, recorder.getFilePathValue(), listener);
        if (fileObj == null || !fileObj.exists()) {
            String errorMessage =
                    "ERROR: " + recorder.getFilePathFieldName() + " not found: " + recorder.getFilePathValue();
            listener.getLogger().println(errorMessage);

            // Add error to consolidated results
            String consoleOutput = errorMessage + "\nProject: " + recorder.getProjectName() + "\n"
                    + recorder.getFilePathFieldName() + ": " + recorder.getFilePathValue();
            recorder.addConsolidatedResult(
                    run, recorder.getAnalysisType(), recorder.getProjectName(), consoleOutput, "ERROR", "N/A");

            return false;
        }

        // Execute the analysis
        listener.getLogger().println("Executing Finite State " + recorder.getAnalysisType() + "...");
        int exitCode = recorder.executeAnalysis(
                cltPath, fileObj.getAbsolutePath(), recorder.getProjectName(), parsedVersion, listener);

        return handleExitCode(recorder, run, listener, exitCode, parsedVersion);
    }

    /**
     * Backward-compatible shim for freestyle builds using AbstractBuild API.
     */
    public static boolean executeAnalysis(
            BaseFiniteStateRecorder recorder, AbstractBuild build, Launcher launcher, BuildListener listener)
            throws InterruptedException, IOException {
        FilePath workspace = build.getWorkspace();
        return executeAnalysis(recorder, (Run<?, ?>) build, workspace, launcher, (TaskListener) listener);
    }

    /**
     * Handle the exit code from the analysis execution
     */
    private static boolean handleExitCode(
            BaseFiniteStateRecorder recorder,
            Run<?, ?> run,
            TaskListener listener,
            int exitCode,
            String parsedVersion) {

        String scanUrl = "https://" + recorder.getSubdomain();

        if (exitCode == 0) {
            // Success case
            String consoleOutput = buildSuccessMessage(recorder, parsedVersion, exitCode);
            recorder.addConsolidatedResult(
                    run, recorder.getAnalysisType(), recorder.getProjectName(), consoleOutput, "SUCCESS", scanUrl);

            listener.getLogger().println("✅ Finite State " + recorder.getAnalysisType() + " started successfully!");
            return true;

        } else if (exitCode == 1) {
            // Warning case - vulnerabilities found but scan completed
            String consoleOutput = buildWarningMessage(recorder, parsedVersion, exitCode);
            recorder.addConsolidatedResult(
                    run, recorder.getAnalysisType(), recorder.getProjectName(), consoleOutput, "WARNING", scanUrl);

            listener.getLogger()
                    .println(
                            "⚠️ Finite State " + recorder.getAnalysisType() + " completed with vulnerabilities found.");
            return true;

        } else {
            // Error case
            String consoleOutput = buildErrorMessage(recorder, parsedVersion, exitCode);
            recorder.addConsolidatedResult(
                    run, recorder.getAnalysisType(), recorder.getProjectName(), consoleOutput, "ERROR", "N/A");

            listener.getLogger()
                    .println("❌ Finite State " + recorder.getAnalysisType() + " failed with exit code: " + exitCode);
            return false;
        }
    }

    /**
     * Build success message for consolidated results
     */
    private static String buildSuccessMessage(BaseFiniteStateRecorder recorder, String parsedVersion, int exitCode) {
        return "Finite State " + recorder.getAnalysisType() + " started successfully!\n"
                + recorder.getFilePathFieldName() + ": " + recorder.getFilePathValue() + "\n"
                + "Project Version: " + parsedVersion + "\n"
                + "Exit Code: " + exitCode;
    }

    /**
     * Build warning message for consolidated results
     */
    private static String buildWarningMessage(BaseFiniteStateRecorder recorder, String parsedVersion, int exitCode) {
        return "Finite State " + recorder.getAnalysisType() + " completed with vulnerabilities found.\n"
                + recorder.getFilePathFieldName() + ": " + recorder.getFilePathValue() + "\n"
                + "Project Version: " + parsedVersion + "\n"
                + "Exit Code: " + exitCode;
    }

    /**
     * Build error message for consolidated results
     */
    private static String buildErrorMessage(BaseFiniteStateRecorder recorder, String parsedVersion, int exitCode) {
        return "Finite State " + recorder.getAnalysisType() + " failed with exit code: " + exitCode + "\n"
                + recorder.getFilePathFieldName() + ": " + recorder.getFilePathValue() + "\n"
                + "Project Version: " + parsedVersion + "\n"
                + "Exit Code: " + exitCode;
    }
}
