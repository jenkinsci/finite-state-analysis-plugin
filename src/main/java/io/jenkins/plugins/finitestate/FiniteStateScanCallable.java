package io.jenkins.plugins.finitestate;

import hudson.model.TaskListener;
import hudson.remoting.VirtualChannel;
import java.io.File;
import java.io.IOException;
import jenkins.MasterToSlaveFileCallable;

/**
 * Runs a Finite State v0 scan flow on the build <em>agent</em> (the node that holds the workspace
 * file), so large artifacts stream from the node straight to storage rather than transiting the
 * Jenkins controller. Returns a {@link ScanResult}; the controller records it into the build.
 *
 * <p>Expected API failures ({@link FiniteStateApiException}) are caught and turned into a failed
 * {@link ScanResult} (logged verbatim per FR-9) rather than thrown, so the controller can still
 * attach the "Finite State Results" action. Only genuinely unexpected I/O escapes.
 */
class FiniteStateScanCallable extends MasterToSlaveFileCallable<ScanResult> {

    private static final long serialVersionUID = 1L;

    private final FiniteStateScanRequest request;
    private final TaskListener listener;

    FiniteStateScanCallable(FiniteStateScanRequest request, TaskListener listener) {
        this.request = request;
        this.listener = listener;
    }

    @Override
    public ScanResult invoke(File file, VirtualChannel channel) throws IOException, InterruptedException {
        ScanResult result = new ScanResult();
        FiniteStateApiClient client = new FiniteStateApiClient(request.getSubdomain(), request.getApiToken(), listener);
        try {
            switch (request.getKind()) {
                case BINARY:
                    client.runBinary(file, request, result);
                    break;
                case SBOM:
                    client.runSbom(file, request, result);
                    break;
                case THIRD_PARTY:
                    client.runThirdParty(file, request, result);
                    break;
                default:
                    throw new FiniteStateApiException(0, "Unknown analysis kind: " + request.getKind());
            }
            result.setConsoleSummary(buildSummary(result, null));
            logConsole(result, null);
        } catch (FiniteStateApiException e) {
            // FR-9: surface the API's message verbatim; fail the build but keep results attached.
            result.setSuccess(false);
            if (result.getFinalStatus() == null) {
                result.setFinalStatus("ERROR");
            }
            result.setConsoleSummary(buildSummary(result, e.getMessage()));
            logConsole(result, e.getMessage());
        }
        return result;
    }

    /** FR-8: emit project ID, version ID, scan ID(s), UI link, final status, then any error. */
    private void logConsole(ScanResult result, String error) {
        listener.getLogger().println("[Finite State] " + request.getAnalysisType() + " summary:");
        listener.getLogger().println("  Project ID:  " + nvl(result.getProjectId()));
        listener.getLogger().println("  Version ID:  " + nvl(result.getVersionId()));
        listener.getLogger().println("  Scan ID(s):  " + result.getScanIdsDisplay());
        if (result.getUiUrl() != null) {
            listener.getLogger().println("  View in UI:  " + result.getUiUrl());
        }
        listener.getLogger().println("  Status:      " + nvl(result.getFinalStatus()));
        if (error != null) {
            listener.error("[Finite State] " + error);
        }
        if ("TIMEOUT".equals(result.getFinalStatus())) {
            listener.getLogger()
                    .println("[Finite State] Scan did not complete within " + request.getPollTimeoutMinutes()
                            + " minutes. Scan ID(s): " + result.getScanIdsDisplay()
                            + (result.getUiUrl() != null ? ". View status: " + result.getUiUrl() : ""));
        }
    }

    private String buildSummary(ScanResult result, String error) {
        StringBuilder sb = new StringBuilder();
        sb.append(request.getAnalysisType()).append('\n');
        sb.append("Project: ").append(nvl(request.getProjectName())).append('\n');
        sb.append("Version: ").append(nvl(request.getVersion())).append('\n');
        sb.append("Project ID: ").append(nvl(result.getProjectId())).append('\n');
        sb.append("Version ID: ").append(nvl(result.getVersionId())).append('\n');
        sb.append("Scan ID(s): ").append(result.getScanIdsDisplay()).append('\n');
        sb.append("Status: ").append(nvl(result.getFinalStatus()));
        if (error != null) {
            sb.append('\n').append("Error: ").append(error);
        }
        return sb.toString();
    }

    private static String nvl(String s) {
        return (s == null || s.isBlank()) ? "N/A" : s;
    }
}
