package io.jenkins.plugins.finitestate;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/**
 * Outcome of a Finite State v0 scan flow, returned from the agent-side {@link FiniteStateScanCallable}
 * back to the controller. Serializable because it crosses the Jenkins remoting channel.
 *
 * <p>{@code success} drives the Jenkins build result; {@code consoleSummary} is the multi-line
 * summary recorded into the "Finite State Results" build action (FR-8).
 */
public class ScanResult implements Serializable {

    private static final long serialVersionUID = 1L;

    private String projectId;
    private String versionId;
    private final List<String> scanIds = new ArrayList<>();
    private String uiUrl;
    private String finalStatus;
    private String consoleSummary;
    private boolean success;

    public String getProjectId() {
        return projectId;
    }

    public void setProjectId(String projectId) {
        this.projectId = projectId;
    }

    public String getVersionId() {
        return versionId;
    }

    public void setVersionId(String versionId) {
        this.versionId = versionId;
    }

    public List<String> getScanIds() {
        return scanIds;
    }

    public void addScanId(String scanId) {
        if (scanId != null && !scanId.isBlank()) {
            this.scanIds.add(scanId);
        }
    }

    /** Comma-joined scan IDs for display, or "N/A" when none were created. */
    public String getScanIdsDisplay() {
        return scanIds.isEmpty() ? "N/A" : String.join(", ", scanIds);
    }

    public String getUiUrl() {
        return uiUrl;
    }

    public void setUiUrl(String uiUrl) {
        this.uiUrl = uiUrl;
    }

    public String getFinalStatus() {
        return finalStatus;
    }

    public void setFinalStatus(String finalStatus) {
        this.finalStatus = finalStatus;
    }

    public String getConsoleSummary() {
        return consoleSummary;
    }

    public void setConsoleSummary(String consoleSummary) {
        this.consoleSummary = consoleSummary;
    }

    public boolean isSuccess() {
        return success;
    }

    public void setSuccess(boolean success) {
        this.success = success;
    }
}
