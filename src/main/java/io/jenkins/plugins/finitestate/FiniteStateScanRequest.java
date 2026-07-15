package io.jenkins.plugins.finitestate;

import hudson.util.Secret;
import java.io.Serializable;

/**
 * Serializable bundle of everything the agent-side {@link FiniteStateScanCallable} needs to run a
 * Finite State v0 scan flow. Built on the controller (where credentials and the run's externalizable
 * ID are available) and shipped across the remoting channel to the agent holding the workspace file.
 */
public class FiniteStateScanRequest implements Serializable {

    private static final long serialVersionUID = 1L;

    /** Which of the three operations to run. */
    public enum Kind {
        BINARY,
        SBOM,
        THIRD_PARTY
    }

    // --- Common ---
    private String subdomain;
    // Stored as Secret so the serialized form (shipped to the agent over remoting) is encrypted,
    // never plaintext — see Jenkins Security Scan "Plaintext password storage".
    private Secret apiToken;
    private String projectName;
    private String version;
    private boolean preRelease;
    private boolean waitForCompletion;
    private int pollTimeoutMinutes;
    private String analysisType;
    private String relativeFilePath;
    private Kind kind;

    // --- Binary ---
    private boolean scaEnabled;
    private boolean sastEnabled;
    private boolean configEnabled;
    private boolean reachabilityEnabled;

    // --- Third-party ---
    private String scanType;

    public String getSubdomain() {
        return subdomain;
    }

    public void setSubdomain(String subdomain) {
        this.subdomain = subdomain;
    }

    public Secret getApiToken() {
        return apiToken;
    }

    public void setApiToken(String apiToken) {
        this.apiToken = apiToken == null ? null : Secret.fromString(apiToken);
    }

    public String getProjectName() {
        return projectName;
    }

    public void setProjectName(String projectName) {
        this.projectName = projectName;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public boolean isPreRelease() {
        return preRelease;
    }

    public void setPreRelease(boolean preRelease) {
        this.preRelease = preRelease;
    }

    public boolean isWaitForCompletion() {
        return waitForCompletion;
    }

    public void setWaitForCompletion(boolean waitForCompletion) {
        this.waitForCompletion = waitForCompletion;
    }

    public int getPollTimeoutMinutes() {
        return pollTimeoutMinutes;
    }

    public void setPollTimeoutMinutes(int pollTimeoutMinutes) {
        this.pollTimeoutMinutes = pollTimeoutMinutes;
    }

    public String getAnalysisType() {
        return analysisType;
    }

    public void setAnalysisType(String analysisType) {
        this.analysisType = analysisType;
    }

    public String getRelativeFilePath() {
        return relativeFilePath;
    }

    public void setRelativeFilePath(String relativeFilePath) {
        this.relativeFilePath = relativeFilePath;
    }

    public Kind getKind() {
        return kind;
    }

    public void setKind(Kind kind) {
        this.kind = kind;
    }

    public boolean isScaEnabled() {
        return scaEnabled;
    }

    public void setScaEnabled(boolean scaEnabled) {
        this.scaEnabled = scaEnabled;
    }

    public boolean isSastEnabled() {
        return sastEnabled;
    }

    public void setSastEnabled(boolean sastEnabled) {
        this.sastEnabled = sastEnabled;
    }

    public boolean isConfigEnabled() {
        return configEnabled;
    }

    public void setConfigEnabled(boolean configEnabled) {
        this.configEnabled = configEnabled;
    }

    public boolean isReachabilityEnabled() {
        return reachabilityEnabled;
    }

    public void setReachabilityEnabled(boolean reachabilityEnabled) {
        this.reachabilityEnabled = reachabilityEnabled;
    }

    public String getScanType() {
        return scanType;
    }

    public void setScanType(String scanType) {
        this.scanType = scanType;
    }
}
