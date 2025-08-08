package io.jenkins.plugins.finitestate;

import hudson.model.Run;
import java.io.Serializable;
import jenkins.model.RunAction2;

public class FiniteStateResultsAction implements RunAction2, Serializable {
    private transient Run build;
    private String projectName;
    private String consoleOutput;
    private String status;
    private String scanUrl;

    public FiniteStateResultsAction(String projectName, String consoleOutput, String status, String scanUrl) {
        this.projectName = projectName;
        this.consoleOutput = consoleOutput;
        this.status = status;
        this.scanUrl = scanUrl;
    }

    public String getProjectName() {
        return projectName;
    }

    public String getConsoleOutput() {
        return consoleOutput;
    }

    public String getStatus() {
        return status;
    }

    public String getScanUrl() {
        return scanUrl;
    }

    @Override
    public String getIconFileName() {
        return "clipboard.png";
    }

    @Override
    public String getDisplayName() {
        return "Finite State Results";
    }

    @Override
    public String getUrlName() {
        return "finite_state_results";
    }

    @Override
    public void onAttached(Run<?, ?> build) {
        this.build = build;
    }

    @Override
    public void onLoad(Run<?, ?> build) {
        this.build = build;
    }

    public Run getRun() {
        return build;
    }
}
