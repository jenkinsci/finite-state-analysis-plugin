package io.jenkins.plugins.finitestate;

import hudson.model.Run;
import jenkins.model.RunAction2;

public class FiniteStateCLTAction implements RunAction2 {
    private transient Run build;
    private String projectName;
    private String consoleOutput; // Add console output storage

    public FiniteStateCLTAction(String projectName) {
        this.projectName = projectName;
    }

    public FiniteStateCLTAction(String projectName, String consoleOutput) {
        this.projectName = projectName;
        this.consoleOutput = consoleOutput;
    }

    public String getProjectName() {
        return projectName;
    }

    public String getConsoleOutput() {
        return consoleOutput;
    }

    public void setConsoleOutput(String consoleOutput) {
        this.consoleOutput = consoleOutput;
    }

    @Override
    public String getIconFileName() {
        return "notepad.png";
    }

    @Override
    public String getDisplayName() {
        return "Finite State Analysis";
    }

    @Override
    public String getUrlName() {
        return "finite_state_analysis";
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
