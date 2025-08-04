package io.jenkins.plugins.finitestateclt;

import hudson.model.Run;
import jenkins.model.RunAction2;

public class FiniteStateCLTAction implements RunAction2 {
    private transient Run build;
    private String projectName;

    public FiniteStateCLTAction(String projectName) {
        this.projectName = projectName;
    }

    public String getProjectName() {
        return projectName;
    }

    @Override
    public String getIconFileName() {
        return null;
    }

    @Override
    public String getDisplayName() {
        return "Finite State CLT Upload";
    }

    @Override
    public String getUrlName() {
        return "finite_state_clt";
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
