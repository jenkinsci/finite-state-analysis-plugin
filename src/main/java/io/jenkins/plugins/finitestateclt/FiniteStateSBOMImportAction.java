package io.jenkins.plugins.finitestateclt;

import hudson.model.Run;
import jenkins.model.RunAction2;

public class FiniteStateSBOMImportAction implements RunAction2 {
    private transient Run build;
    private String projectName;

    public FiniteStateSBOMImportAction(String projectName) {
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
        return "Finite State SBOM Import";
    }

    @Override
    public String getUrlName() {
        return "finite_state_sbom_import";
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
