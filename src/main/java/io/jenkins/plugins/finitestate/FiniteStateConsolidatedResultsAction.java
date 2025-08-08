package io.jenkins.plugins.finitestate;

import hudson.model.Run;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import jenkins.model.RunAction2;

public class FiniteStateConsolidatedResultsAction implements RunAction2, Serializable {
    private transient Run build;
    private List<AnalysisResult> results;

    public FiniteStateConsolidatedResultsAction() {
        this.results = new ArrayList<>();
    }

    public void addResult(
            String analysisType, String projectName, String consoleOutput, String status, String scanUrl) {
        results.add(new AnalysisResult(analysisType, projectName, consoleOutput, status, scanUrl));
    }

    public List<AnalysisResult> getResults() {
        return results;
    }

    public boolean hasResults() {
        return !results.isEmpty();
    }

    public static FiniteStateConsolidatedResultsAction getOrCreate(Run<?, ?> build) {
        FiniteStateConsolidatedResultsAction action = build.getAction(FiniteStateConsolidatedResultsAction.class);
        if (action == null) {
            action = new FiniteStateConsolidatedResultsAction();
            build.addAction(action);
        }
        return action;
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

    public static class AnalysisResult implements Serializable {
        private String analysisType;
        private String projectName;
        private String consoleOutput;
        private String status;
        private String scanUrl;

        public AnalysisResult(
                String analysisType, String projectName, String consoleOutput, String status, String scanUrl) {
            this.analysisType = analysisType;
            this.projectName = projectName;
            this.consoleOutput = consoleOutput;
            this.status = status;
            this.scanUrl = scanUrl;
        }

        public String getAnalysisType() {
            return analysisType;
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
    }
}
