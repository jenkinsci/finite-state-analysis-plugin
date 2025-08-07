package io.jenkins.plugins.finitestate;

import hudson.model.Run;
import java.io.Serializable;
import jenkins.model.RunAction2;

public class FiniteStateConsoleAction implements RunAction2, Serializable {
    private transient Run build;
    private String consoleOutput;
    private String title;
    private String iconName;

    public FiniteStateConsoleAction(String title, String consoleOutput) {
        this.title = title;
        this.consoleOutput = consoleOutput;
        this.iconName = "notepad.png";
    }

    public FiniteStateConsoleAction(String title, String consoleOutput, String iconName) {
        this.title = title;
        this.consoleOutput = consoleOutput;
        this.iconName = iconName;
    }

    public String getConsoleOutput() {
        return consoleOutput;
    }

    public void setConsoleOutput(String consoleOutput) {
        this.consoleOutput = consoleOutput;
    }

    public String getTitle() {
        return title;
    }

    @Override
    public String getIconFileName() {
        return iconName;
    }

    @Override
    public String getDisplayName() {
        return title;
    }

    @Override
    public String getUrlName() {
        return "finite_state_console";
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
