package io.jenkins.plugins.finitestate;

import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import hudson.model.Item;
import hudson.security.ACL;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.Publisher;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import java.io.IOException;
import java.util.Collections;
import javax.servlet.ServletException;
import jenkins.model.Jenkins;
import org.jenkinsci.plugins.plaincredentials.StringCredentials;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.interceptor.RequirePOST;

/**
 * Abstract base descriptor class for all Finite State recorders.
 * Contains common descriptor functionality shared across different analysis types.
 */
public abstract class BaseFiniteStateDescriptor extends BuildStepDescriptor<Publisher> {

    protected BaseFiniteStateDescriptor() {
        super();
    }

    /**
     * Common method to fill API token items from credentials
     */
    @RequirePOST
    public ListBoxModel doFillApiTokenItems(@AncestorInPath Item item, @QueryParameter String apiToken) {
        StandardListBoxModel result = new StandardListBoxModel();
        if (item == null) {
            if (!Jenkins.get().hasPermission(Jenkins.ADMINISTER)) {
                return result.includeCurrentValue(apiToken);
            }
        } else {
            if (!item.hasPermission(Item.CONFIGURE)) {
                return result.includeCurrentValue(apiToken);
            }
        }

        result.add("", "Select API Token");
        result.includeAs(ACL.SYSTEM, item, StringCredentials.class, Collections.emptyList());
        return result.includeCurrentValue(apiToken);
    }

    /**
     * Common validation helper for required values
     */
    protected FormValidation checkRequiredValue(Item item, String value) {
        if (value == null || value.trim().isEmpty()) {
            return FormValidation.error("This field is required");
        }
        return FormValidation.ok();
    }

    /**
     * Common subdomain validation
     */
    @RequirePOST
    public FormValidation doCheckSubdomain(@AncestorInPath Item item, @QueryParameter String value)
            throws IOException, ServletException {
        return checkRequiredValue(item, value);
    }

    /**
     * Common API token validation
     */
    @RequirePOST
    public FormValidation doCheckApiToken(@AncestorInPath Item item, @QueryParameter String value)
            throws IOException, ServletException {
        return checkRequiredValue(item, value);
    }

    /**
     * Common project name validation
     */
    @RequirePOST
    public FormValidation doCheckProjectName(@AncestorInPath Item item, @QueryParameter String value)
            throws IOException, ServletException {
        return checkRequiredValue(item, value);
    }

    /**
     * Common applicability check
     */
    @Override
    public boolean isApplicable(Class<? extends hudson.model.AbstractProject> aClass) {
        return true;
    }
}
