package io.jenkins.plugins.finitestateclt;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.StandardCredentials;
import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.AbstractBuild;
import hudson.model.AbstractProject;
import hudson.model.BuildListener;
import hudson.model.Item;
import hudson.security.ACL;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.Publisher;
import hudson.tasks.Recorder;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.servlet.ServletException;
import jenkins.model.Jenkins;
import org.jenkinsci.Symbol;
import org.jenkinsci.plugins.plaincredentials.StringCredentials;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.interceptor.RequirePOST;

public class FiniteStateCLTRecorder extends Recorder {

    private String subdomain;
    private String apiToken;
    private String binaryFilePath;
    private String projectName;
    private String projectVersion;
    private String scanTypes;
    private Boolean externalizableId;

    @DataBoundConstructor
    public FiniteStateCLTRecorder(
            String subdomain,
            String apiToken,
            String binaryFilePath,
            String projectName,
            String projectVersion,
            String scanTypes,
            Boolean externalizableId) {
        this.subdomain = subdomain;
        this.apiToken = apiToken;
        this.binaryFilePath = binaryFilePath;
        this.projectName = projectName;
        this.projectVersion = projectVersion;
        this.scanTypes = scanTypes;
        this.externalizableId = externalizableId;
    }

    public String getSubdomain() {
        return subdomain;
    }

    public String getApiToken() {
        return apiToken;
    }

    public String getBinaryFilePath() {
        return binaryFilePath;
    }

    public String getProjectName() {
        return projectName;
    }

    public String getProjectVersion() {
        return projectVersion;
    }

    public String getScanTypes() {
        return scanTypes;
    }

    public boolean getExternalizableId() {
        return externalizableId != null ? externalizableId : false;
    }

    @DataBoundSetter
    public void setSubdomain(String subdomain) {
        this.subdomain = subdomain;
    }

    @DataBoundSetter
    public void setApiToken(String apiToken) {
        this.apiToken = apiToken;
    }

    @DataBoundSetter
    public void setBinaryFilePath(String binaryFilePath) {
        this.binaryFilePath = binaryFilePath;
    }

    @DataBoundSetter
    public void setProjectName(String projectName) {
        this.projectName = projectName;
    }

    @DataBoundSetter
    public void setProjectVersion(String projectVersion) {
        this.projectVersion = projectVersion;
    }

    @DataBoundSetter
    public void setScanTypes(String scanTypes) {
        this.scanTypes = scanTypes;
    }

    @DataBoundSetter
    public void setExternalizableId(boolean externalizableId) {
        this.externalizableId = externalizableId;
    }

    /**
     * Get file from workspace with proper path resolution
     */
    private File getFileFromWorkspace(AbstractBuild build, String relativeFilePath, BuildListener listener) {
        // Get the workspace directory for the current build
        FilePath workspace = build.getWorkspace();
        if (workspace != null) {
            String workspaceRemote = workspace.getRemote();
            // Construct the absolute path to the file
            File file = new File(workspaceRemote, relativeFilePath);
            listener.getLogger().println("Looking for file at: " + file.getAbsolutePath());
            return file;
        }
        listener.getLogger().println("ERROR: Could not determine workspace path");
        return null;
    }

    /**
     * Get secret values from credentials
     */
    public String getSecretTextValue(AbstractBuild build, String credentialId) {
        StandardCredentials credentials =
                CredentialsProvider.findCredentialById(credentialId, StringCredentials.class, build);

        if (credentials instanceof StringCredentials) {
            StringCredentials stringCredentials = (StringCredentials) credentials;
            return stringCredentials.getSecret().getPlainText();
        }
        return null;
    }

    /**
     * Test if the JAR file is valid and executable
     */
    private boolean testJarFile(Path jarPath, BuildListener listener) {
        try {
            // Test if we can read the JAR file
            try (java.util.jar.JarFile jarFile = new java.util.jar.JarFile(jarPath.toFile())) {
                listener.getLogger().println("JAR file is valid and readable");
                return true;
            }
        } catch (Exception e) {
            listener.getLogger().println("JAR file validation failed: " + e.getMessage());
            return false;
        }
    }

    /**
     * Get or download the CLT jar file (Bamboo-style caching and logging)
     */
    private Path getOrDownloadCLT(String cltUrl, String apiToken, BuildListener listener) throws IOException {
        Path cltPath = Paths.get("finitestate-clt.jar");

        // Check if CLT already exists, is executable, and is valid
        if (cltPath.toFile().exists() && cltPath.toFile().canExecute() && testJarFile(cltPath, listener)) {
            listener.getLogger().println("CLT already exists at: " + cltPath.toAbsolutePath());
            return cltPath;
        }

        // Download the CLT if it doesn't exist
        listener.getLogger().println("CLT not found, downloading from: " + cltUrl);
        return downloadCLT(cltUrl, apiToken, listener);
    }

    /**
     * Download the CLT jar file
     */
    private Path downloadCLT(String url, String apiToken, BuildListener listener) throws IOException {
        Path cltPath = Paths.get("finitestate-clt.jar");

        listener.getLogger().println("Downloading CLT from: " + url);

        // Create URL connection with authentication
        java.net.URLConnection connection = new URL(url).openConnection();
        connection.setRequestProperty("X-Authorization", apiToken);
        connection.setRequestProperty("User-Agent", "FiniteState-Jenkins-Plugin/1.0");

        // Check response code
        if (connection instanceof java.net.HttpURLConnection) {
            java.net.HttpURLConnection httpConnection = (java.net.HttpURLConnection) connection;
            int responseCode = httpConnection.getResponseCode();
            listener.getLogger().println("HTTP Response Code: " + responseCode);
            
            if (responseCode != 200) {
                String errorMessage = "Failed to download CLT. HTTP Response: " + responseCode;
                try (java.io.BufferedReader reader = new java.io.BufferedReader(
                        new java.io.InputStreamReader(httpConnection.getErrorStream()))) {
                    String line;
                    StringBuilder errorResponse = new StringBuilder();
                    while ((line = reader.readLine()) != null) {
                        errorResponse.append(line).append("\n");
                    }
                    if (errorResponse.length() > 0) {
                        errorMessage += "\nError Response: " + errorResponse.toString();
                    }
                }
                throw new IOException(errorMessage);
            }
        }

        // Download the file
        long totalBytes = 0;
        try (java.io.InputStream in = connection.getInputStream();
             java.io.OutputStream out = Files.newOutputStream(cltPath)) {

            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = in.read(buffer)) != -1) {
                out.write(buffer, 0, bytesRead);
                totalBytes += bytesRead;
            }
        }

        // Verify the downloaded file
        if (!cltPath.toFile().exists()) {
            throw new IOException("Downloaded file does not exist");
        }
        
        if (cltPath.toFile().length() == 0) {
            throw new IOException("Downloaded file is empty");
        }

        listener.getLogger().println("Downloaded " + totalBytes + " bytes to: " + cltPath.toAbsolutePath());
        listener.getLogger().println("File size: " + cltPath.toFile().length() + " bytes");

        // Verify it's a valid JAR file by checking the magic number
        try (java.io.FileInputStream fis = new java.io.FileInputStream(cltPath.toFile())) {
            byte[] header = new byte[4];
            if (fis.read(header) == 4) {
                // JAR files start with PK (0x50 0x4B)
                if (header[0] == 0x50 && header[1] == 0x4B) {
                    listener.getLogger().println("JAR file header verified successfully");
                } else {
                    listener.getLogger().println("WARNING: File does not appear to be a valid JAR file");
                    listener.getLogger().println("Expected PK header, got: " + 
                        String.format("%02X %02X %02X %02X", header[0], header[1], header[2], header[3]));
                }
            }
        }

        // Make the file executable
        cltPath.toFile().setExecutable(true);
        listener.getLogger().println("CLT downloaded successfully to: " + cltPath.toAbsolutePath());

        return cltPath;
    }

    /**
     * Execute the CLT command
     */
    private int executeCLT(Path cltPath, String binaryFile, String projectName, String projectVersion,
                          String scanTypes, BuildListener listener) throws IOException, InterruptedException {

        // Build the command
        List<String> command = new ArrayList<>();
        command.add("java");
        command.add("-jar");
        command.add(cltPath.toString());
        command.add("--upload");
        command.add(binaryFile);
        command.add("--name=" + projectName);

        if (projectVersion != null && !projectVersion.trim().isEmpty()) {
            command.add("--version=" + projectVersion);
        }

        if (scanTypes != null && !scanTypes.trim().isEmpty()) {
            command.add("--upload=" + scanTypes);
        }

        listener.getLogger().println("Executing command: " + String.join(" ", command));

        // Execute the process
        ProcessBuilder processBuilder = new ProcessBuilder(command);
        processBuilder.redirectErrorStream(true);

        Process process = processBuilder.start();

        // Read output and look for URL
        String uploadUrl = null;
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                listener.getLogger().println(line);
                // Look for URL in the output
                if (line.contains("https://") && line.contains("finitestate.io")) {
                    uploadUrl = line.trim();
                }
            }
        }

        int exitCode = process.waitFor();
        
        if (exitCode == 0 && uploadUrl != null) {
            listener.getLogger().println("Finite State scan completed successfully");
            listener.getLogger().println("Upload URL: " + uploadUrl);
        } else if (exitCode != 0) {
            listener.getLogger().println("Finite State scan failed with exit code: " + exitCode);
        }

        return exitCode;
    }

    @Override
    public boolean perform(AbstractBuild build, Launcher launcher, BuildListener listener)
            throws InterruptedException, IOException {
        
        listener.getLogger().println("Starting Finite State CLT upload...");

        // Validate required fields
        if (subdomain == null || subdomain.trim().isEmpty()) {
            listener.getLogger().println("ERROR: Subdomain is required");
            return false;
        }
        if (apiToken == null || apiToken.trim().isEmpty()) {
            listener.getLogger().println("ERROR: API Token is required");
            return false;
        }
        if (binaryFilePath == null || binaryFilePath.trim().isEmpty()) {
            listener.getLogger().println("ERROR: Binary file path is required");
            return false;
        }
        if (projectName == null || projectName.trim().isEmpty()) {
            listener.getLogger().println("ERROR: Project name is required");
            return false;
        }

        // Get credentials
        String parsedApiToken = getSecretTextValue(build, apiToken);
        if (parsedApiToken == null) {
            listener.getLogger().println("ERROR: Could not retrieve API token from credentials");
            return false;
        }

        listener.getLogger().println("Subdomain: " + subdomain);
        String parsedVersion = getExternalizableId() ? build.getExternalizableId() : projectVersion;
        listener.getLogger().println("Project: " + projectName);
        listener.getLogger().println("Binary file: " + binaryFilePath);
        if (parsedVersion != null && !parsedVersion.trim().isEmpty()) {
            listener.getLogger().println("Project version: " + parsedVersion);
        }
        if (scanTypes != null && !scanTypes.trim().isEmpty()) {
            listener.getLogger().println("Scan types: " + scanTypes);
        }

        // Check if CLT already exists, download if not
        String cltUrl = "https://" + subdomain + "/api/config/clt";
        Path cltPath = getOrDownloadCLT(cltUrl, parsedApiToken, listener);

        // Verify binary file exists
        File binaryFileObj = getFileFromWorkspace(build, binaryFilePath, listener);
        if (binaryFileObj == null || !binaryFileObj.exists()) {
            listener.getLogger().println("ERROR: Binary file not found: " + binaryFilePath);
            return false;
        }

        // Execute the CLT
        listener.getLogger().println("Executing Finite State CLT...");
        int exitCode = executeCLT(cltPath, binaryFileObj.getAbsolutePath(), projectName, parsedVersion, scanTypes, listener);

        if (exitCode == 0) {
            build.addAction(new FiniteStateCLTAction(projectName));
            return true;
        } else {
            return false;
        }
    }

    @Symbol("finite-state-clt")
    @Extension
    public static final class DescriptorImpl extends BuildStepDescriptor<Publisher> {
        
        @RequirePOST
        public ListBoxModel doFillApiTokenItems(
                @AncestorInPath Item item, @QueryParameter String apiToken) {
            StandardListBoxModel items = new StandardListBoxModel();
            if (item == null) {
                if (!Jenkins.get().hasPermission(Jenkins.ADMINISTER)) {
                    return items.includeCurrentValue(apiToken);
                }
            } else {
                if (!item.hasPermission(Item.EXTENDED_READ) && !item.hasPermission(CredentialsProvider.USE_ITEM)) {
                    return items.includeCurrentValue(apiToken);
                }
            }
            for (StandardCredentials credential : CredentialsProvider.lookupCredentials(
                    StandardCredentials.class, (Item) null, ACL.SYSTEM, Collections.emptyList())) {
                items.add(credential.getId());
            }
            return items;
        }

        private FormValidation checkRequiredValue(Item item, String value) {
            if (item == null
                    || !item.hasPermission(Item.EXTENDED_READ) && !item.hasPermission(CredentialsProvider.USE_ITEM)) {
                return FormValidation.error("You do not have permission to perform this action.");
            }
            if (value == null || value.trim().isEmpty()) {
                return FormValidation.error("This value is required");
            }
            return FormValidation.ok();
        }

        @RequirePOST
        public FormValidation doCheckSubdomain(@AncestorInPath Item item, @QueryParameter String value)
                throws IOException, ServletException {
            return checkRequiredValue(item, value);
        }

        @RequirePOST
        public FormValidation doCheckApiToken(@AncestorInPath Item item, @QueryParameter String value)
                throws IOException, ServletException {
            return checkRequiredValue(item, value);
        }

        @RequirePOST
        public FormValidation doCheckBinaryFilePath(@AncestorInPath Item item, @QueryParameter String value)
                throws IOException, ServletException {
            return checkRequiredValue(item, value);
        }

        @RequirePOST
        public FormValidation doCheckProjectName(@AncestorInPath Item item, @QueryParameter String value)
                throws IOException, ServletException {
            return checkRequiredValue(item, value);
        }

        @Override
        public boolean isApplicable(Class<? extends AbstractProject> aClass) {
            return true;
        }

        @Override
        public String getDisplayName() {
            return "Finite State CLT Upload";
        }
    }
} 