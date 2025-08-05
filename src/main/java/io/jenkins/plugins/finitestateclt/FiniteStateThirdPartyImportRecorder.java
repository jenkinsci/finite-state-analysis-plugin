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

public class FiniteStateThirdPartyImportRecorder extends Recorder {

    private String subdomain;
    private String apiToken;
    private String scanFilePath;
    private String projectName;
    private String projectVersion;
    private Boolean externalizableId;
    private String scanType;
    private Boolean preRelease;

    @DataBoundConstructor
    public FiniteStateThirdPartyImportRecorder(
            String subdomain,
            String apiToken,
            String scanFilePath,
            String projectName,
            String projectVersion,
            Boolean externalizableId,
            String scanType,
            Boolean preRelease) {
        this.subdomain = subdomain;
        this.apiToken = apiToken;
        this.scanFilePath = scanFilePath;
        this.projectName = projectName;
        this.projectVersion = projectVersion;
        this.externalizableId = externalizableId;
        this.scanType = scanType;
        this.preRelease = preRelease;
    }

    public String getSubdomain() {
        return subdomain;
    }

    public String getApiToken() {
        return apiToken;
    }

    public String getScanFilePath() {
        return scanFilePath;
    }

    public String getProjectName() {
        return projectName;
    }

    public String getProjectVersion() {
        return projectVersion;
    }

    public boolean getExternalizableId() {
        return externalizableId != null ? externalizableId : true;
    }

    public String getScanType() {
        return scanType;
    }

    public boolean getPreRelease() {
        return preRelease != null ? preRelease : false;
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
    public void setScanFilePath(String scanFilePath) {
        this.scanFilePath = scanFilePath;
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
    public void setExternalizableId(boolean externalizableId) {
        this.externalizableId = externalizableId;
    }

    @DataBoundSetter
    public void setScanType(String scanType) {
        this.scanType = scanType;
    }

    @DataBoundSetter
    public void setPreRelease(boolean preRelease) {
        this.preRelease = preRelease;
    }

    private File getFileFromWorkspace(AbstractBuild build, String relativeFilePath, BuildListener listener) {
        try {
            FilePath workspace = build.getWorkspace();
            if (workspace == null) {
                listener.getLogger().println("ERROR: Workspace is null");
                return null;
            }
            FilePath filePath = workspace.child(relativeFilePath);
            return new File(filePath.getRemote());
        } catch (Exception e) {
            listener.getLogger().println("ERROR: Failed to resolve file path: " + e.getMessage());
            return null;
        }
    }

    public String getSecretTextValue(AbstractBuild build, String credentialId) {
        try {
            StringCredentials credential =
                    CredentialsProvider.findCredentialById(credentialId, StringCredentials.class, build);
            if (credential != null) {
                return credential.getSecret().getPlainText();
            }
        } catch (Exception e) {
            // Log error but continue
        }
        return null;
    }

    private Path getOrDownloadCLT(String cltUrl, String apiToken, BuildListener listener) throws IOException {
        String cltDir = System.getProperty("user.home") + "/.finite-state-clt";
        Path cltPath = Paths.get(cltDir, "finite-state-clt.jar");

        if (!Files.exists(cltPath)) {
            Files.createDirectories(Paths.get(cltDir));
            return downloadCLT(cltUrl, apiToken, listener);
        }

        return cltPath;
    }

    private Path downloadCLT(String url, String apiToken, BuildListener listener) throws IOException {
        try {
            URL cltUrl = new URL(url);
            java.net.HttpURLConnection connection = (java.net.HttpURLConnection) cltUrl.openConnection();
            connection.setRequestProperty("X-Authorization", apiToken);
            connection.setRequestProperty("User-Agent", "FiniteState-Jenkins-Plugin/1.0");

            String cltDir = System.getProperty("user.home") + "/.finite-state-clt";
            Path cltPath = Paths.get(cltDir, "finite-state-clt.jar");

            // Check response code
            int responseCode = connection.getResponseCode();
            listener.getLogger().println("HTTP Response Code: " + responseCode);

            if (responseCode != 200) {
                String errorMessage = "Failed to download CLT. HTTP Response: " + responseCode;
                try (java.io.BufferedReader reader =
                        new java.io.BufferedReader(new java.io.InputStreamReader(connection.getErrorStream()))) {
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

            try (java.io.InputStream in = connection.getInputStream();
                    java.io.OutputStream out = Files.newOutputStream(cltPath)) {
                byte[] buffer = new byte[8192];
                int bytesRead;
                long totalBytes = 0;
                while ((bytesRead = in.read(buffer)) != -1) {
                    out.write(buffer, 0, bytesRead);
                    totalBytes += bytesRead;
                }
                listener.getLogger().println("Downloaded " + totalBytes + " bytes");
            }

            listener.getLogger().println("CLT downloaded successfully to: " + cltPath);
            return cltPath;
        } catch (Exception e) {
            listener.getLogger().println("ERROR: Failed to download CLT: " + e.getMessage());
            throw new IOException("Failed to download CLT", e);
        }
    }

    private int executeThirdPartyImport(
            Path cltPath,
            String scanFile,
            String projectName,
            String projectVersion,
            String scanType,
            boolean preRelease,
            BuildListener listener)
            throws IOException, InterruptedException {

        List<String> command = new ArrayList<>();
        command.add("java");
        command.add("-jar");
        command.add(cltPath.toString());
        command.add("--thirdParty=" + scanType);
        command.add("--name=" + projectName);
        command.add("--version=" + projectVersion);
        command.add(scanFile);

        if (preRelease) {
            command.add("--pre-release");
        }

        listener.getLogger().println("Executing command: " + String.join(" ", command));

        ProcessBuilder pb = new ProcessBuilder(command);
        pb.redirectErrorStream(true);

        Process process = pb.start();

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                listener.getLogger().println(line);
            }
        }

        return process.waitFor();
    }

    @Override
    public boolean perform(AbstractBuild build, Launcher launcher, BuildListener listener)
            throws InterruptedException, IOException {

        listener.getLogger().println("Starting Finite State Third Party Import...");

        // Get API token from credentials
        String parsedApiToken = getSecretTextValue(build, apiToken);
        if (parsedApiToken == null) {
            listener.getLogger().println("ERROR: Invalid API token credential");
            return false;
        }

        // Parse version
        String parsedVersion = projectVersion;
        if (getExternalizableId()) {
            parsedVersion = "build-" + build.getNumber();
        }

        listener.getLogger().println("Subdomain: " + subdomain);
        listener.getLogger().println("Project name: " + projectName);
        listener.getLogger().println("Scan file: " + scanFilePath);
        listener.getLogger().println("Scan type: " + scanType);
        if (parsedVersion != null && !parsedVersion.trim().isEmpty()) {
            listener.getLogger().println("Project version: " + parsedVersion);
        }

        // Check if CLT already exists, download if not
        String cltUrl = "https://" + subdomain + "/api/config/clt";
        Path cltPath = getOrDownloadCLT(cltUrl, parsedApiToken, listener);

        // Verify scan file exists
        File scanFileObj = getFileFromWorkspace(build, scanFilePath, listener);
        if (scanFileObj == null || !scanFileObj.exists()) {
            listener.getLogger().println("ERROR: Scan file not found: " + scanFilePath);
            return false;
        }

        // Execute the third party import
        listener.getLogger().println("Executing Finite State Third Party Import...");
        int exitCode = executeThirdPartyImport(
                cltPath,
                scanFileObj.getAbsolutePath(),
                projectName,
                parsedVersion,
                scanType,
                getPreRelease(),
                listener);

        if (exitCode == 0) {
            build.addAction(new FiniteStateThirdPartyImportAction(projectName));

            // Display link to scan results
            String scanUrl = "https://" + subdomain;
            listener.getLogger().println("✅ Finite State third party import started successfully!");
            listener.getLogger().println("Access your scan results at: " + scanUrl);

            return true;
        } else if (exitCode == 1) {
            build.addAction(new FiniteStateThirdPartyImportAction(projectName));

            // Display link to scan results even when vulnerabilities found
            String scanUrl = "https://" + subdomain;
            listener.getLogger().println("⚠️ Finite State third party import completed with vulnerabilities found.");
            listener.getLogger().println("Access your scan results at: " + scanUrl);

            return true;
        } else {
            // Handle other error codes
            switch (exitCode) {
                case 2:
                    listener.getLogger()
                            .println(
                                    "❌ Failed to connect to FiniteState service. Please check your credentials and subdomain.");
                    break;
                case 100:
                    listener.getLogger().println("❌ Invalid command arguments provided to FiniteState CLT.");
                    break;
                case 101:
                    listener.getLogger().println("❌ Error with command arguments.");
                    break;
                case 200:
                    listener.getLogger().println("❌ Other errors occurred during scan execution.");
                    break;
                default:
                    if (exitCode >= 1000) {
                        listener.getLogger().println("❌ Tool execution error (exit code: " + exitCode + ").");
                    } else {
                        listener.getLogger().println("❌ Third party import failed with exit code: " + exitCode);
                    }
                    break;
            }
            return false;
        }
    }

    @Symbol("finite-state-import-third-party")
    @Extension
    public static final class DescriptorImpl extends BuildStepDescriptor<Publisher> {

        @RequirePOST
        public ListBoxModel doFillApiTokenItems(@AncestorInPath Item item, @QueryParameter String apiToken) {
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
        public FormValidation doCheckScanFilePath(@AncestorInPath Item item, @QueryParameter String value)
                throws IOException, ServletException {
            return checkRequiredValue(item, value);
        }

        @RequirePOST
        public FormValidation doCheckProjectName(@AncestorInPath Item item, @QueryParameter String value)
                throws IOException, ServletException {
            return checkRequiredValue(item, value);
        }

        @RequirePOST
        public FormValidation doCheckScanType(@AncestorInPath Item item, @QueryParameter String value)
                throws IOException, ServletException {
            return checkRequiredValue(item, value);
        }

        @RequirePOST
        public ListBoxModel doFillScanTypeItems() {
            ListBoxModel items = new ListBoxModel();

            // Third-party scanning tools
            items.add("Acunetix360 Scan", "acunetix360_scan");
            items.add("Acunetix Scan", "acunetix_scan");
            items.add("Anchore Engine Scan", "anchore_engine_scan");
            items.add("Anchore Enterprise Policy Check", "anchore_enterprise_policy_check");
            items.add("Anchore Grype", "anchore_grype");
            items.add("AnchoreCTL Policies Report", "anchorectl_policies_report");
            items.add("AnchoreCTL Vuln Report", "anchorectl_vuln_report");
            items.add("AppSpider Scan", "appspider_scan");
            items.add("Aqua Scan", "aqua_scan");
            items.add("Arachni Scan", "arachni_scan");
            items.add("AuditJS Scan", "auditjs_scan");
            items.add("AWS Prowler Scan", "aws_prowler_scan");
            items.add("AWS Prowler V3", "aws_prowler_v3");
            items.add("AWS Scout2 Scan", "aws_scout2_scan");
            items.add("AWS Security Finding Format (ASFF) Scan", "aws_security_finding_format_asff_scan");
            items.add("AWS Security Hub Scan", "aws_security_hub_scan");
            items.add("Azure Security Center Recommendations Scan", "azure_security_center_recommendations_scan");
            items.add("Bandit Scan", "bandit_scan");
            items.add("BlackDuck API", "blackduck_api");
            items.add("Blackduck Component Risk", "blackduck_component_risk");
            items.add("Blackduck Hub Scan", "blackduck_hub_scan");
            items.add("Brakeman Scan", "brakeman_scan");
            items.add("Bugcrowd API Import", "bugcrowd_api_import");
            items.add("BugCrowd Scan", "bugcrowd_scan");
            items.add("Bundler-Audit Scan", "bundler_audit_scan");
            items.add("Burp Enterprise Scan", "burp_enterprise_scan");
            items.add("Burp GraphQL API", "burp_graphql_api");
            items.add("Burp REST API", "burp_rest_api");
            items.add("Burp Scan", "burp_scan");
            items.add("CargoAudit Scan", "cargoaudit_scan");
            items.add("Checkmarx One Scan", "checkmarx_one_scan");
            items.add("Checkmarx OSA", "checkmarx_osa");
            items.add("Checkmarx Scan", "checkmarx_scan");
            items.add("Checkmarx Scan detailed", "checkmarx_scan_detailed");
            items.add("Checkov Scan", "checkov_scan");
            items.add("Clair Klar Scan", "clair_klar_scan");
            items.add("Clair Scan", "clair_scan");
            items.add("Cloudsploit Scan", "cloudsploit_scan");
            items.add("Cobalt.io API Import", "cobalt_io_api_import");
            items.add("Cobalt.io Scan", "cobalt_io_scan");
            items.add("Codechecker Report native", "codechecker_report_native");
            items.add("Contrast Scan", "contrast_scan");
            items.add("Coverity API", "coverity_api");
            items.add("Crashtest Security JSON File", "crashtest_security_json_file");
            items.add("Crashtest Security XML File", "crashtest_security_xml_file");
            items.add("CredScan Scan", "credscan_scan");
            items.add("CycloneDX", "cyclonedx");
            items.add("DawnScanner Scan", "dawnscanner_scan");
            items.add("Dependency Check Scan", "dependency_check_scan");
            items.add(
                    "Dependency Track Finding Packaging Format (FPF) Export",
                    "dependency_track_finding_packaging_format_fpf_export");
            items.add("Detect-secrets Scan", "detect_secrets_scan");
            items.add("docker-bench-security Scan", "docker_bench_security_scan");
            items.add("Dockle Scan", "dockle_scan");
            items.add("DrHeader JSON Importer", "drheader_json_importer");
            items.add("DSOP Scan", "dsop_scan");
            items.add("Edgescan Scan", "edgescan_scan");
            items.add("ESLint Scan", "eslint_scan");
            items.add("Fortify Scan", "fortify_scan");
            items.add("Generic Findings Import", "generic_findings_import");
            items.add("Ggshield Scan", "ggshield_scan");
            items.add("Github Vulnerability Scan", "github_vulnerability_scan");
            items.add("GitLab API Fuzzing Report Scan", "gitlab_api_fuzzing_report_scan");
            items.add("GitLab Container Scan", "gitlab_container_scan");
            items.add("GitLab DAST Report", "gitlab_dast_report");
            items.add("GitLab Dependency Scanning Report", "gitlab_dependency_scanning_report");
            items.add("GitLab SAST Report", "gitlab_sast_report");
            items.add("GitLab Secret Detection Report", "gitlab_secret_detection_report");
            items.add("Gitleaks Scan", "gitleaks_scan");
            items.add("Gosec Scanner", "gosec_scanner");
            items.add("Govulncheck Scanner", "govulncheck_scanner");
            items.add("HackerOne Cases", "hackerone_cases");
            items.add("Hadolint Dockerfile check", "hadolint_dockerfile_check");
            items.add("Harbor Vulnerability Scan", "harbor_vulnerability_scan");
            items.add("Horusec Scan", "horusec_scan");
            items.add("HuskyCI Report", "huskyci_report");
            items.add("Hydra Scan", "hydra_scan");
            items.add("IBM DAST", "ibm_appscan_dast");
            items.add("Immuniweb Scan", "immuniweb_scan");
            items.add("IntSights Report", "intsights_report");
            items.add("JFrog Xray API", "jfrog_xray_api_summary_artifact_scan");
            items.add("JFrog Xray Scan", "jfrog_xray_scan");
            items.add("JFrog Xray Unified Scan", "jfrog_xray_unified_scan");
            items.add("KICS Scan", "kics_scan");
            items.add("Kiuwan Scan", "kiuwan_scan");
            items.add("Kube Bench Scan", "kube_bench_scan");
            items.add("Logic Bomb", "logic_bomb");
            items.add("Meterian Scan", "meterian_scan");
            items.add("Microfocus WebInspect Scan", "microfocus_webinspect_scan");
            items.add("MobSF Scan", "mobsf_scan");
            items.add("Mobsfscan Scan", "mobsfscan_scan");
            items.add("Mozilla Observatory Scan", "mozilla_observatory_scan");
            items.add("Netsparker Scan", "netsparker_scan");
            items.add("NeuVector (compliance)", "neuvector_compliance");
            items.add("NeuVector (REST)", "neuvector_rest");
            items.add("Nexpose Scan", "nexpose_scan");
            items.add("Nikto Scan", "nikto_scan");
            items.add("Nmap Scan", "nmap_scan");
            items.add("Node Security Platform Scan", "node_security_platform_scan");
            items.add("NPM Audit Scan", "npm_audit_scan");
            items.add("Nuclei Scan", "nuclei_scan");
            items.add("Openscap Vulnerability Scan", "openscap_vulnerability_scan");
            items.add("OpenVAS CSV", "openvas_csv");
            items.add("ORT evaluated model Importer", "ort_evaluated_model_importer");
            items.add("OssIndex Devaudit SCA Scan Importer", "ossindex_devaudit_sca_scan_importer");
            items.add("Outpost24 Scan", "outpost24_scan");
            items.add("PHP Security Audit v2", "php_security_audit_v2");
            items.add("PHP Symfony Security Check", "php_symfony_security_check");
            items.add("pip-audit Scan", "pip_audit_scan");
            items.add("PMD Scan", "pmd_scan");
            items.add("Popeye Scan", "popeye_scan");
            items.add("PWN SAST", "pwn_sast");
            items.add("Qualys Infrastructure Scan (WebGUI XML)", "qualys_infrastructure_scan_webgui_xml");
            items.add("Qualys Scan", "qualys_scan");
            items.add("Qualys Webapp Scan", "qualys_webapp_scan");
            items.add("Retire.js Scan", "retire_js_scan");
            items.add("Rubocop Scan", "rubocop_scan");
            items.add("Rusty Hog Scan", "rusty_hog_scan");
            items.add("SARIF", "sarif");
            items.add("Scantist Scan", "scantist_scan");
            items.add("Scout Suite Scan", "scout_suite_scan");
            items.add("Semgrep JSON Report", "semgrep_json_report");
            items.add("SKF Scan", "skf_scan");
            items.add("Snyk Scan", "snyk_scan");
            items.add("Solar Appscreener Scan", "solar_appscreener_scan");
            items.add("SonarQube Cloud Scan", "sonarqube_cloud_scan");
            items.add("SonarQube Scan", "sonarqube_scan");
            items.add("SonarQube Scan detailed", "sonarqube_scan_detailed");
            items.add("Sonatype Application Scan", "sonatype_application_scan");
            items.add("SPDX", "spdx");
            items.add("SpotBugs Scan", "spotbugs_scan");
            items.add("SSL Labs Scan", "ssl_labs_scan");
            items.add("Sslscan", "sslscan");
            items.add("SSLyze Scan (JSON)", "sslyze_scan_json");
            items.add("Sslyze Scan", "sslyze_scan");
            items.add("StackHawk HawkScan", "stackhawk_hawkscan");
            items.add("Talisman Scan", "talisman_scan");
            items.add("Tenable Scan", "tenable_scan");
            items.add("Terrascan Scan", "terrascan_scan");
            items.add("Testssl Scan", "testssl_scan");
            items.add("TFSec Scan", "tfsec_scan");
            items.add("Trivy Operator Scan", "trivy_operator_scan");
            items.add("Trivy Scan", "trivy_scan");
            items.add("Trufflehog3 Scan", "trufflehog3_scan");
            items.add("Trufflehog Scan", "trufflehog_scan");
            items.add("Trustwave Fusion API Scan", "trustwave_fusion_api_scan");
            items.add("Trustwave Scan (CSV)", "trustwave_scan_csv");
            items.add("Twistlock Image Scan", "twistlock_image_scan");
            items.add("VCG Scan", "vcg_scan");
            items.add("Veracode Scan", "veracode_scan");
            items.add("Veracode SourceClear Scan", "veracode_sourceclear_scan");
            items.add("Vulners", "vulners");
            items.add("Wapiti Scan", "wapiti_scan");
            items.add("Wazuh", "wazuh");
            items.add("WFuzz JSON report", "wfuzz_json_report");
            items.add("Whispers Scan", "whispers_scan");
            items.add("WhiteHat Sentinel", "whitehat_sentinel");
            items.add("Whitesource Scan", "whitesource_scan");
            items.add("Wpscan", "wpscan");
            items.add("Xanitizer Scan", "xanitizer_scan");
            items.add("Yarn Audit Scan", "yarn_audit_scan");
            items.add("ZAP Scan", "zap_scan");

            return items;
        }

        @Override
        public boolean isApplicable(Class<? extends AbstractProject> aClass) {
            return true;
        }

        @Override
        public String getDisplayName() {
            return "Finite State Import 3rd Party Scan";
        }
    }
}
