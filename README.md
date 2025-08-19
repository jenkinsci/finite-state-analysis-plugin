# [Finite State Analysis](https://finitestate.io) Jenkins Plugin

![Finite state logo](FS-Logo.png)
[finitestate.io](https://finitestate.io)

## Introduction

The Finite State Analysis Jenkins Plugin provides multiple post-build actions for integrating with the Finite State platform using the Finite State CLT (Command Line Tool).

This plugin gives you the ability to add Post Build actions and Pipeline steps for:

- Freestyle projects
- Multi-configuration projects
- Pipeline (Declarative and Scripted)

## Features

- **Finite State Analyze Binary**: Upload and analyze binary files
- **Finite State Import SBOM**: Import SBOM files for analysis  
- **Finite State Import 3rd Party Scan**: Import third-party scan results
- Downloads and manages the Finite State CLT automatically
- Secure credential management for API tokens
- Logs upload URLs for easy access to results

## Getting started

To use this plugin, follow the following steps:

1. [Install the plugin](https://www.jenkins.io/doc/book/managing/plugins/#installing-a-plugin) in your Jenkins instance.
2. Create or edit your `Freestyle project` or `Multi-configuration project`.
3. Click on the **Add a Post-build Actions** dropdown and select one of the Finite State options:
   - `Finite State - Analyze Binary`
   - `Finite State - Import SBOM`
   - `Finite State - Import 3rd Party Scan`
4. **Generate an API Token**: You need to generate an API token from your Finite State instance. Navigate to your Finite State domain (e.g., if your domain is `fs-yolo.finitestate.io`, go to https://fs-yolo.finitestate.io/settings/api-tokens) and generate a new API token. This token will be used to authenticate with the Finite State platform.
5. Complete the fields following the below reference. For sensitive fields like `API Token`, we use the credentials plugin, so be sure to create the text credential for this field and select the correct one on the dropdown.

## Post-Build Actions

### 1. Finite State Analyze Binary

Uploads binary files to Finite State for comprehensive analysis.

| parameter | description | required | type | default |
|-----------|-------------|----------|------|---------|
| Subdomain | Your Finite State instance subdomain (e.g., "fs-yolo.dev.fstate.ninja") | `true` | `string` | |
| API Token Credentials | A Secret Text credentials ID containing your Finite State API token | `true` | `credential` | |
| Binary File Path | Path to the binary file to upload for analysis | `true` | `string` | |
| Project Name | Name of the project in Finite State | `true` | `string` | |
| Project Version | Version of the project (recommended for tracking) | `false` | `string` | |
| Scan Types | Enable one or more: Binary SCA, Binary SAST, Configuration Analysis. If none are selected, SCA is used by default. | `false` | `checkboxes` | `SCA enabled; SAST/Config disabled` |

### 2. Finite State Import SBOM

Imports SBOM (Software Bill of Materials) files to Finite State for analysis.

| parameter | description | required | type | default |
|-----------|-------------|----------|------|---------|
| Subdomain | Your Finite State instance subdomain | `true` | `string` | |
| API Token Credentials | A Secret Text credentials ID containing your Finite State API token | `true` | `credential` | |
| SBOM File Path | Path to the SBOM file to import | `true` | `string` | |
| Project Name | Name of the project in Finite State | `true` | `string` | |
| Project Version | Version of the project | `false` | `string` | |

### 3. Finite State Import 3rd Party Scan

Imports third-party scan results to Finite State for analysis.

| parameter | description | required | type | default |
|-----------|-------------|----------|------|---------|
| Subdomain | Your Finite State instance subdomain | `true` | `string` | |
| API Token Credentials | A Secret Text credentials ID containing your Finite State API token | `true` | `credential` | |
| Scan File Path | Path to the scan results file | `true` | `string` | |
| Project Name | Name of the project in Finite State | `true` | `string` | |
| Scan Type | Type of third-party scanner (e.g., GitLab SAST, SonarQube, Snyk, etc.) | `true` | `dropdown` | |
| Project Version | Version of the project | `false` | `string` | |

## Usage

1. Add any of the Finite State post-build actions to your Jenkins job
2. Configure the required fields for your chosen action
3. Run the build

The plugin will:
1. Download the CLT if it doesn't exist
2. Execute the appropriate action (upload, import SBOM, or import scan)
3. Log the results in the build output
4. Mark the build as successful if the operation completes

## Jenkins Pipeline usage

You can use these steps directly in Pipelines. The step names are the Jenkins symbols shown below.

### Symbols

- `finiteStateAnalyzeBinary`
- `finiteStateImportSbom`
- `finiteStateImportThirdParty`

### Declarative Pipeline examples

- Analyze Binary

```groovy
pipeline {
  agent any
  stages {
    stage('Finite State Binary Analysis') {
      steps {
        finiteStateAnalyzeBinary(
          subdomain: 'fs-your-subdomain.finitestate.io',
          apiTokenCredentialsId: 'your-jenkins-string-credentials-id',
          binaryFilePath: 'build/firmware.bin',
          projectName: 'My Project',
          projectVersion: '1.2.3',
          scaEnabled: true,
          sastEnabled: false,
          configEnabled: false,
          externalizableId: false,
          preRelease: false
        )
      }
    }
  }
}
```

- Import SBOM

```groovy
pipeline {
  agent any
  stages {
    stage('Finite State Import SBOM') {
      steps {
        finiteStateImportSbom(
          subdomain: 'fs-your-subdomain.finitestate.io',
          apiTokenCredentialsId: 'your-jenkins-string-credentials-id',
          sbomFilePath: 'sbom/cyclonedx.json',
          projectName: 'My Project',
          projectVersion: '1.2.3',
          externalizableId: false,
          preRelease: false
        )
      }
    }
  }
}
```

- Import 3rd Party Scan

```groovy
pipeline {
  agent any
  stages {
    stage('Finite State Import 3rd Party Scan') {
      steps {
        finiteStateImportThirdParty(
          subdomain: 'fs-your-subdomain.finitestate.io',
          apiTokenCredentialsId: 'your-jenkins-string-credentials-id',
          scanFilePath: 'reports/sonarqube.json',
          scanType: 'sonarqube_scan',
          projectName: 'My Project',
          projectVersion: '1.2.3',
          externalizableId: false,
          preRelease: false
        )
      }
    }
  }
}
```

Notes:

- Use `apiTokenCredentialsId` (the ID of a Secret Text credential containing your Finite State API token).

- If you set `externalizableId: true`, the step will use the Jenkins Run Externalizable ID as the project version.

- For the `scanType` field in the `finiteStateImportThirdParty` step, you must select one of the supported scan types from the list in section Third-Party scanType values (exact identifiers) below. The value you provide should match exactly one of the identifiers in the "Third-Party scanType values" table. This ensures your scan is properly recognized and processed by the Finite State platform.


## Scan Types for Binary Analysis

- These options are presented in the UI as three checkboxes: `Binary SCA`, `Binary SAST`, and `Configuration Analysis`.
- At runtime, the plugin builds the CLI flag `--upload` by concatenating the enabled scan types as a comma-separated list (e.g., `--upload=sca,sast`).
- If none are selected, SCA is enforced by default.

- **SCA**: Binary Software Composition Analysis (default)
- **SAST**: Binary Static Application Security Testing
- **Configuration Analysis**: Configuration and security analysis

## Supported Third-Party Scanning Tools

The plugin supports a comprehensive list of third-party scanning tools including:

**Popular Tools:**
- **GitLab SAST/DAST/Container Scan**: GitLab's built-in security scanning
- **SonarQube**: Code quality and security analysis
- **Snyk**: Vulnerability scanning for dependencies and containers
- **Trivy**: Container and infrastructure vulnerability scanner
- **Semgrep**: Static analysis for security and bugs
- **Bandit**: Python security linter
- **Gosec**: Go security linter
- **ESLint**: JavaScript/TypeScript linting with security rules

**Cloud Security:**
- **AWS Prowler**: AWS security assessment
- **AWS Security Hub**: AWS security findings
- **Azure Security Center**: Azure security recommendations
- **Checkov**: Infrastructure as Code security scanning

**Container Security:**
- **Clair**: Container vulnerability scanning
- **Anchore**: Container image analysis
- **Twistlock**: Container security platform

**Dependency Scanning:**
- **Dependency Check**: OWASP dependency vulnerability scanner
- **Retire.js**: JavaScript library vulnerability scanner
- **NPM Audit**: Node.js package vulnerability scanning
- **Yarn Audit**: Yarn package vulnerability scanning

**And many more...** including Acunetix, Burp Suite, Checkmarx, Fortify, Qualys, Tenable, Veracode, ZAP, and over 100 other supported tools.

For the complete list of supported tools and their expected file formats, refer to the dropdown in the Jenkins configuration.

### Third-Party scanType values (exact identifiers)

Use these values for the `scanType` field in Pipelines (e.g., `scanType: 'sonarqube_scan'`). The left column is the UI label; the right column is the exact `scanType` identifier accepted by the step.

| Tool | scanType |
|------|----------|
| Acunetix360 Scan | `acunetix360_scan` |
| Acunetix Scan | `acunetix_scan` |
| Anchore Engine Scan | `anchore_engine_scan` |
| Anchore Enterprise Policy Check | `anchore_enterprise_policy_check` |
| Anchore Grype | `anchore_grype` |
| AnchoreCTL Policies Report | `anchorectl_policies_report` |
| AnchoreCTL Vuln Report | `anchorectl_vuln_report` |
| AppSpider Scan | `appspider_scan` |
| Aqua Scan | `aqua_scan` |
| Arachni Scan | `arachni_scan` |
| AuditJS Scan | `auditjs_scan` |
| AWS Prowler Scan | `aws_prowler_scan` |
| AWS Prowler V3 | `aws_prowler_v3` |
| AWS Scout2 Scan | `aws_scout2_scan` |
| AWS Security Finding Format (ASFF) Scan | `aws_security_finding_format_asff_scan` |
| AWS Security Hub Scan | `aws_security_hub_scan` |
| Azure Security Center Recommendations Scan | `azure_security_center_recommendations_scan` |
| Bandit Scan | `bandit_scan` |
| BlackDuck API | `blackduck_api` |
| Blackduck Component Risk | `blackduck_component_risk` |
| Blackduck Hub Scan | `blackduck_hub_scan` |
| Brakeman Scan | `brakeman_scan` |
| Bugcrowd API Import | `bugcrowd_api_import` |
| BugCrowd Scan | `bugcrowd_scan` |
| Bundler-Audit Scan | `bundler_audit_scan` |
| Burp Enterprise Scan | `burp_enterprise_scan` |
| Burp GraphQL API | `burp_graphql_api` |
| Burp REST API | `burp_rest_api` |
| Burp Scan | `burp_scan` |
| CargoAudit Scan | `cargoaudit_scan` |
| Checkmarx One Scan | `checkmarx_one_scan` |
| Checkmarx OSA | `checkmarx_osa` |
| Checkmarx Scan | `checkmarx_scan` |
| Checkmarx Scan detailed | `checkmarx_scan_detailed` |
| Checkov Scan | `checkov_scan` |
| Clair Klar Scan | `clair_klar_scan` |
| Clair Scan | `clair_scan` |
| Cloudsploit Scan | `cloudsploit_scan` |
| Cobalt.io API Import | `cobalt_io_api_import` |
| Cobalt.io Scan | `cobalt_io_scan` |
| Codechecker Report native | `codechecker_report_native` |
| Contrast Scan | `contrast_scan` |
| Coverity API | `coverity_api` |
| Crashtest Security JSON File | `crashtest_security_json_file` |
| Crashtest Security XML File | `crashtest_security_xml_file` |
| CredScan Scan | `credscan_scan` |
| CycloneDX | `cyclonedx` |
| DawnScanner Scan | `dawnscanner_scan` |
| Dependency Check Scan | `dependency_check_scan` |
| Dependency Track Finding Packaging Format (FPF) Export | `dependency_track_finding_packaging_format_fpf_export` |
| Detect-secrets Scan | `detect_secrets_scan` |
| docker-bench-security Scan | `docker_bench_security_scan` |
| Dockle Scan | `dockle_scan` |
| DrHeader JSON Importer | `drheader_json_importer` |
| DSOP Scan | `dsop_scan` |
| Edgescan Scan | `edgescan_scan` |
| ESLint Scan | `eslint_scan` |
| Fortify Scan | `fortify_scan` |
| Generic Findings Import | `generic_findings_import` |
| Ggshield Scan | `ggshield_scan` |
| Github Vulnerability Scan | `github_vulnerability_scan` |
| GitLab API Fuzzing Report Scan | `gitlab_api_fuzzing_report_scan` |
| GitLab Container Scan | `gitlab_container_scan` |
| GitLab DAST Report | `gitlab_dast_report` |
| GitLab Dependency Scanning Report | `gitlab_dependency_scanning_report` |
| GitLab SAST Report | `gitlab_sast_report` |
| GitLab Secret Detection Report | `gitlab_secret_detection_report` |
| Gitleaks Scan | `gitleaks_scan` |
| Gosec Scanner | `gosec_scanner` |
| Govulncheck Scanner | `govulncheck_scanner` |
| HackerOne Cases | `hackerone_cases` |
| Hadolint Dockerfile check | `hadolint_dockerfile_check` |
| Harbor Vulnerability Scan | `harbor_vulnerability_scan` |
| Horusec Scan | `horusec_scan` |
| HuskyCI Report | `huskyci_report` |
| Hydra Scan | `hydra_scan` |
| IBM DAST | `ibm_appscan_dast` |
| Immuniweb Scan | `immuniweb_scan` |
| IntSights Report | `intsights_report` |
| JFrog Xray API | `jfrog_xray_api_summary_artifact_scan` |
| JFrog Xray Scan | `jfrog_xray_scan` |
| JFrog Xray Unified Scan | `jfrog_xray_unified_scan` |
| KICS Scan | `kics_scan` |
| Kiuwan Scan | `kiuwan_scan` |
| Kube Bench Scan | `kube_bench_scan` |
| Logic Bomb | `logic_bomb` |
| Meterian Scan | `meterian_scan` |
| Microfocus WebInspect Scan | `microfocus_webinspect_scan` |
| MobSF Scan | `mobsf_scan` |
| Mobsfscan Scan | `mobsfscan_scan` |
| Mozilla Observatory Scan | `mozilla_observatory_scan` |
| Netsparker Scan | `netsparker_scan` |
| NeuVector (compliance) | `neuvector_compliance` |
| NeuVector (REST) | `neuvector_rest` |
| Nexpose Scan | `nexpose_scan` |
| Nikto Scan | `nikto_scan` |
| Nmap Scan | `nmap_scan` |
| Node Security Platform Scan | `node_security_platform_scan` |
| NPM Audit Scan | `npm_audit_scan` |
| Nuclei Scan | `nuclei_scan` |
| Openscap Vulnerability Scan | `openscap_vulnerability_scan` |
| OpenVAS CSV | `openvas_csv` |
| ORT evaluated model Importer | `ort_evaluated_model_importer` |
| OssIndex Devaudit SCA Scan Importer | `ossindex_devaudit_sca_scan_importer` |
| Outpost24 Scan | `outpost24_scan` |
| PHP Security Audit v2 | `php_security_audit_v2` |
| PHP Symfony Security Check | `php_symfony_security_check` |
| pip-audit Scan | `pip_audit_scan` |
| PMD Scan | `pmd_scan` |
| Popeye Scan | `popeye_scan` |
| PWN SAST | `pwn_sast` |
| Qualys Infrastructure Scan (WebGUI XML) | `qualys_infrastructure_scan_webgui_xml` |
| Qualys Scan | `qualys_scan` |
| Qualys Webapp Scan | `qualys_webapp_scan` |
| Retire.js Scan | `retire_js_scan` |
| Rubocop Scan | `rubocop_scan` |
| Rusty Hog Scan | `rusty_hog_scan` |
| SARIF | `sarif` |
| Scantist Scan | `scantist_scan` |
| Scout Suite Scan | `scout_suite_scan` |
| Semgrep JSON Report | `semgrep_json_report` |
| SKF Scan | `skf_scan` |
| Snyk Scan | `snyk_scan` |
| Solar Appscreener Scan | `solar_appscreener_scan` |
| SonarQube Cloud Scan | `sonarqube_cloud_scan` |
| SonarQube Scan | `sonarqube_scan` |
| SonarQube Scan detailed | `sonarqube_scan_detailed` |
| Sonatype Application Scan | `sonatype_application_scan` |
| SPDX | `spdx` |
| SpotBugs Scan | `spotbugs_scan` |
| SSL Labs Scan | `ssl_labs_scan` |
| Sslscan | `sslscan` |
| SSLyze Scan (JSON) | `sslyze_scan_json` |
| Sslyze Scan | `sslyze_scan` |
| StackHawk HawkScan | `stackhawk_hawkscan` |
| Talisman Scan | `talisman_scan` |
| Tenable Scan | `tenable_scan` |
| Terrascan Scan | `terrascan_scan` |
| Testssl Scan | `testssl_scan` |
| TFSec Scan | `tfsec_scan` |
| Trivy Operator Scan | `trivy_operator_scan` |
| Trivy Scan | `trivy_scan` |
| Trufflehog3 Scan | `trufflehog3_scan` |
| Trufflehog Scan | `trufflehog_scan` |
| Trustwave Fusion API Scan | `trustwave_fusion_api_scan` |
| Trustwave Scan (CSV) | `trustwave_scan_csv` |
| Twistlock Image Scan | `twistlock_image_scan` |
| VCG Scan | `vcg_scan` |
| Veracode Scan | `veracode_scan` |
| Veracode SourceClear Scan | `veracode_sourceclear_scan` |
| Vulners | `vulners` |
| Wapiti Scan | `wapiti_scan` |
| Wazuh | `wazuh` |
| WFuzz JSON report | `wfuzz_json_report` |
| Whispers Scan | `whispers_scan` |
| WhiteHat Sentinel | `whitehat_sentinel` |
| Whitesource Scan | `whitesource_scan` |
| Wpscan | `wpscan` |
| Xanitizer Scan | `xanitizer_scan` |
| Yarn Audit Scan | `yarn_audit_scan` |
| ZAP Scan | `zap_scan` |

## Requirements

- Jenkins 2.479.3 or later
- Java 8 or later (for running the CLT)
- Internet access to download the CLT from your Finite State instance

## Security

- API tokens are stored securely using Jenkins credentials
- The CLT is downloaded over HTTPS with authentication
- No sensitive data is logged in the build output

## Issues

Report issues and enhancements in the [Github issue tracker](https://github.com/jenkinsci/finite-state-jenkins-plugin/issues).

## Contributing

Refer to our [contribution guidelines](https://github.com/jenkinsci/.github/blob/master/CONTRIBUTING.md)

## LICENSE

Licensed under MIT, see [LICENSE](LICENSE.md)

## Developers Guide

Please follow the steps described in the [Developer Guide](DeveloperGuide.md)

