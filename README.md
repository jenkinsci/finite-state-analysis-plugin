# [Finite State Analysis](https://finitestate.io) Jenkins Plugin

![Finite state logo](FS-Logo.png)
[finitestate.io](https://finitestate.io)

## Introduction

The Finite State Analysis Jenkins Plugin provides multiple post-build actions for integrating with the Finite State platform using the Finite State CLT (Command Line Tool).

This plugin gives you the ability to add Post Build actions for:

- Freestyle projects
- Multi-configuration projects

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
4. Complete the fields following the below reference. For sensitive fields like `Subdomain` and `API Token`, we use the credentials plugin, so be sure to create the credentials for each of these fields and select the correct ones on each dropdown.

## Post-Build Actions

### 1. Finite State Analyze Binary

Uploads binary files to Finite State for comprehensive analysis.

| parameter | description | required | type | default |
|-----------|-------------|----------|------|---------|
| Subdomain | Your Finite State instance subdomain (e.g., "fs-yolo.dev.fstate.ninja") | `true` | `credential` | |
| API Token | A Secret text credential containing your Finite State API token | `true` | `credential` | |
| Binary File Path | Path to the binary file to upload for analysis | `true` | `string` | |
| Project Name | Name of the project in Finite State | `true` | `string` | |
| Project Version | Version of the project (recommended for tracking) | `false` | `string` | |
| Scan Types | Select from SCA, SAST, and Configuration Analysis | `false` | `multiple` | `SCA` |

### 2. Finite State Import SBOM

Imports SBOM (Software Bill of Materials) files to Finite State for analysis.

| parameter | description | required | type | default |
|-----------|-------------|----------|------|---------|
| Subdomain | Your Finite State instance subdomain | `true` | `credential` | |
| API Token | A Secret text credential containing your Finite State API token | `true` | `credential` | |
| SBOM File Path | Path to the SBOM file to import | `true` | `string` | |
| Project Name | Name of the project in Finite State | `true` | `string` | |
| Project Version | Version of the project | `false` | `string` | |

### 3. Finite State Import 3rd Party Scan

Imports third-party scan results to Finite State for analysis.

| parameter | description | required | type | default |
|-----------|-------------|----------|------|---------|
| Subdomain | Your Finite State instance subdomain | `true` | `credential` | |
| API Token | A Secret text credential containing your Finite State API token | `true` | `credential` | |
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

## Scan Types for Binary Analysis

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

## Requirements

- Jenkins 2.440.3 or later
- Java 8 or later (for running the CLT)
- Internet access to download the CLT from your Finite State instance

## Security

- API tokens are stored securely using Jenkins credentials
- The CLT is downloaded over HTTPS with authentication
- No sensitive data is logged in the build output

## Issues

Report issues and enhancements in the [Github issue tracker](https://github.com/FiniteStateInc/finite-state-jenkins-plugin/issues).

## Contributing

Refer to our [contribution guidelines](https://github.com/jenkinsci/.github/blob/master/CONTRIBUTING.md)

## LICENSE

Licensed under MIT, see [LICENSE](LICENSE.md)

## Developers Guide

Please follow the steps described [**here**](DeveloperGuide.md) 