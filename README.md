# Finite State Jenkins Plugin

This Jenkins plugin provides multiple post-build actions for integrating with the Finite State platform using the Finite State CLT (Command Line Tool).

## Features

- **Finite State Analyze Binary**: Upload and analyze binary files
- **Finite State Import SBOM**: Import SBOM files for analysis
- **Finite State Import 3rd Party Scan**: Import third-party scan results
- Downloads and manages the Finite State CLT automatically
- Secure credential management for API tokens
- Logs upload URLs for easy access to results

## Post-Build Actions

### 1. Finite State Analyze Binary

Uploads binary files to Finite State for comprehensive analysis.

**Required Fields:**
- **Subdomain**: Your Finite State instance subdomain (e.g., "fs-yolo.dev.fstate.ninja")
- **API Token**: A Secret text credential containing your Finite State API token
- **Binary File Path**: Path to the binary file to upload for analysis
- **Project Name**: Name of the project in Finite State

**Optional Fields:**
- **Project Version**: Version of the project (recommended for tracking)
- **Scan Types**: Select from SCA, SAST, and Configuration Analysis

### 2. Finite State Import SBOM

Imports SBOM (Software Bill of Materials) files to Finite State for analysis.

**Required Fields:**
- **Subdomain**: Your Finite State instance subdomain
- **API Token**: A Secret text credential containing your Finite State API token
- **SBOM File Path**: Path to the SBOM file to import
- **Project Name**: Name of the project in Finite State

**Optional Fields:**
- **Project Version**: Version of the project

### 3. Finite State Import 3rd Party Scan

Imports third-party scan results to Finite State for analysis.

**Required Fields:**
- **Subdomain**: Your Finite State instance subdomain
- **API Token**: A Secret text credential containing your Finite State API token
- **Scan File Path**: Path to the scan results file
- **Project Name**: Name of the project in Finite State
- **Scan Type**: Type of third-party scanner (e.g., GitLab SAST, SonarQube, Snyk, etc.)

**Optional Fields:**
- **Project Version**: Version of the project

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