# Finite State CLT Jenkins Plugin

This Jenkins plugin allows you to upload binary files to Finite State for analysis using the Finite State CLT (Command Line Tool).

## Features

- Downloads and manages the Finite State CLT automatically
- Supports uploading binary files for analysis
- Configurable scan types (SCA, SAST, configuration analysis)
- Secure credential management for API tokens
- Logs upload URLs for easy access to results

## Configuration

### Required Fields

- **Subdomain**: Your Finite State instance subdomain (e.g., "fs-yolo.dev.fstate.ninja" for https://fs-yolo.dev.fstate.ninja)
- **API Token**: A Secret text credential containing your Finite State API token
- **Binary File Path**: Path to the binary file to upload for analysis
- **Project Name**: Name of the project in Finite State

### Optional Fields

- **Project Version**: Version of the project (recommended for tracking)
- **Scan Types**: Comma-separated list of scan types (sca, sast, config). Default is "sca"

## Usage

1. Add the "Finite State CLT Upload" post-build action to your Jenkins job
2. Configure the required fields:
   - Enter your Finite State subdomain
   - Select your API token credential
   - Specify the path to your binary file
   - Enter a project name
   - Optionally specify project version and scan types
3. Run the build

The plugin will:
1. Download the CLT if it doesn't exist
2. Upload your binary file for analysis
3. Log the upload URL in the build output
4. Mark the build as successful if the upload completes

## Scan Types

- **sca**: Binary Software Composition Analysis (default)
- **sast**: Binary Static Application Security Testing
- **config**: Configuration analysis

## Example

```
java -jar finitestate-clt.jar --upload myapp.jar --name=myproject --version=1.0.0 --upload=sca,sast
```

## Requirements

- Jenkins 2.440.3 or later
- Java 8 or later (for running the CLT)
- Internet access to download the CLT from your Finite State instance

## Security

- API tokens are stored securely using Jenkins credentials
- The CLT is downloaded over HTTPS with authentication
- No sensitive data is logged in the build output 