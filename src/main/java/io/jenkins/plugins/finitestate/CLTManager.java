package io.jenkins.plugins.finitestate;

import hudson.FilePath;
import hudson.model.TaskListener;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;

/**
 * Utility class for managing the Finite State CLT (Command Line Tool) download and caching.
 * This class provides centralized logic for downloading, caching, and validating the CLT JAR file.
 */
public class CLTManager {

    private static final String CLT_FILENAME_PREFIX = "finitestate-clt";
    private static final String CLT_FILENAME_SUFFIX = ".jar";
    private static final String USER_AGENT = "FiniteState-Jenkins-Plugin/1.0";

    /**
     * Private constructor to prevent instantiation of utility class.
     */
    private CLTManager() {
        // Utility class - no instantiation allowed
    }

    /**
     * Get the CLT filename for a specific subdomain
     *
     * @param subdomain The subdomain to generate filename for
     * @return The subdomain-specific CLT filename
     */
    private static String getCLTFilename(String subdomain) {
        return CLT_FILENAME_PREFIX + "-" + subdomain + CLT_FILENAME_SUFFIX;
    }

    /**
     * Get or download the CLT jar file with proper caching and validation.
     *
     * @param cltUrl The URL to download the CLT from
     * @param apiToken The API token for authentication
     * @param subdomain The subdomain for filename generation
     * @param listener The build listener for logging
     * @return The path to the CLT JAR file
     * @throws IOException if download fails or file is invalid
     */
    public static FilePath getOrDownloadCLT(
            String cltUrl, String apiToken, String subdomain, FilePath workspace, TaskListener listener)
            throws IOException, InterruptedException {
        String filename = getCLTFilename(subdomain);
        FilePath cltPath = workspace.child(filename);

        // Check if CLT already exists on the node
        if (cltPath.exists() && cltPath.length() > 0) {
            listener.getLogger().println("CLT already exists at: " + cltPath.getRemote());
            return cltPath;
        }

        // Download the CLT if it doesn't exist
        listener.getLogger().println("CLT not found, downloading from: " + cltUrl);
        return downloadCLT(cltUrl, apiToken, subdomain, cltPath, listener);
    }

    /**
     * Test if the JAR file is valid and executable
     */
    private static boolean testJarFile(FilePath jarPath, TaskListener listener)
            throws IOException, InterruptedException {
        try (java.io.InputStream is = jarPath.read()) {
            byte[] header = new byte[4];
            int read = is.read(header);
            boolean looksLikeZip = read == 4 && header[0] == 0x50 && header[1] == 0x4B;
            if (looksLikeZip) {
                listener.getLogger().println("JAR file header verified successfully");
            } else {
                listener.getLogger().println("WARNING: File does not appear to be a valid JAR file");
            }
            return looksLikeZip;
        }
    }

    /**
     * Download the CLT jar file
     */
    private static FilePath downloadCLT(
            String url, String apiToken, String subdomain, FilePath cltPath, TaskListener listener)
            throws IOException, InterruptedException {
        listener.getLogger().println("Downloading CLT from: " + url);

        // Create URL connection with authentication
        java.net.URLConnection connection = new URL(url).openConnection();
        connection.setRequestProperty("X-Authorization", apiToken);
        connection.setRequestProperty("User-Agent", USER_AGENT);

        // Check response code
        if (connection instanceof java.net.HttpURLConnection) {
            java.net.HttpURLConnection httpConnection = (java.net.HttpURLConnection) connection;
            int responseCode = httpConnection.getResponseCode();
            listener.getLogger().println("HTTP Response Code: " + responseCode);

            if (responseCode != 200) {
                String errorMessage = "Failed to download CLT. HTTP Response: " + responseCode;

                // Add specific error messages for common HTTP status codes
                if (responseCode == 401) {
                    errorMessage =
                            "Authentication failed (HTTP 401). Please check your API token and ensure it is valid for the specified subdomain.";
                } else if (responseCode == 403) {
                    errorMessage = "Access denied (HTTP 403). Please check your API token permissions.";
                } else if (responseCode == 404) {
                    errorMessage = "CLT not found (HTTP 404). Please check the subdomain configuration.";
                } else if (responseCode >= 500) {
                    errorMessage =
                            "Server error (HTTP " + responseCode + "). Please try again later or contact support.";
                }

                // Try to read error response if available
                try {
                    java.io.InputStream errorStream = httpConnection.getErrorStream();
                    if (errorStream != null) {
                        try (java.io.BufferedReader reader = new java.io.BufferedReader(
                                new java.io.InputStreamReader(errorStream, StandardCharsets.UTF_8))) {
                            String line;
                            StringBuilder errorResponse = new StringBuilder();
                            while ((line = reader.readLine()) != null) {
                                errorResponse.append(line).append("\n");
                            }
                            if (errorResponse.length() > 0) {
                                errorMessage += "\nError Response: " + errorResponse.toString();
                            }
                        }
                    }
                } catch (Exception e) {
                    // If we can't read the error stream, just log it and continue
                    listener.getLogger().println("Warning: Could not read error response details: " + e.getMessage());
                }

                throw new IOException(errorMessage);
            }
        }

        // Download the file
        long totalBytes = 0;
        try (java.io.InputStream in = connection.getInputStream();
                java.io.OutputStream out = cltPath.write()) {
            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = in.read(buffer)) != -1) {
                out.write(buffer, 0, bytesRead);
                totalBytes += bytesRead;
            }
        }

        // Verify the downloaded file
        if (!cltPath.exists()) {
            throw new IOException("Downloaded file does not exist");
        }

        if (cltPath.length() == 0) {
            throw new IOException("Downloaded file is empty");
        }

        listener.getLogger().println("Downloaded " + totalBytes + " bytes to: " + cltPath.getRemote());
        listener.getLogger().println("File size: " + cltPath.length() + " bytes");

        // Verify it's a valid JAR file by checking the magic number
        testJarFile(cltPath, listener);

        try {
            cltPath.chmod(0755);
        } catch (Exception ignore) {
            // best effort; may fail on non-POSIX filesystems
        }
        listener.getLogger().println("CLT downloaded successfully to: " + cltPath.getRemote());

        return cltPath;
    }
}
