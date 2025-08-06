package io.jenkins.plugins.finitestateclt;

import hudson.model.BuildListener;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Utility class for managing the Finite State CLT (Command Line Tool) download and caching.
 * This class provides centralized logic for downloading, caching, and validating the CLT JAR file.
 */
public class CLTManager {

    private static final String CLT_FILENAME = "finitestate-clt.jar";
    private static final String USER_AGENT = "FiniteState-Jenkins-Plugin/1.0";

    /**
     * Private constructor to prevent instantiation of utility class.
     */
    private CLTManager() {
        // Utility class - no instantiation allowed
    }

    /**
     * Get or download the CLT jar file with proper caching and validation.
     *
     * @param cltUrl The URL to download the CLT from
     * @param apiToken The API token for authentication
     * @param listener The build listener for logging
     * @return The path to the CLT JAR file
     * @throws IOException if download fails or file is invalid
     */
    public static Path getOrDownloadCLT(String cltUrl, String apiToken, BuildListener listener) throws IOException {
        Path cltPath = Paths.get(CLT_FILENAME);

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
     * Test if the JAR file is valid and executable
     */
    private static boolean testJarFile(Path jarPath, BuildListener listener) {
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
     * Download the CLT jar file
     */
    private static Path downloadCLT(String url, String apiToken, BuildListener listener) throws IOException {
        Path cltPath = Paths.get(CLT_FILENAME);

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
                try (java.io.BufferedReader reader =
                        new java.io.BufferedReader(new java.io.InputStreamReader(httpConnection.getErrorStream()))) {
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
                    listener.getLogger()
                            .println("Expected PK header, got: "
                                    + String.format("%02X %02X %02X %02X", header[0], header[1], header[2], header[3]));
                }
            }
        }

        // Make the file executable
        cltPath.toFile().setExecutable(true);
        listener.getLogger().println("CLT downloaded successfully to: " + cltPath.toAbsolutePath());

        return cltPath;
    }
}
