package io.jenkins.plugins.finitestate;

/**
 * Raised when a Finite State v0 API call fails (non-2xx response, or exhausted retries on a
 * transient failure). Carries the HTTP status (0 for network-level failures) and a message that
 * already includes the API's error body and a human-readable hint where available, so callers can
 * surface it verbatim to the build log (FR-9).
 */
public class FiniteStateApiException extends Exception {

    private static final long serialVersionUID = 1L;

    private final int statusCode;

    public FiniteStateApiException(int statusCode, String message) {
        super(message);
        this.statusCode = statusCode;
    }

    public FiniteStateApiException(int statusCode, String message, Throwable cause) {
        super(message, cause);
        this.statusCode = statusCode;
    }

    /** HTTP status code, or 0 when the failure was network-level (no response received). */
    public int getStatusCode() {
        return statusCode;
    }
}
