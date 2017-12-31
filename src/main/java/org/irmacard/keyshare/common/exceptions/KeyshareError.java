package org.irmacard.keyshare.common.exceptions;

/**
 * Errors that can occur in usage of the API, along with their HTTP status code
 * and human-readable descriptions. For use in {@link KeyshareErrorMessage} and {@link KeyshareException}.
 */
public enum KeyshareError {
	// IdP-specific errors
	// MALFORMED_ISSUER_REQUEST(400, "Malformed issuer request"),

	// SP-specific errors
	MALFORMED_VERIFIER_REQUEST(400, "Malformed verification request"),

	// SP, IdP, or token errors
	MALFORMED_INPUT(400, "Input could not be parsed"),

	// Token errors
	UNEXPECTED_REQUEST(403, "Unexpected request in this state"),
	UNKNOWN_PUBLIC_KEY(403, "Attributes were not valid against a known public key"),
	USER_BLOCKED(403, "User is blocked"),
	USER_NOT_REGISTERED(403, "User is not yet fully registered"),
	UNAUTHORIZED(403, "Unauthorized, authenticate to the server first"),
	USERNAME_UNAVAILABLE(409, "E-mailaddress unavailable"),

	// webclient related exceptions
	USER_NOT_FOUND(404, "Cannot find user"),
	USER_SESSION_INVALID(401, "Session expired"),

	// Any other exception
	EXCEPTION(500, "Encountered unexpected problem");


	private int statusCode;
	private String description;

	KeyshareError(int statusCode, String description) {
		this.statusCode = statusCode;
		this.description = description;
	}

	public int getStatusCode() {
		return statusCode;
	}

	public String getDescription() {
		return description;
	}
}
