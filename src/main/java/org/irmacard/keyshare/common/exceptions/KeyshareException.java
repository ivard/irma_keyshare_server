package org.irmacard.keyshare.common.exceptions;

/**
 * Exception occuring during usage of the API. Mainly a wrapper around an {@link ApiError}.
 */
public class KeyshareException extends RuntimeException {
	private static final long serialVersionUID = 5763289075477918475L;

	private KeyshareError error;

	public KeyshareException(KeyshareError error) {
		this.error = error;
	}

	public KeyshareException(KeyshareError error, String message) {
		super(message);
		this.error = error;
	}

	public KeyshareError getError() {
		return error;
	}
}
