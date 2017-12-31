package org.irmacard.keyshare.common.exceptions;

import java.io.PrintWriter;
import java.io.StringWriter;

/**
 * An error message for clients of this server, meant for JSON (d)serialization of {@link KeyshareException}s
 * (although it can also hold other {@link Throwable}s).
 */
public class KeyshareErrorMessage {
	private KeyshareError error;
	private int status;
	private String description;
	private String message;
	private String stacktrace;

	/**
	 * Construct a new error message.
	 * @param ex cause of the problem
	 */
	public KeyshareErrorMessage(Throwable ex) {
		if (ex instanceof KeyshareException) {
			this.error = ((KeyshareException) ex).getError();
			this.message = ex.getMessage();
		} else {
			this.error = KeyshareError.EXCEPTION;
			this.message = ex.toString(); // Include exception classname
		}

		this.status = this.error.getStatusCode();
		this.description = this.error.getDescription();
		this.stacktrace = getExceptionStacktrace(ex);
	}

	/** The error that occured. */
	public KeyshareError getError() {
		return error;
	}

	/** The HTTP status. */
	public int getStatus() {
		return status;
	}

	/** Human-readable description of the problem */
	public String getDescription() {
		return description;
	}

	/** The causer or subject of the error; a suggested alternative value;
	 *  or the message of an uncaught exception. */
	public String getMessage() {
		return message;
	}

	/** Stacktrace of the problem */
	public String getStacktrace() {
		return stacktrace;
	}

	public static String getExceptionStacktrace(Throwable ex) {
		StringWriter errorStackTrace = new StringWriter();
		ex.printStackTrace(new PrintWriter(errorStackTrace));
		return errorStackTrace.toString();
	}
}