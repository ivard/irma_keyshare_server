package org.irmacard.keyshare.common;

public class KeyshareResult {
	String status;
	String message;

	public static final String STATUS_SUCCESS = "success";
	public static final String STATUS_FAILURE = "failure";
	public static final String STATUS_ERROR = "error";

	public KeyshareResult() {
	}

	public KeyshareResult(String status, String message) {
		this.status = status;
		this.message = message;
	}

	public String getStatus() {
		return status;
	}

	public void setstatus(String status) {
		this.status = status;
	}

	public String getMessage() {
		return message;
	}

	public void setMessage(String message) {
		this.message = message;
	}

	public String toString() {
		return "Status: " + status + ", msg: " + message;
	}
}
