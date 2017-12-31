package org.irmacard.keyshare.common;

import java.util.Arrays;
import java.util.List;

public class AuthorizationResult {
	String status;
	List<String> candidates;

	public static final String STATUS_AUTHORIZED = "authorized";
	public static final String STATUS_EXPIRED = "expired";

	public AuthorizationResult() {
	}

	public AuthorizationResult(String status, List<String> candidates) {
		this.status = status;
		this.candidates = candidates;
	}

	public String getStatus() {
		return status;
	}

	public void setStatus(String status) {
		this.status = status;
	}

	public List<String> getCandidates() {
		return candidates;
	}

	public void setCandidates(List<String> candidates) {
		this.candidates = candidates;
	}

	public String toString() {
		String result = "Status: " + status + ", candidates: [";
		if(candidates != null) {
			result += Arrays.toString(candidates.toArray()) + "]";
		} else {
			result += "<<null>>";
		}
		return result;
	}
}
