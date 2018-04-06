package org.irmacard.keyshare.common;

import com.google.api.client.util.DateTime;

public class UserCandidate {
	public UserCandidate(String username, long lastActive) {
		this.username = username;
		this.lastActive = lastActive;
	}
	public String username;
	public long lastActive;
}