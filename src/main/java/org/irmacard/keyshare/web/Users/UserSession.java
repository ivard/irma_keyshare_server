package org.irmacard.keyshare.web.users;

public class UserSession {
	private String username;
	private String sessionToken;

	@SuppressWarnings({"unused", "FieldCanBeLocal"})
	private int userID;

	public UserSession() {};

	public UserSession(String username, String sessionToken, int userID) {
		this.username = username;
		this.sessionToken = sessionToken;
		this.userID = userID;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getSessionToken() {
		return sessionToken;
	}

	public void setSessionToken(String sessionToken) {
		this.sessionToken = sessionToken;
	}

	public int getUserID() {
		return userID;
	}
}
