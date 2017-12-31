package org.irmacard.keyshare.common;

import de.henku.jpaillier.PublicKey;

public class UserLoginMessage {
	private String username;
	private String password;
	private String pin;
	private PublicKey publicKey;

	public UserLoginMessage() {};

	public UserLoginMessage(String username, String password, String pin) {
		this.username = username;
		this.password = password;
		this.pin = pin;
	}

	public UserLoginMessage(String username, String password, String pin, PublicKey publicKey) {
		this.username = username;
		this.password = password;
		this.pin = pin;
		this.publicKey = publicKey;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public void setPin(String pin) {
		this.pin = pin;
	}

	public String getPin() {
		return pin;
	}

	public PublicKey getPublicKey() {
		return publicKey;
	}

	public void setPublicKey(PublicKey publicKey) {
		this.publicKey = publicKey;
	}
}
