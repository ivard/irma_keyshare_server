package org.irmacard.keyshare.common;

class TokenMessage {
	private String id;

	public TokenMessage() {
	}

	public TokenMessage(String id) {
		this.id = id;
	}

	public String getID() {
		return id;
	}

	public void setID(String id) {
		this.id = id;
	}
}
