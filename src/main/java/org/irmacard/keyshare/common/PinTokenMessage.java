package org.irmacard.keyshare.common;

public class PinTokenMessage extends TokenMessage {
	private String pin;

	public PinTokenMessage() {
		super();
	}

	public PinTokenMessage(String id, String pin) {
		super(id);
		this.pin = pin;
	}

	public void setPin(String pin) {
		this.pin = pin;
	}

	public String getPin() {
		return pin;
	}
}
