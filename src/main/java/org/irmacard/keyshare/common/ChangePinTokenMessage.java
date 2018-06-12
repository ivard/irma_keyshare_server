package org.irmacard.keyshare.common;

public class ChangePinTokenMessage extends TokenMessage {
	private String oldPin;
	private String newPin;

	public ChangePinTokenMessage() {
		super();
	}

	public ChangePinTokenMessage(String id, String oldPin, String newPin) {
		super(id);
		this.oldPin = oldPin;
		this.newPin = newPin;
	}

	public void setOldPin(String oldPin) {
		this.oldPin = oldPin;
	}

	public String getOldPin() {
		return oldPin;
	}

	public void setNewPin(String newPin) {
		this.newPin = newPin;
	}

	public String getNewPin() {
		return newPin;
	}
}
