package org.irmacard.keyshare.common;

public class ChangePinTokenMessage extends TokenMessage {
	private String oldpin;
	private String newpin;

	public ChangePinTokenMessage() {
		super();
	}

	public ChangePinTokenMessage(String id, String oldPin, String newPin) {
		super(id);
		this.oldpin = oldPin;
		this.newpin = newPin;
	}

	public void setOldPin(String oldPin) {
		this.oldpin = oldPin;
	}

	public String getOldPin() {
		return oldpin;
	}

	public void setNewPin(String newPin) {
		this.newpin = newPin;
	}

	public String getNewPin() {
		return newpin;
	}
}
