package org.irmacard.keyshare.common;

public class PinchangeTokenMessage extends TokenMessage {
	private String oldpin;
	private String newpin;

	public PinchangeTokenMessage() {
		super();
	}

	public PinchangeTokenMessage(String id, String oldpin, String newpin) {
		super(id);
		this.oldpin = oldpin;
		this.newpin = newpin;
	}

	public void setOldpin(String oldpin) {
		this.oldpin = oldpin;
	}

	public String getOldpin() {
		return oldpin;
	}

	public void setNewpin(String newpin) {
		this.newpin = newpin;
	}

	public String getNewpin() {
		return newpin;
	}
}
