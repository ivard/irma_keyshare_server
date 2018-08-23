package org.irmacard.keyshare.common;

public class RecoveryPinInit {

    private String hashedPin;

    public RecoveryPinInit(String hashedPin) {
        this.hashedPin = hashedPin;
    }

    public String getHashedPin() {
        return hashedPin;
    }

    public void setHashedPin(String hashedPin) {
        this.hashedPin = hashedPin;
    }
}
