package org.irmacard.keyshare.common;

public class RecoveryRequest {
    private byte[] redPacket;
    private String delta;
    private String newHashedPin;

    public RecoveryRequest(byte[] redPacket, String delta, String newHashedPin) {
        this.redPacket = redPacket;
        this.delta = delta;
        this.newHashedPin = newHashedPin;
    }

    public String getDelta() {
        return delta;
    }

    public void setDelta(String delta) {
        this.delta = delta;
    }

    public byte[] getRedPacket() {
        return redPacket;
    }

    public void setRedPacket(byte[] redPacket) {
        this.redPacket = redPacket;
    }

    public String getNewHashedPin() {
        return newHashedPin;
    }

    public void setNewHashedPin(String newHashedPin) {
        this.newHashedPin = newHashedPin;
    }
}
