package org.irmacard.keyshare.common;

public class RecoveryRequest {
    private byte[] redPacket;
    private String delta;

    public RecoveryRequest(byte[] redPacket, String delta) {
        this.redPacket = redPacket;
        this.delta = delta;
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
}
