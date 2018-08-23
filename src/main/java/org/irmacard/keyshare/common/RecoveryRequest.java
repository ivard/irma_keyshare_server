package org.irmacard.keyshare.common;

public class RecoveryRequest {
    private byte[] redPacket;
    private byte[] delta;

    public RecoveryRequest(byte[] redPacket, byte[] delta) {
        this.redPacket = redPacket;
        this.delta = delta;
    }

    public byte[] getDelta() {

        return delta;
    }

    public void setDelta(byte[] delta) {
        this.delta = delta;
    }

    public byte[] getRedPacket() {

        return redPacket;
    }

    public void setRedPacket(byte[] redPacket) {
        this.redPacket = redPacket;
    }
}
