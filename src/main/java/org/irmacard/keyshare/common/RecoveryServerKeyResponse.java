package org.irmacard.keyshare.common;

public class RecoveryServerKeyResponse {
    private byte[] serverKey;

    public RecoveryServerKeyResponse(byte[] serverKey) {
        this.serverKey = serverKey;
    }

    public byte[] getServerKey() {
        return serverKey;
    }

    public void setServerKey(byte[] serverKey) {
        this.serverKey = serverKey;
    }
}
