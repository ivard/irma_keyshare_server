package org.irmacard.keyshare.common;

public class RecoveryServerKeyResponse {
    private String serverKey;

    public RecoveryServerKeyResponse(String serverKey) {
        this.serverKey = serverKey;
    }

    public String getServerKey() {
        return serverKey;
    }

    public void setServerKey(String serverKey) {
        this.serverKey = serverKey;
    }
}
