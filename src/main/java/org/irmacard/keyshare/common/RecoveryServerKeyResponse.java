package org.irmacard.keyshare.common;

public class RecoveryServerKeyResponse {
    private String serverKey;
    private String serverDelta;

    public RecoveryServerKeyResponse(String serverKey, String serverDelta) {
        this.serverKey = serverKey;
        this.serverDelta = serverDelta;
    }

    public String getServerKey() {
        return serverKey;
    }

    public void setServerKey(String serverKey) {
        this.serverKey = serverKey;
    }

    public String getServerDelta() {
        return serverDelta;
    }

    public void setServerDelta(String serverDelta) {
        this.serverDelta = serverDelta;
    }
}
