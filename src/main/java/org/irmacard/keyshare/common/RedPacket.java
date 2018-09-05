package org.irmacard.keyshare.common;

public class RedPacket {
    private String serverKey;
    private String username;

    public RedPacket(String serverKey, String username) {
        this.serverKey = serverKey;
        this.username = username;
    }

    public String getServerKey() {
        return serverKey;
    }

    public void setServerKey(String serverKey) {
        this.serverKey = serverKey;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }
}
