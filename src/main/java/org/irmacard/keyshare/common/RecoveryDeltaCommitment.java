package org.irmacard.keyshare.common;

public class RecoveryDeltaCommitment {
    private String serverDeltaHash;

    public RecoveryDeltaCommitment(String serverDeltaHash) {
        this.serverDeltaHash = serverDeltaHash;
    }

    public String getServerDeltaHash() {
        return serverDeltaHash;
    }

    public void setServerDeltaHash(String serverDeltaHash) {
        this.serverDeltaHash = serverDeltaHash;
    }
}
