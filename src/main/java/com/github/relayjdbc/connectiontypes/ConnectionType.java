package com.github.relayjdbc.connectiontypes;

public enum ConnectionType {

    HTTP(new HttpConnectionTypeHandler()),
    HTTPS(new HttpsConnectionTypeHandler()),
    SSH_PIPE(new SshPipeConnectionTypeHandler());

    public ConnectionTypeHandler getConnectionTypeHandler() {
        return connectionTypeHandler;
    }

    private final ConnectionTypeHandler connectionTypeHandler;

    ConnectionType(ConnectionTypeHandler connectionTypeHandler) {
        this.connectionTypeHandler = connectionTypeHandler;
    }

    public static ConnectionType fromRelayUrl(String relayUrl) {
        for(ConnectionType ct : ConnectionType.values()) {
            if (ct.connectionTypeHandler.canHandle(relayUrl)) {
                return ct;
            }
        }

        return null;
    }
}
