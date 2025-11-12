package de.tu_darmstadt.seemoo.nfcgate.network.data;

public enum NetworkStatus {
    ERROR,
    ERROR_TLS,
    ERROR_TLS_CERT_UNKNOWN,
    ERROR_TLS_CERT_UNTRUSTED,
    ERROR_AUTH_FAILED,

    CONNECTING,
    CONNECTED,
    PARTNER_CONNECT,
    PARTNER_LEFT,

    AUTH_IN_PROGRESS,
    AUTH_SUCCESS,
}
