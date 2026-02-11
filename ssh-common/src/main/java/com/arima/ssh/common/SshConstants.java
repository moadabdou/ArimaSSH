package com.arima.ssh.common;

public class SshConstants {

    // Message Codes

    public static final byte SSH_MSG_DISCONNECT = 1;
    public static final byte SSH_MSG_IGNORE = 2;
    public static final byte SSH_MSG_UNIMPLEMENTED = 3;
    public static final byte SSH_MSG_DEBUG = 4;
    public static final byte SSH_MSG_SERVICE_REQUEST = 5;
    public static final byte SSH_MSG_SERVICE_ACCEPT = 6;


    public static final byte SSH_MSG_KEXINIT = 20;
    public static final byte SSH_MSG_NEWKEYS = 21;
    public static final byte SSH_MSG_KEXDH_INIT = 30;
    public static final byte SSH_MSG_KEXDH_REPLY = 31;


    public static final byte SSH_MSG_USERAUTH_REQUEST = 50;
    public static final byte SSH_MSG_USERAUTH_FAILURE = 51;
    public static final byte SSH_MSG_USERAUTH_SUCCESS = 52;
    public static final byte SSH_MSG_USERAUTH_BANNER = 53;
    public static final byte SSH_MSG_USERAUTH_INFO_REQUEST = 60;
    public static final byte SSH_MSG_USERAUTH_INFO_RESPONSE = 61;


    // Disconnect Reasons
    public static final int SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT = 1;
    public static final int SSH_DISCONNECT_PROTOCOL_ERROR = 2;
    public static final int SSH_DISCONNECT_KEY_EXCHANGE_FAILED = 3;
    public static final int SSH_DISCONNECT_RESERVED = 4;
    public static final int SSH_DISCONNECT_MAC_ERROR = 5;
    public static final int SSH_DISCONNECT_COMPRESSION_ERROR = 6;
    public static final int SSH_DISCONNECT_SERVICE_NOT_AVAILABLE = 7;
    public static final int SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED = 8;
    public static final int SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE = 9;
    public static final int SSH_DISCONNECT_CONNECTION_LOST = 10;
    public static final int SSH_DISCONNECT_BY_APPLICATION = 11;
    public static final int SSH_DISCONNECT_TOO_MANY_CONNECTIONS = 12;
    public static final int SSH_DISCONNECT_AUTH_CANCELLED_BY_USER = 13;
    public static final int SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE = 14;
    public static final int SSH_DISCONNECT_ILLEGAL_USER_NAME = 15;


    // Supported Authentication Methods

    public static final String SUPPORTED_AUTH_METHODS = "publickey,password";

    // Supported Algorithms
    public static final String PROPOSAL_KEX = "diffie-hellman-group14-sha1";
    public static final String PROPOSAL_HOST_KEY = "ssh-rsa"; 
    public static final String PROPOSAL_CIPHER = "aes128-ctr";
    public static final String PROPOSAL_MAC = "hmac-sha1";
    public static final String PROPOSAL_COMPRESSION = "none";
    
    // Empty lists for things we don't care about yet
    public static final String PROPOSAL_LANG = "";
}