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
    public static final byte SSH_MSG_USERAUTH_PK_OK = 60;


    public static final byte SSH_MSG_GLOBAL_REQUEST = 80;
    public static final byte SSH_MSG_REQUEST_SUCCESS = 81;
    public static final byte SSH_MSG_REQUEST_FAILURE = 82;


    public static final byte SSH_MSG_CHANNEL_OPEN = 90;
    public static final byte SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91;
    public static final byte SSH_MSG_CHANNEL_OPEN_FAILURE = 92;
    public static final byte SSH_MSG_CHANNEL_WINDOW_ADJUST = 93;
    public static final byte SSH_MSG_CHANNEL_DATA = 94;
    public static final byte SSH_MSG_CHANNEL_EXTENDED_DATA = 95;
    public static final byte SSH_MSG_CHANNEL_EOF = 96;
    public static final byte SSH_MSG_CHANNEL_CLOSE = 97;
    public static final byte SSH_MSG_CHANNEL_REQUEST = 98;
    public static final byte SSH_MSG_CHANNEL_SUCCESS = 99;
    public static final byte SSH_MSG_CHANNEL_FAILURE = 100;


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


    // Channel Open Failure Reasons
    public static final int SSH_OPEN_ADMINISTRATIVELY_PROHIBITED = 1;
    public static final int SSH_OPEN_CONNECT_FAILED = 2;
    public static final int SSH_OPEN_UNKNOWN_CHANNEL_TYPE = 3;
    public static final int SSH_OPEN_RESOURCE_SHORTAGE = 4;


    // SFTP Message Codes
    public static final byte SSH_FXP_INIT = 1;
    public static final byte SSH_FXP_VERSION = 2;
    public static final byte SSH_FXP_OPEN = 3;
    public static final byte SSH_FXP_CLOSE = 4;
    public static final byte SSH_FXP_READ = 5;
    public static final byte SSH_FXP_WRITE = 6;
    public static final byte SSH_FXP_LSTAT = 7;
    public static final byte SSH_FXP_FSTAT = 8;
    public static final byte SSH_FXP_SETSTAT = 9;
    public static final byte SSH_FXP_FSETSTAT = 10;
    public static final byte SSH_FXP_OPENDIR = 11;
    public static final byte SSH_FXP_READDIR = 12;
    public static final byte SSH_FXP_REMOVE = 13;
    public static final byte SSH_FXP_MKDIR = 14;
    public static final byte SSH_FXP_RMDIR = 15;
    public static final byte SSH_FXP_REALPATH = 16;
    public static final byte SSH_FXP_STAT = 17;
    public static final byte SSH_FXP_RENAME = 18;
    public static final byte SSH_FXP_STATUS = 101;
    public static final byte SSH_FXP_HANDLE = 102;
    public static final byte SSH_FXP_DATA = 103;
    public static final byte SSH_FXP_NAME = 104;
    public static final byte SSH_FXP_ATTRS = 105;

    // SFTP Status Codes
    public static final int SSH_FX_OK = 0;
    public static final int SSH_FX_EOF = 1;
    public static final int SSH_FX_NO_SUCH_FILE = 2;
    public static final int SSH_FX_PERMISSION_DENIED = 3;
    public static final int SSH_FX_FAILURE = 4;
    public static final int SSH_FX_BAD_MESSAGE = 5;
    public static final int SSH_FX_NO_CONNECTION = 6;
    public static final int SSH_FX_CONNECTION_LOST = 7;
    public static final int SSH_FX_OP_UNSUPPORTED = 8;
    
    // File Open Flags
    public static final int SSH_FXF_READ = 0x00000001;
    public static final int SSH_FXF_WRITE = 0x00000002;
    public static final int SSH_FXF_APPEND = 0x00000004;
    public static final int SSH_FXF_CREAT = 0x00000008;
    public static final int SSH_FXF_TRUNC = 0x00000010;
    public static final int SSH_FXF_EXCL = 0x00000020;


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