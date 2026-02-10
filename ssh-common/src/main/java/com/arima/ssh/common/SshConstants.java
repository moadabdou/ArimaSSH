package com.arima.ssh.common;

public class SshConstants {

    // Message Codes
    public static final byte SSH_MSG_KEXINIT = 20;
    public static final byte SSH_MSG_NEWKEYS = 21;
    public static final byte SSH_MSG_KEXDH_INIT = 30;
    public static final byte SSH_MSG_KEXDH_REPLY = 31;

    // Supported Algorithms
    public static final String PROPOSAL_KEX = "diffie-hellman-group14-sha1";
    public static final String PROPOSAL_HOST_KEY = "ssh-rsa"; 
    public static final String PROPOSAL_CIPHER = "aes128-ctr";
    public static final String PROPOSAL_MAC = "hmac-sha1";
    public static final String PROPOSAL_COMPRESSION = "none";
    
    // Empty lists for things we don't care about yet
    public static final String PROPOSAL_LANG = "";
}