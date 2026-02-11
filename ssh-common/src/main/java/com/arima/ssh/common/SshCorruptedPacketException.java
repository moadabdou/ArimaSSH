package com.arima.ssh.common;

public class SshCorruptedPacketException extends Exception {
    public SshCorruptedPacketException(String message) {
        super(message);
    }
}
