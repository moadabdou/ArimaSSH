package com.arima.ssh.server.subsystem;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.arima.ssh.server.channel.SessionChannel;

public class SftpSubsystem {

    private final SessionChannel channel;

    private Logger logger = LoggerFactory.getLogger(SftpSubsystem.class.getName());
    
    public SftpSubsystem(SessionChannel channel) {
        this.channel = channel;
    }

    public void handleInput(byte[] data) {
        // Issue #30: We will parse SFTP packets here (INIT, OPEN, READ)
        // For now, just log that we got data.
        logger.info("Received data on SFTP subsystem: {} bytes", data.length);
    }
    
    public void close() {
        logger.info("Closing SFTP subsystem");
    }

}
