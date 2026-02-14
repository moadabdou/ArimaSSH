package com.arima.ssh.server.subsystem;


public interface SftpHandle extends AutoCloseable {

    void close() throws Exception;
    
}
