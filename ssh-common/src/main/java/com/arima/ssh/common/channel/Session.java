package com.arima.ssh.common.channel;

import java.io.IOException;

import com.arima.ssh.common.SshBuffer;

/**
 * Minimal session contract that both ServerSession and ClientSession implement.
 * This allows channel code to live in ssh-common without depending on either side.
 */
public interface Session {
    void sendPacket(SshBuffer buffer) throws IOException;
}
