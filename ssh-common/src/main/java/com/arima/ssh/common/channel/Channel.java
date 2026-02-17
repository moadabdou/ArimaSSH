package com.arima.ssh.common.channel;

import java.io.IOException;

import com.arima.ssh.common.SshBuffer;

/**
 * Common channel contract for both server-side and client-side SSH channels.
 */
public interface Channel {

    long getChannelId();
    long getRemoteId();
    Session getSession();

    void init(Session session, long channelId, long remoteId, long remoteWindow, long remoteMaxPacket);

    // --- Handlers (incoming from remote) ---
    boolean handleRequest(String type, SshBuffer buffer);
    void handleChannleReplay( byte Type);
    void handleWindowAdjust(long bytesToAdd);
    void handleData(byte[] data);
    void handleEof();

    // --- Senders (outgoing to remote) ---
    void sendData(byte[] data, int length) throws IOException;
    void sendEof() throws IOException;
    void sendClose() throws IOException;

    void close();
}
