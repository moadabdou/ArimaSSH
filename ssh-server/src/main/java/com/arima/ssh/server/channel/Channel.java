package com.arima.ssh.server.channel;
import com.arima.ssh.common.SshBuffer;
import com.arima.ssh.server.ServerSession;

public interface Channel {
    long getChannelId(); // The Server's ID (e.g., 0)
    long getRemoteId();  // The Client's ID (e.g., 5)
    ServerSession getSession();
    
    void init(ServerSession session, long channelId, long remoteId, long remoteWindow, long remoteMaxPacket);
    
    boolean handleRequest(String type, SshBuffer buffer);
    void handleWindowAdjust(long bytesToAdd);

    void handleData(byte[] data);
    void handleEof();
    void close();
}