package com.arima.ssh.server.channel;
import com.arima.ssh.common.SshBuffer;
import com.arima.ssh.server.ServerSession;
import java.io.IOException;

public interface Channel {
    long getChannelId(); // The Server's ID (e.g., 0)
    long getRemoteId();  // The Client's ID (e.g., 5)
    
    void init(ServerSession session, long channelId, long remoteId, long remoteWindow, long remoteMaxPacket);
    
    // Future methods for Phase 3:
    // void handleRequest(String type, SshBuffer buffer);
    // void handleData(byte[] data);
    // void close();
}