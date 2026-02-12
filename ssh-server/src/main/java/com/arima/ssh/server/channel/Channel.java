package com.arima.ssh.server.channel;
import com.arima.ssh.common.SshBuffer;
import com.arima.ssh.server.ServerSession;

public interface Channel {
    long getChannelId(); // The Server's ID (e.g., 0)
    long getRemoteId();  // The Client's ID (e.g., 5)
    
    void init(ServerSession session, long channelId, long remoteId, long remoteWindow, long remoteMaxPacket);
    
    
    /**
     * Handles a generic channel request.
     * @param type The request type (e.g., "pty-req", "env")
     * @param wantReply Whether the client expects a success/failure packet
     * @param buffer The rest of the payload
     * @return true if we handled it successfully, false if we failed or don't support it.
     */
    boolean handleRequest(String type, boolean wantReply, SshBuffer buffer);

    void handleData(byte[] data);
    // void close();
}