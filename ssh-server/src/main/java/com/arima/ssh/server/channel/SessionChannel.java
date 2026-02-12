package com.arima.ssh.server.channel;

import com.arima.ssh.server.ServerSession;

public class SessionChannel implements Channel {
    
    private long id;
    private long remoteId;
    private long remoteWindow;
    private long remoteMaxPacket;
    private ServerSession session;

    @Override
    public void init(ServerSession session, long id, long remoteId, long remoteWindow, long remoteMaxPacket) {
        this.session = session;
        this.id = id;
        this.remoteId = remoteId;
        this.remoteWindow = remoteWindow;
        this.remoteMaxPacket = remoteMaxPacket;
    }

    @Override
    public long getChannelId() { return id; }

    @Override
    public long getRemoteId() { return remoteId; }
}