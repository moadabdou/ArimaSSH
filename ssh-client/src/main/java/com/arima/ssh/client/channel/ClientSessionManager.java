package com.arima.ssh.client.channel;

import com.arima.ssh.client.ClientSession;
import com.arima.ssh.common.channel.ChannelManager;


public class ClientSessionManager  extends ChannelManager {

    public ClientSessionManager(ClientSession session) {
        super(session);
    }

}
