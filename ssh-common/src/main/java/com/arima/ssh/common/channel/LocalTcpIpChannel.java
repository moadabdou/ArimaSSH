package com.arima.ssh.common.channel;

import java.net.Socket;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A TCP/IP channel that wraps an already-accepted local socket.
 * <p>
 * Used by {@link com.arima.ssh.common.ForwardingManager} when a connection is
 * accepted on a locally-bound listener and needs to be tunnelled through the
 * SSH connection to the remote peer.
 */
public class LocalTcpIpChannel extends BaseTcpIpChannel {

    private static final Logger logger = LoggerFactory.getLogger(LocalTcpIpChannel.class);

    public LocalTcpIpChannel(Socket socket) {
        super(socket, "LocalTcpIp");

        logger.info("[LocalTcpIp] CREATING channel: accepted connection from {}:{}",
            socket.getInetAddress().getHostAddress(), socket.getPort());
    }
    
}
