package com.arima.ssh.server;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.arima.ssh.common.SshBuffer;
import com.arima.ssh.common.channel.ChannelManager;
import com.arima.ssh.common.channel.LocalTcpIpChannel;

/**
 * Manages TCP/IP port-forwarding listeners for the server (remote forwarding).
 * <p>
 * When a connection is accepted on a bound port, a {@link LocalTcpIpChannel} is
 * created, registered with the {@link ChannelManager}, and an
 * SSH_MSG_CHANNEL_OPEN is sent to the remote peer using "forwarded-tcpip".
 */
public class ServerForwardingManager {

    private final ChannelManager channelManager;
    private final Map<Integer, ServerSocket> listeners = new ConcurrentHashMap<>();

    private final Logger logger = LoggerFactory.getLogger(ServerForwardingManager.class);

    public ServerForwardingManager(ChannelManager channelManager) {
        this.channelManager = channelManager;
    }

    public boolean requestForwarding(String bindAddr, int bindPort) {

        try {

            logger.info("Requesting forwarding on port {} with bind address '{}'", bindPort, bindAddr);

            InetAddress bindIp = (bindAddr == null || bindAddr.isEmpty()) 
                                 ? null : InetAddress.getByName(bindAddr);
                                 
            ServerSocket serverSocket = new ServerSocket(bindPort, 50, bindIp);

            listeners.put(bindPort, serverSocket);
            
            new Thread(() -> acceptLoop(serverSocket, bindAddr, bindPort), "ServerForward-Listen-" + bindPort).start();

            return true;
            
        } catch (IOException e) {
            logger.error("Failed to start forwarding on bindPort {}", bindPort, e);
            return false;
        }
    }

    private void acceptLoop(ServerSocket serverSocket, String bindAddr, int bindPort) {

        logger.info("Started server forwarding listener on port {} with bind address '{}'", bindPort, bindAddr);

        while (!serverSocket.isClosed()) {

            try {

                Socket incomingSocket = serverSocket.accept();
                
                logger.info("Accepted connection on forwarded port {}", bindPort);

                LocalTcpIpChannel channel = new LocalTcpIpChannel(incomingSocket);

                SshBuffer extraData = new SshBuffer();

                // associated with the "forwarded-tcpip" channel type
                extraData.writeString(bindAddr);
                extraData.writeUInt32(bindPort);
                extraData.writeString(incomingSocket.getInetAddress().getHostAddress());
                extraData.writeUInt32(incomingSocket.getPort());

                channelManager.sendChannelOpen("forwarded-tcpip", extraData, channel);
                
            } catch (IOException e) {
                if (!serverSocket.isClosed()) logger.error("Accept error", e);
            }
        }
    }
    
    public void closeAll() {
        listeners.values().forEach(s -> {
            try { s.close(); } catch (IOException ignored) {}
        });
        listeners.clear();
    }
}
