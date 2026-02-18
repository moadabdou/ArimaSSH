package com.arima.ssh.client;

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
 * Manages TCP/IP port-forwarding listeners for the client.
 * <p>
 * When a connection is accepted on a bound port, a {@link LocalTcpIpChannel} is
 * created, registered with the {@link ChannelManager}, and an
 * SSH_MSG_CHANNEL_OPEN is sent to the remote peer using "direct-tcpip".
 */
public class ClientForwardingManager {

    private final ChannelManager channelManager;
    private final Map<Integer, ServerSocket> listeners = new ConcurrentHashMap<>();

    private final Logger logger = LoggerFactory.getLogger(ClientForwardingManager.class);

    public ClientForwardingManager(ChannelManager channelManager) {
        this.channelManager = channelManager;
    }

    public boolean requestForwarding(String bindAddr, int bindPort, String targetHost, int targetPort) {

        try {

            logger.info("Requesting forwarding on port {} with bind address '{}' to target {}:{}", 
                        bindPort, bindAddr, targetHost, targetPort);

            InetAddress bindIp = (bindAddr == null || bindAddr.isEmpty()) 
                                 ? null : InetAddress.getByName(bindAddr);
                                 
            ServerSocket serverSocket = new ServerSocket(bindPort, 50, bindIp);

            listeners.put(bindPort, serverSocket);
            
            new Thread(() -> acceptLoop(serverSocket, bindAddr, bindPort, targetHost, targetPort), 
                        "ClientForward-Listen-" + bindPort).start();

            return true;
            
        } catch (IOException e) {
            logger.error("Failed to start forwarding on bindPort {}", bindPort, e);
            return false;
        }
    }

    private void acceptLoop(ServerSocket serverSocket, String bindAddr, int bindPort, String targetHost, int targetPort) {

        logger.info("Started client forwarding listener on port {} -> {}:{}", bindPort, targetHost, targetPort);

        while (!serverSocket.isClosed()) {

            try {

                Socket incomingSocket = serverSocket.accept();
                
                logger.info("Accepted connection on forwarded port {}", bindPort);

                LocalTcpIpChannel channel = new LocalTcpIpChannel(incomingSocket);

                SshBuffer extraData = new SshBuffer();

                // associated with the "direct-tcpip" channel type:
                // string    host to connect
                // uint32    port to connect
                // string    originator IP address
                // uint32    originator port
                extraData.writeString(targetHost);
                extraData.writeUInt32(targetPort);
                extraData.writeString(incomingSocket.getInetAddress().getHostAddress());
                extraData.writeUInt32(incomingSocket.getPort());

                channelManager.sendChannelOpen("direct-tcpip", extraData, channel);
                
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
