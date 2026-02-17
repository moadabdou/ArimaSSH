
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
import com.arima.ssh.common.SshConstants;
import com.arima.ssh.server.channel.ForwardedTcpipChannel;

public class ForwardingManager {

    private final ServerSession session;
    private final Map<Integer, ServerSocket> listeners = new ConcurrentHashMap<>();

    private final Logger logger = LoggerFactory.getLogger(ForwardingManager.class);

    public ForwardingManager(ServerSession session) {
        this.session = session;
    }

    public boolean requestForwarding(String bindAddr, int port) {

        try {

            logger.info("Requesting forwarding on port {} with bind address '{}'", port, bindAddr);

            InetAddress bindIp = (bindAddr == null || bindAddr.isEmpty()) 
                                 ? null : InetAddress.getByName(bindAddr);
                                 
            ServerSocket serverSocket = new ServerSocket(port, 50, bindIp);

            listeners.put(port, serverSocket);
            
            new Thread(() -> acceptLoop(serverSocket, bindAddr, port), "Forward-Listen-" + port).start();

            return true;
            
        } catch (IOException e) {
            logger.error("Failed to start forwarding on port {}", port, e);
            return false;
        }
    }

    private void acceptLoop(ServerSocket serverSocket, String bindAddr, int bindPort) {

        logger.info("Started forwarding listener on port {} with bind address '{}'", bindPort, bindAddr);

        while (!serverSocket.isClosed()) {

            try {

                Socket incomingSocket = serverSocket.accept();
                
                logger.info("Accepted connection on forwarded port {}", bindPort);

                ForwardedTcpipChannel channel = new ForwardedTcpipChannel(incomingSocket);
                
                long myId = session.getChannelManager().registerChannel(channel);
                

                SshBuffer buffer = new SshBuffer();
                buffer.writeByte(SshConstants.SSH_MSG_CHANNEL_OPEN);
                buffer.writeString("forwarded-tcpip");
                buffer.writeUInt32(myId);          
                buffer.writeUInt32(2 * 1024 * 1024);
                buffer.writeUInt32(32 * 1024);  
                
                buffer.writeString(bindAddr);  
                buffer.writeUInt32(bindPort);   
                buffer.writeString(incomingSocket.getInetAddress().getHostAddress());
                buffer.writeUInt32(incomingSocket.getPort());   
                
                session.sendPacket(buffer);
                
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