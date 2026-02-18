package com.arima.ssh.common.channel;

import java.io.IOException;
import java.net.Socket;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A TCP/IP channel that actively connects to a remote target host.
 * <p>
 * Used when the SSH peer asks us to open a connection on its behalf:
 * <ul>
 *   <li>Server-side: handles incoming "direct-tcpip" channel-open requests from the client</li>
 *   <li>Client-side: handles incoming "forwarded-tcpip" channel-open requests from the server</li>
 * </ul>
 */
public class RemoteTcpIpChannel extends BaseTcpIpChannel {

    private static final Logger logger = LoggerFactory.getLogger(RemoteTcpIpChannel.class);

    private final String targetHost;
    private final long targetPort;
    private final String originatorHost;
    private final long originatorPort;

    public RemoteTcpIpChannel(String targetHost, long targetPort, String originatorHost, long originatorPort) throws IOException {
        
        super(new Socket(targetHost, (int) targetPort), "RemoteTcpIp");

        this.targetHost = targetHost;
        this.targetPort = targetPort;
        this.originatorHost = originatorHost;
        this.originatorPort = originatorPort;

        logger.info("[RemoteTcpIp] CREATING channel: tunnel {}:{} <-- originator {}:{}",
            targetHost, targetPort, originatorHost, originatorPort);
        logger.info("[RemoteTcpIp] TCP socket CONNECTED to {}:{} (local={}:{})",
            targetHost, targetPort, socket.getLocalAddress().getHostAddress(), socket.getLocalPort());
    }

    public String getTargetHost() { return targetHost; }
    public long getTargetPort() { return targetPort; }
    public String getOriginatorHost() { return originatorHost; }
    public long getOriginatorPort() { return originatorPort; }
}
