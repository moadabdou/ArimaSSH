package com.arima.ssh.server.channel;

import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.util.concurrent.atomic.AtomicLong;

import com.arima.ssh.common.SshBuffer;
import com.arima.ssh.common.SshConstants;
import com.arima.ssh.server.ServerSession;

public class DirectTcpipChannel implements Channel{
    
    private long id;
    private long remoteId;
    private long remoteWindow;
    private long remoteMaxPacket;
    private ServerSession session;
    
    private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(DirectTcpipChannel.class);

    private final Object lock = new Object();

    private String targetHost;
    private long targetPort;
    private String originatorHost;
    private long originatorPort;
    private Socket socket;

    // --- Metrics for data exchange tracking ---
    private final AtomicLong totalBytesReceived = new AtomicLong(0);  // client -> target
    private final AtomicLong totalBytesSent = new AtomicLong(0);      // target -> client
    private final AtomicLong dataChunksReceived = new AtomicLong(0);
    private final AtomicLong dataChunksSent = new AtomicLong(0);
    private volatile boolean eofSent = false;
    private volatile boolean closeSent = false;
    private volatile boolean closed = false;
    private long createdAtMillis;


    public DirectTcpipChannel(String targetHost, long targetPort, String originatorHost, long originatorPort)  throws IOException {

        this.createdAtMillis = System.currentTimeMillis();

        logger.info("[DirectTcpip] CREATING channel: tunnel {}:{} <-- originator {}:{}", 
            targetHost, targetPort, originatorHost, originatorPort);

        this.targetHost = targetHost;
        this.targetPort = targetPort;
        this.originatorHost = originatorHost;
        this.originatorPort = originatorPort;

        logger.debug("[DirectTcpip] Opening TCP socket to {}:{} ...", targetHost, targetPort);
        this.socket = new Socket(this.targetHost, (int)this.targetPort);
        logger.info("[DirectTcpip] TCP socket CONNECTED to {}:{} (local={}:{})", 
            targetHost, targetPort, socket.getLocalAddress().getHostAddress(), socket.getLocalPort());
    }


    @Override
    public void init(ServerSession session, long channelId, long remoteId, long remoteWindow, long remoteMaxPacket) {
        this.session = session;
        this.id = channelId;
        this.remoteId = remoteId;
        this.remoteWindow = remoteWindow;
        this.remoteMaxPacket = remoteMaxPacket;

        logger.info("[DirectTcpip ch#{}] INITIALIZED: localId={}, remoteId={}, remoteWindow={}, remoteMaxPacket={}, tunnel={}:{}", 
            id, channelId, remoteId, remoteWindow, remoteMaxPacket, targetHost, targetPort);

        startPump();
    }

    @Override
    public boolean handleRequest(String type, SshBuffer buffer){
        logger.warn("[DirectTcpip ch#{}] Unsupported request type '{}' (no handler registered)", id, type);
        return false;
    }

    @Override
    public void handleWindowAdjust(long bytesToAdd) {
        synchronized (lock) {
            long oldWindow = remoteWindow;
            remoteWindow += bytesToAdd;
            logger.debug("[DirectTcpip ch#{}] WINDOW_ADJUST: +{} bytes (window {} -> {})", id, bytesToAdd, oldWindow, remoteWindow);
            lock.notifyAll();
        }
    }

    @Override
    public void handleData(byte[] data) { 

        long chunkNum = dataChunksReceived.incrementAndGet();
        long totalRecv = totalBytesReceived.addAndGet(data.length);

        logger.debug("[DirectTcpip ch#{}] DATA_IN: chunk #{}, {} bytes (totalReceived={})", id, chunkNum, data.length, totalRecv);

        if (this.socket == null || !this.socket.isConnected() || this.socket.isClosed()) {
            logger.warn("[DirectTcpip ch#{}] DATA_IN DROPPED: socket is {} (connected={}, closed={}), {} bytes lost",
                id, 
                socket == null ? "null" : "present",
                socket != null && socket.isConnected(),
                socket != null && socket.isClosed(),
                data.length);
            return;
        }

        try {
            this.socket.getOutputStream().write(data);
            this.socket.getOutputStream().flush();
            logger.debug("[DirectTcpip ch#{}] DATA_IN FORWARDED: {} bytes written to target {}:{}", id, data.length, targetHost, targetPort);
        } catch (IOException e) {
            logger.error("[DirectTcpip ch#{}] DATA_IN ERROR: failed to write {} bytes to target {}:{} - {}", 
                id, data.length, targetHost, targetPort, e.getMessage(), e);
            try {
                sendEof();
                sendClose();
            } catch (IOException ex) {
                logger.error("[DirectTcpip ch#{}] Failed to send EOF/Close after write error: {}", id, ex.getMessage(), ex);
            }
        }
    }

    @Override
    public void close() { 

        if (closed) {
            logger.debug("[DirectTcpip ch#{}] close() called but already closed, skipping", id);
            return;
        }

        closed = true;
        long uptimeMs = System.currentTimeMillis() - createdAtMillis;

        logger.info("[DirectTcpip ch#{}] CLOSING channel (uptime={}ms)", id, uptimeMs);
        logger.info("[DirectTcpip ch#{}] Final stats: bytesSentToClient={}, bytesReceivedFromClient={}, chunksSent={}, chunksReceived={}", 
            id, totalBytesSent.get(), totalBytesReceived.get(), dataChunksSent.get(), dataChunksReceived.get());

        if (socket != null && !socket.isClosed()) {
            try {
                logger.info("[DirectTcpip ch#{}] Closing TCP socket to {}:{} (local={}:{})", 
                    id, targetHost, targetPort, socket.getLocalAddress().getHostAddress(), socket.getLocalPort());
                socket.close();
                logger.info("[DirectTcpip ch#{}] TCP socket CLOSED successfully", id);
            } catch (IOException e) {
                logger.error("[DirectTcpip ch#{}] Error closing TCP socket: {}", id, e.getMessage(), e);
            }
        } else {
            logger.debug("[DirectTcpip ch#{}] Socket already closed or null during close()", id);
        }

        logger.info("[DirectTcpip ch#{}] Channel DESTROYED (tunnel was {}:{} <-- {}:{})", 
            id, targetHost, targetPort, originatorHost, originatorPort);
    }


    private void waitForWindow(int len) throws InterruptedException {
        synchronized (lock) {
            if (remoteWindow < len) {
                logger.debug("[DirectTcpip ch#{}] WINDOW_WAIT: need {} bytes, available={}, blocking...", id, len, remoteWindow);
            }
            while (remoteWindow < len) {
                lock.wait();
            }
            remoteWindow -= len;
            logger.debug("[DirectTcpip ch#{}] WINDOW_CONSUMED: {} bytes (remaining={})", id, len, remoteWindow);
        }
    }

    public void startPump() {
        logger.info("[DirectTcpip ch#{}] Starting data pump thread (target={}:{}, maxPacket={})", id, targetHost, targetPort, remoteMaxPacket);

        new Thread( ()->{
            logger.debug("[DirectTcpip ch#{}] Pump thread started", id);
            try (InputStream socketIn = socket.getInputStream()) {
                byte[] buffer = new byte[(int)remoteMaxPacket];
                int read;
                while ((read = socketIn.read(buffer)) != -1) {
                    if (read > 0) {

                        long chunkNum = dataChunksSent.incrementAndGet();
                        long totalSent = totalBytesSent.addAndGet(read);

                        try{ 
                            waitForWindow(read);
                        } catch (InterruptedException e) {
                            logger.error("[DirectTcpip ch#{}] Pump INTERRUPTED while waiting for window (chunk #{}, {} bytes pending)", id, chunkNum, read, e);
                            Thread.currentThread().interrupt();
                            break;
                        }

                        SshBuffer sshBuffer = new SshBuffer();
                        sshBuffer.writeByte(SshConstants.SSH_MSG_CHANNEL_DATA);
                        sshBuffer.writeUInt32(remoteId);
                        sshBuffer.writeByteString(buffer, 0, read);

                        logger.debug("[DirectTcpip ch#{}] DATA_OUT: chunk #{}, {} bytes -> client (totalSent={}, remoteWindow={})", 
                            id, chunkNum, read, totalSent, remoteWindow);

                        session.sendPacket(sshBuffer);
                    }
                }
                logger.info("[DirectTcpip ch#{}] Pump: target socket EOF reached (stream ended normally)", id);
            } catch (IOException e) {
                logger.error("[DirectTcpip ch#{}] Pump ERROR: {} (totalBytesSent={}, totalBytesReceived={})", 
                    id, e.getMessage(), totalBytesSent.get(), totalBytesReceived.get(), e);
            } finally {
                logger.info("[DirectTcpip ch#{}] Pump thread finishing, sending EOF and Close...", id);
                try {
                    sendEof();
                    sendClose();
                } catch (IOException e) {
                    logger.error("[DirectTcpip ch#{}] Pump cleanup: failed to send EOF/Close: {}", id, e.getMessage(), e);
                }
                logger.info("[DirectTcpip ch#{}] Pump thread TERMINATED (totalBytesSent={}, totalBytesReceived={})", 
                    id, totalBytesSent.get(), totalBytesReceived.get());
            }
        }, "DirectTcpip-Pump-" + id).start();
    }

    private void sendEof() throws IOException {
        if (eofSent) {
            logger.debug("[DirectTcpip ch#{}] EOF already sent, skipping duplicate", id);
            return;
        }
        eofSent = true;
        logger.info("[DirectTcpip ch#{}] Sending SSH_MSG_CHANNEL_EOF to remote (remoteId={})", id, remoteId);
        SshBuffer buffer = new SshBuffer();
        buffer.writeByte(SshConstants.SSH_MSG_CHANNEL_EOF);
        buffer.writeUInt32(this.remoteId);
        session.sendPacket(buffer);
        logger.debug("[DirectTcpip ch#{}] SSH_MSG_CHANNEL_EOF sent", id);
    }

    private void sendClose() throws IOException {
        if (closeSent) {
            logger.debug("[DirectTcpip ch#{}] CLOSE already sent, skipping duplicate", id);
            return;
        }
        closeSent = true;
        logger.info("[DirectTcpip ch#{}] Sending SSH_MSG_CHANNEL_CLOSE to remote (remoteId={})", id, remoteId);
        SshBuffer buffer = new SshBuffer();
        buffer.writeByte(SshConstants.SSH_MSG_CHANNEL_CLOSE);
        buffer.writeUInt32(this.remoteId);
        session.sendPacket(buffer);
        logger.debug("[DirectTcpip ch#{}] SSH_MSG_CHANNEL_CLOSE sent, cleaning up resources...", id);
        close();
    }

    @Override
    public long getChannelId() {
        return id; 
    }

    @Override
    public long getRemoteId() {
        return remoteId;
    }

    @Override 
    public ServerSession getSession() {
        return session;
    }


    public String getTargetHost() {
        return targetHost;
    }

    public long getTargetPort() {
        return targetPort;
    }

    public String getOriginatorHost() {
        return originatorHost;
    }

    public long getOriginatorPort() {
        return originatorPort;
    }

    public Socket getSocket() {
        return socket;
    }
    

}
