package com.arima.ssh.server.channel;

import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.util.concurrent.atomic.AtomicLong;

import com.arima.ssh.common.SshBuffer;
import com.arima.ssh.common.SshConstants;
import com.arima.ssh.server.ServerSession;

public class ForwardedTcpipChannel implements Channel {

    private long id;
    private long remoteId;
    private long remoteWindow;
    private long remoteMaxPacket;
    private ServerSession session;
    
    private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ForwardedTcpipChannel.class);

    private final Object lock = new Object();

    private Socket socket;

    Thread pumpThread;

    private final AtomicLong totalBytesReceived = new AtomicLong(0);
    private final AtomicLong totalBytesSent = new AtomicLong(0);
    private final AtomicLong dataChunksReceived = new AtomicLong(0);
    private final AtomicLong dataChunksSent = new AtomicLong(0);
    private volatile boolean eofSent = false;
    private volatile boolean closeSent = false;
    private volatile boolean closed = false;
    private long createdAtMillis;


    public ForwardedTcpipChannel(Socket socket) {
        this.createdAtMillis = System.currentTimeMillis();
        this.socket = socket;

        logger.info("[ForwardedTcpip] CREATING channel: accepted connection from {}:{}", 
            socket.getInetAddress().getHostAddress(), socket.getPort());
    }


    @Override
    public void init(ServerSession session, long channelId, long remoteId, long remoteWindow, long remoteMaxPacket) {
        this.session = session;
        this.id = channelId;
        this.remoteId = remoteId;
        this.remoteWindow = remoteWindow;
        this.remoteMaxPacket = remoteMaxPacket;

        logger.info("[ForwardedTcpip ch#{}] INITIALIZED: localId={}, remoteId={}, remoteWindow={}, remoteMaxPacket={}", 
            id, channelId, remoteId, remoteWindow, remoteMaxPacket);

        startPump();
    }

    @Override
    public boolean handleRequest(String type, SshBuffer buffer){
        logger.warn("[ForwardedTcpip ch#{}] Unsupported request type '{}' (no handler registered)", id, type);
        return false;
    }

    @Override
    public void handleEof() {
        logger.info("[ForwardedTcpip ch#{}] EOF received from client, closing socket output stream", id);
        if (socket != null && !socket.isOutputShutdown()) {
            try {
                socket.shutdownOutput();
                logger.info("[ForwardedTcpip ch#{}] Socket output stream shutdown successfully", id);
            } catch (IOException e) {
                logger.error("[ForwardedTcpip ch#{}] Error shutting down socket output stream: {}", id, e.getMessage(), e);
            }
        } else {
            logger.debug("[ForwardedTcpip ch#{}] Socket already closed or null when handling EOF", id);
        }
    }

    @Override
    public void handleWindowAdjust(long bytesToAdd) {
        synchronized (lock) {
            long oldWindow = remoteWindow;
            remoteWindow += bytesToAdd;
            logger.debug("[ForwardedTcpip ch#{}] WINDOW_ADJUST: +{} bytes (window {} -> {})", id, bytesToAdd, oldWindow, remoteWindow);
            lock.notifyAll();
        }
    }

    @Override
    public void handleData(byte[] data) { 

        long chunkNum = dataChunksReceived.incrementAndGet();
        long totalRecv = totalBytesReceived.addAndGet(data.length);

        logger.debug("[ForwardedTcpip ch#{}] DATA_IN: chunk #{}, {} bytes (totalReceived={})", id, chunkNum, data.length, totalRecv);

        if (this.socket == null || !this.socket.isConnected() || this.socket.isClosed()) {
            logger.warn("[ForwardedTcpip ch#{}] DATA_IN DROPPED: socket is {} (connected={}, closed={}), {} bytes lost",
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
            logger.debug("[ForwardedTcpip ch#{}] DATA_IN FORWARDED: {} bytes written to socket", id, data.length);
        } catch (IOException e) {
            logger.error("[ForwardedTcpip ch#{}] DATA_IN ERROR: failed to write {} bytes to socket - {}", 
                id, data.length, e.getMessage(), e);
            try {
                sendEof();
                sendClose();
            } catch (IOException ex) {
                logger.error("[ForwardedTcpip ch#{}] Failed to send EOF/Close after write error: {}", id, ex.getMessage(), ex);
            }
        }
    }

    @Override
    public void close() { 

        if (closed) {
            logger.debug("[ForwardedTcpip ch#{}] close() called but already closed, skipping", id);
            return;
        }
        
        closed = true;
        long uptimeMs = System.currentTimeMillis() - createdAtMillis;

        logger.info("[ForwardedTcpip ch#{}] CLOSING channel (uptime={}ms)", id, uptimeMs);
        logger.info("[ForwardedTcpip ch#{}] Final stats: bytesSentToClient={}, bytesReceivedFromClient={}, chunksSent={}, chunksReceived={}", 
            id, totalBytesSent.get(), totalBytesReceived.get(), dataChunksSent.get(), dataChunksReceived.get());

        if (socket != null && !socket.isClosed()) {
            try {
                logger.info("[ForwardedTcpip ch#{}] Closing TCP socket (remote={}:{}, local={}:{})", 
                    id, socket.getInetAddress().getHostAddress(), socket.getPort(),
                    socket.getLocalAddress().getHostAddress(), socket.getLocalPort());
                socket.close();
                logger.info("[ForwardedTcpip ch#{}] TCP socket CLOSED successfully", id);
            } catch (IOException e) {
                logger.error("[ForwardedTcpip ch#{}] Error closing TCP socket: {}", id, e.getMessage(), e);
            }
        } else {
            logger.debug("[ForwardedTcpip ch#{}] Socket already closed or null during close()", id);
        }

        logger.info("[ForwardedTcpip ch#{}] Channel DESTROYED", id);
    }


    private void waitForWindow(int len) throws InterruptedException {
        synchronized (lock) {
            if (remoteWindow < len) {
                logger.debug("[ForwardedTcpip ch#{}] WINDOW_WAIT: need {} bytes, available={}, blocking...", id, len, remoteWindow);
            }
            while (remoteWindow < len) {
                lock.wait();
            }
            remoteWindow -= len;
            logger.debug("[ForwardedTcpip ch#{}] WINDOW_CONSUMED: {} bytes (remaining={})", id, len, remoteWindow);
        }
    }

    public void startPump() {
        logger.info("[ForwardedTcpip ch#{}] Starting data pump thread (maxPacket={})", id, remoteMaxPacket);

        pumpThread = new Thread( ()->{
            logger.debug("[ForwardedTcpip ch#{}] Pump thread started", id);
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
                            logger.error("[ForwardedTcpip ch#{}] Pump INTERRUPTED while waiting for window (chunk #{}, {} bytes pending)", id, chunkNum, read, e);
                            Thread.currentThread().interrupt();
                            break;
                        }

                        try {
                            sendData(buffer,read);
                            logger.debug("[ForwardedTcpip ch#{}] Pump: sent chunk #{}, {} bytes to client (totalSent={})", id, chunkNum, read, totalSent);
                        } catch (IOException e) {
                            logger.error("[ForwardedTcpip ch#{}] Pump ERROR sending data to client for chunk #{}: {} ({} bytes)", 
                                id, chunkNum, e.getMessage(), read, e);
                            break;
                        }
                    }
                }
                logger.info("[ForwardedTcpip ch#{}] Pump: socket EOF reached (stream ended normally)", id);
            } catch (IOException e) {
                logger.error("[ForwardedTcpip ch#{}] Pump ERROR: {} (totalBytesSent={}, totalBytesReceived={})", 
                    id, e.getMessage(), totalBytesSent.get(), totalBytesReceived.get(), e);
            } finally {
                logger.info("[ForwardedTcpip ch#{}] Pump thread finishing, sending EOF and Close...", id);
                try {
                    sendEof();
                    sendClose();
                } catch (IOException e) {
                    logger.error("[ForwardedTcpip ch#{}] Pump cleanup: failed to send EOF/Close: {}", id, e.getMessage(), e);
                }
                logger.info("[ForwardedTcpip ch#{}] Pump thread TERMINATED (totalBytesSent={}, totalBytesReceived={})", 
                    id, totalBytesSent.get(), totalBytesReceived.get());
            }
        }, "ForwardedTcpip-Pump-" + id);

        pumpThread.start();
    }

    public void sendData(byte[] data, int length) throws IOException {
        if (closed) {
            logger.warn("[ForwardedTcpip ch#{}] Attempt to send data after channel is closed, dropping {} bytes", id, data.length);
            return;
        }
        SshBuffer buffer = new SshBuffer();
        buffer.writeByte(SshConstants.SSH_MSG_CHANNEL_DATA);
        buffer.writeUInt32(remoteId);
        buffer.writeByteString(data, 0, length);
        session.sendPacket(buffer);
        logger.debug("[ForwardedTcpip ch#{}] Sent {} bytes to client (totalSent={})", id, data.length, totalBytesSent.get());
    }

    public void sendEof() throws IOException {
        if (eofSent) {
            logger.debug("[ForwardedTcpip ch#{}] EOF already sent, skipping duplicate", id);
            return;
        }
        eofSent = true;
        logger.info("[ForwardedTcpip ch#{}] Sending SSH_MSG_CHANNEL_EOF to remote (remoteId={})", id, remoteId);
        SshBuffer buffer = new SshBuffer();
        buffer.writeByte(SshConstants.SSH_MSG_CHANNEL_EOF);
        buffer.writeUInt32(this.remoteId);
        session.sendPacket(buffer);
        logger.debug("[ForwardedTcpip ch#{}] SSH_MSG_CHANNEL_EOF sent", id);
    }

    public void sendClose() throws IOException {
        if (closeSent) {
            logger.debug("[ForwardedTcpip ch#{}] CLOSE already sent, skipping duplicate", id);
            return;
        }
        closeSent = true;
        logger.info("[ForwardedTcpip ch#{}] Sending SSH_MSG_CHANNEL_CLOSE to remote (remoteId={})", id, remoteId);
        SshBuffer buffer = new SshBuffer();
        buffer.writeByte(SshConstants.SSH_MSG_CHANNEL_CLOSE);
        buffer.writeUInt32(this.remoteId);
        session.sendPacket(buffer);
        logger.debug("[ForwardedTcpip ch#{}] SSH_MSG_CHANNEL_CLOSE sent, cleaning up resources...", id);
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

    public Socket getSocket() {
        return socket;
    }
 
    
}
