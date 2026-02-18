package com.arima.ssh.common.channel;

import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;

import com.arima.ssh.common.SshBuffer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Base class for TCP/IP tunnelling channels (both "direct-tcpip" and "forwarded-tcpip").
 * <p>
 * Handles all the common plumbing: reading from / writing to the underlying TCP
 * socket, the data-pump thread, EOF handling, and closing.
 * Subclasses only differ in how the socket is obtained (connect vs. accept).
 */
public abstract class BaseTcpIpChannel extends AbstractChannel {

    private static final Logger logger = LoggerFactory.getLogger(BaseTcpIpChannel.class);

    protected Socket socket;
    protected Thread pumpThread;
    protected final String logPrefix;

    protected BaseTcpIpChannel(Socket socket, String logPrefix) {
        this.createdAtMillis = System.currentTimeMillis();
        this.socket = socket;
        this.logPrefix = logPrefix;
    }

    // ---- Lifecycle ----

    @Override
    public void init(Session session, long channelId, long remoteId, long remoteWindow, long remoteMaxPacket) {
        super.init(session, channelId, remoteId, remoteWindow, remoteMaxPacket);
        logger.info("[{} ch#{}] INITIALIZED", logPrefix, id);
        startPump();
    }

    @Override
    public boolean handleRequest(String type, SshBuffer buffer) {
        logger.warn("[{} ch#{}] Unsupported request type '{}' (no handler registered)", logPrefix, id, type);
        return false;
    }

    // ---- Data ----

    @Override
    public void handleData(byte[] data) {

        long chunkNum = dataChunksReceived.incrementAndGet();
        long totalRecv = totalBytesReceived.addAndGet(data.length);

        logger.debug("[{} ch#{}] DATA_IN: chunk #{}, {} bytes (totalReceived={})", logPrefix, id, chunkNum, data.length, totalRecv);

        if (this.socket == null || !this.socket.isConnected() || this.socket.isClosed()) {
            logger.warn("[{} ch#{}] DATA_IN DROPPED: socket is {} (connected={}, closed={}), {} bytes lost",
                logPrefix, id,
                socket == null ? "null" : "present",
                socket != null && socket.isConnected(),
                socket != null && socket.isClosed(),
                data.length);
            return;
        }

        try {
            this.socket.getOutputStream().write(data);
            this.socket.getOutputStream().flush();
            logger.debug("[{} ch#{}] DATA_IN FORWARDED: {} bytes written to socket", logPrefix, id, data.length);
        } catch (IOException e) {
            logger.error("[{} ch#{}] DATA_IN ERROR: failed to write {} bytes to socket - {}",
                logPrefix, id, data.length, e.getMessage(), e);
            try {
                sendEof();
                sendClose();
            } catch (IOException ex) {
                logger.error("[{} ch#{}] Failed to send EOF/Close after write error: {}", logPrefix, id, ex.getMessage(), ex);
            }
        }
    }

    // ---- EOF / Close ----

    @Override
    public void handleEof() {
        if (socket != null && !socket.isOutputShutdown()) {
            try {
                socket.shutdownOutput();
                logger.info("[{} ch#{}] Shut down socket output after receiving EOF", logPrefix, id);
            } catch (IOException e) {
                logger.error("[{} ch#{}] Failed to shut down socket output: {}", logPrefix, id, e.getMessage());
            }
        }
    }

    @Override
    protected void doClose() {
        if (socket != null && !socket.isClosed()) {
            try {
                logger.info("[{} ch#{}] Closing TCP socket (remote={}:{}, local={}:{})",
                    logPrefix, id,
                    socket.getInetAddress().getHostAddress(), socket.getPort(),
                    socket.getLocalAddress().getHostAddress(), socket.getLocalPort());
                socket.close();
                logger.info("[{} ch#{}] TCP socket CLOSED successfully", logPrefix, id);
            } catch (IOException e) {
                logger.error("[{} ch#{}] Error closing TCP socket: {}", logPrefix, id, e.getMessage(), e);
            }
        }
    }

    // ---- Pump thread ----

    private void startPump() {
        logger.info("[{} ch#{}] Starting data pump thread (maxPacket={})", logPrefix, id, remoteMaxPacket);

        pumpThread = new Thread(() -> {
            logger.debug("[{} ch#{}] Pump thread started", logPrefix, id);
            try (InputStream socketIn = socket.getInputStream()) {
                byte[] buffer = new byte[(int) remoteMaxPacket];
                int read;
                while ((read = socketIn.read(buffer)) != -1) {
                    if (read > 0) {

                        long chunkNum = dataChunksSent.incrementAndGet();
                        long totalSent = totalBytesSent.addAndGet(read);

                        try {
                            waitForWindow(read);
                        } catch (InterruptedException e) {
                            logger.error("[{} ch#{}] Pump INTERRUPTED while waiting for window (chunk #{}, {} bytes pending)",
                                logPrefix, id, chunkNum, read, e);
                            Thread.currentThread().interrupt();
                            break;
                        }

                        try {
                            sendData(buffer, read);
                            logger.debug("[{} ch#{}] Pump: sent chunk #{}, {} bytes (totalSent={})",
                                logPrefix, id, chunkNum, read, totalSent);
                        } catch (IOException e) {
                            logger.error("[{} ch#{}] Pump ERROR sending data for chunk #{}: {} ({} bytes)",
                                logPrefix, id, chunkNum, e.getMessage(), read, e);
                            break;
                        }
                    }
                }
                logger.info("[{} ch#{}] Pump: socket EOF reached (stream ended normally)", logPrefix, id);
            } catch (IOException e) {
                logger.error("[{} ch#{}] Pump ERROR: {} (totalBytesSent={}, totalBytesReceived={})",
                    logPrefix, id, e.getMessage(), totalBytesSent.get(), totalBytesReceived.get(), e);
            } finally {
                logger.info("[{} ch#{}] Pump thread finishing, sending EOF and Close...", logPrefix, id);
                try {
                    sendEof();
                    sendClose();
                } catch (IOException e) {
                    logger.error("[{} ch#{}] Pump cleanup: failed to send EOF/Close: {}", logPrefix, id, e.getMessage(), e);
                }
                logger.info("[{} ch#{}] Pump thread TERMINATED (totalBytesSent={}, totalBytesReceived={})",
                    logPrefix, id, totalBytesSent.get(), totalBytesReceived.get());
            }
        }, logPrefix + "-Pump-" + id);

        pumpThread.start();
    }

    // ---- Accessors ----

    public Socket getSocket() {
        return socket;
    }
}
