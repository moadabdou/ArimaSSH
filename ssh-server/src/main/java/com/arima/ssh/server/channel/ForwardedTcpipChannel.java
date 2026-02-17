package com.arima.ssh.server.channel;

import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;

import com.arima.ssh.common.SshBuffer;
import com.arima.ssh.common.channel.AbstractChannel;
import com.arima.ssh.common.channel.Session;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ForwardedTcpipChannel extends AbstractChannel {

    private static final Logger logger = LoggerFactory.getLogger(ForwardedTcpipChannel.class);

    private Socket socket;
    private Thread pumpThread;

    public ForwardedTcpipChannel(Socket socket) {
        this.createdAtMillis = System.currentTimeMillis();
        this.socket = socket;

        logger.info("[ForwardedTcpip] CREATING channel: accepted connection from {}:{}",
            socket.getInetAddress().getHostAddress(), socket.getPort());
    }

    @Override
    public void init(Session session, long channelId, long remoteId, long remoteWindow, long remoteMaxPacket) {
        super.init(session, channelId, remoteId, remoteWindow, remoteMaxPacket);
        logger.info("[ForwardedTcpip ch#{}] INITIALIZED", id);
        startPump();
    }

    @Override
    public boolean handleRequest(String type, SshBuffer buffer) {
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
    protected void doClose() {
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
        }
    }

    private void startPump() {
        logger.info("[ForwardedTcpip ch#{}] Starting data pump thread (maxPacket={})", id, remoteMaxPacket);

        pumpThread = new Thread(() -> {
            logger.debug("[ForwardedTcpip ch#{}] Pump thread started", id);
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
                            logger.error("[ForwardedTcpip ch#{}] Pump INTERRUPTED while waiting for window (chunk #{}, {} bytes pending)", id, chunkNum, read, e);
                            Thread.currentThread().interrupt();
                            break;
                        }

                        try {
                            sendData(buffer, read);
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

    public Socket getSocket() {
        return socket;
    }
}
