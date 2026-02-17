package com.arima.ssh.server.channel;

import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;

import com.arima.ssh.common.SshBuffer;
import com.arima.ssh.common.channel.AbstractChannel;
import com.arima.ssh.common.channel.Session;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DirectTcpipChannel extends AbstractChannel {

    private static final Logger logger = LoggerFactory.getLogger(DirectTcpipChannel.class);

    private String targetHost;
    private long targetPort;
    private String originatorHost;
    private long originatorPort;
    private Socket socket;

    private Thread pumpThread;

    public DirectTcpipChannel(String targetHost, long targetPort, String originatorHost, long originatorPort) throws IOException {
        this.createdAtMillis = System.currentTimeMillis();

        logger.info("[DirectTcpip] CREATING channel: tunnel {}:{} <-- originator {}:{}",
            targetHost, targetPort, originatorHost, originatorPort);

        this.targetHost = targetHost;
        this.targetPort = targetPort;
        this.originatorHost = originatorHost;
        this.originatorPort = originatorPort;

        logger.debug("[DirectTcpip] Opening TCP socket to {}:{} ...", targetHost, targetPort);
        this.socket = new Socket(this.targetHost, (int) this.targetPort);
        logger.info("[DirectTcpip] TCP socket CONNECTED to {}:{} (local={}:{})",
            targetHost, targetPort, socket.getLocalAddress().getHostAddress(), socket.getLocalPort());
    }

    @Override
    public void init(Session session, long channelId, long remoteId, long remoteWindow, long remoteMaxPacket) {
        super.init(session, channelId, remoteId, remoteWindow, remoteMaxPacket);
        logger.info("[DirectTcpip ch#{}] INITIALIZED: tunnel={}:{}", id, targetHost, targetPort);
        startPump();
    }

    @Override
    public boolean handleRequest(String type, SshBuffer buffer) {
        logger.warn("[DirectTcpip ch#{}] Unsupported request type '{}' (no handler registered)", id, type);
        return false;
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
    public void handleEof() {
        if (socket != null && !socket.isOutputShutdown()) {
            try {
                socket.shutdownOutput();
                logger.info("[DirectTcpip ch#{}] Shut down socket output after receiving EOF", id);
            } catch (IOException e) {
                logger.error("[DirectTcpip ch#{}] Failed to shut down socket output: {}", id, e.getMessage());
            }
        }
    }

    @Override
    protected void doClose() {
        if (socket != null && !socket.isClosed()) {
            try {
                logger.info("[DirectTcpip ch#{}] Closing TCP socket to {}:{} (local={}:{})",
                    id, targetHost, targetPort, socket.getLocalAddress().getHostAddress(), socket.getLocalPort());
                socket.close();
                logger.info("[DirectTcpip ch#{}] TCP socket CLOSED successfully", id);
            } catch (IOException e) {
                logger.error("[DirectTcpip ch#{}] Error closing TCP socket: {}", id, e.getMessage(), e);
            }
        }
    }

    private void startPump() {
        logger.info("[DirectTcpip ch#{}] Starting data pump thread (target={}:{}, maxPacket={})", id, targetHost, targetPort, remoteMaxPacket);

        pumpThread = new Thread(() -> {
            logger.debug("[DirectTcpip ch#{}] Pump thread started", id);
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
                            logger.error("[DirectTcpip ch#{}] Pump INTERRUPTED while waiting for window (chunk #{}, {} bytes pending)", id, chunkNum, read, e);
                            Thread.currentThread().interrupt();
                            break;
                        }

                        try {
                            sendData(buffer, read);
                            logger.debug("[DirectTcpip ch#{}] Pump: sent chunk #{}, {} bytes to client (totalSent={})", id, chunkNum, read, totalSent);
                        } catch (IOException e) {
                            logger.error("[DirectTcpip ch#{}] Pump ERROR sending data to client for chunk #{}: {} ({} bytes)",
                                id, chunkNum, e.getMessage(), read, e);
                            break;
                        }
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
        }, "DirectTcpip-Pump-" + id);

        pumpThread.start();
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
