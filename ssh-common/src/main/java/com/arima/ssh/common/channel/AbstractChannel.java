package com.arima.ssh.common.channel;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicLong;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.arima.ssh.common.SshBuffer;
import com.arima.ssh.common.SshConstants;

/**
 * Base implementation of {@link Channel} that handles all the wire-protocol
 * boilerplate shared by every channel type on both the server and client side:
 * window management, sendData/sendEof/sendClose, metrics, and guard flags.
 * <p>
 * Subclasses only need to implement:
 * <ul>
 *   <li>{@link #handleRequest(String, SshBuffer)}</li>
 *   <li>{@link #handleData(byte[])}</li>
 *   <li>{@link #handleEof()}</li>
 *   <li>{@link #doClose()} — subclass-specific resource cleanup</li>
 * </ul>
 */
public abstract class AbstractChannel implements Channel {

    private static final Logger logger = LoggerFactory.getLogger(AbstractChannel.class);

    protected long id;
    protected long remoteId;
    protected long remoteWindow;
    protected long remoteMaxPacket;
    protected Session session;

    protected final Object lock = new Object();

    protected volatile boolean eofSent = false;
    protected volatile boolean closeSent = false;
    protected volatile boolean closed = false;
    protected long createdAtMillis;

    protected final AtomicLong totalBytesReceived = new AtomicLong(0);
    protected final AtomicLong totalBytesSent = new AtomicLong(0);
    protected final AtomicLong dataChunksReceived = new AtomicLong(0);
    protected final AtomicLong dataChunksSent = new AtomicLong(0);

    // ---- Channel identity ----

    @Override
    public long getChannelId() {
        return id;
    }

    @Override
    public long getRemoteId() {
        return remoteId;
    }

    @Override
    public Session getSession() {
        return session;
    }

    public long getRemoteMaxPacket() {
        return remoteMaxPacket;
    }

    // ---- Initialization ----

    @Override
    public void init(Session session, long channelId, long remoteId, long remoteWindow, long remoteMaxPacket) {
        this.session = session;
        this.id = channelId;
        this.remoteId = remoteId;
        this.remoteWindow = remoteWindow;
        this.remoteMaxPacket = remoteMaxPacket;
        this.createdAtMillis = System.currentTimeMillis();

        logger.info("[Channel ch#{}] INITIALIZED: localId={}, remoteId={}, remoteWindow={}, remoteMaxPacket={}",
            id, channelId, remoteId, remoteWindow, remoteMaxPacket);
    }

    // ---- Channel Replay ------- 
    @Override
    public void handleChannleReplay( byte Type) {

        boolean success = (Type == SshConstants.SSH_MSG_CHANNEL_SUCCESS);

        logger.info("[Channel ch#{}] REPLAY : success={}", id, success);

    }

    // ---- Window management ----

    @Override
    public void handleWindowAdjust(long bytesToAdd) {
        synchronized (lock) {
            long oldWindow = remoteWindow;
            remoteWindow += bytesToAdd;
            logger.debug("[Channel ch#{}] WINDOW_ADJUST: +{} bytes (window {} -> {})", id, bytesToAdd, oldWindow, remoteWindow);
            lock.notifyAll();
        }
    }

    protected void waitForWindow(int len) throws InterruptedException {
        synchronized (lock) {
            if (remoteWindow < len) {
                logger.debug("[Channel ch#{}] WINDOW_WAIT: need {} bytes, available={}, blocking...", id, len, remoteWindow);
            }
            while (remoteWindow < len) {
                lock.wait();
            }
            remoteWindow -= len;
            logger.debug("[Channel ch#{}] WINDOW_CONSUMED: {} bytes (remaining={})", id, len, remoteWindow);
        }
    }

    // ---- Senders ----

    @Override
    public void sendData(byte[] data, int length) throws IOException {
        if (closed) {
            logger.warn("[Channel ch#{}] Attempt to send data after channel is closed, dropping {} bytes", id, length);
            return;
        }
        SshBuffer buffer = new SshBuffer();
        buffer.writeByte(SshConstants.SSH_MSG_CHANNEL_DATA);
        buffer.writeUInt32(remoteId);
        buffer.writeByteString(data, 0, length);
        session.sendPacket(buffer);
        totalBytesSent.addAndGet(length);
        dataChunksSent.incrementAndGet();
        logger.debug("[Channel ch#{}] Sent {} bytes (totalSent={})", id, length, totalBytesSent.get());
    }

    @Override
    public void sendEof() throws IOException {
        if (eofSent) {
            logger.debug("[Channel ch#{}] EOF already sent, skipping duplicate", id);
            return;
        }
        eofSent = true;
        logger.info("[Channel ch#{}] Sending SSH_MSG_CHANNEL_EOF (remoteId={})", id, remoteId);
        SshBuffer buffer = new SshBuffer();
        buffer.writeByte(SshConstants.SSH_MSG_CHANNEL_EOF);
        buffer.writeUInt32(this.remoteId);
        session.sendPacket(buffer);
    }

    @Override
    public void sendClose() throws IOException {
        if (closeSent) {
            logger.debug("[Channel ch#{}] CLOSE already sent, skipping duplicate", id);
            return;
        }
        closeSent = true;
        logger.info("[Channel ch#{}] Sending SSH_MSG_CHANNEL_CLOSE (remoteId={})", id, remoteId);
        SshBuffer buffer = new SshBuffer();
        buffer.writeByte(SshConstants.SSH_MSG_CHANNEL_CLOSE);
        buffer.writeUInt32(this.remoteId);
        session.sendPacket(buffer);
        close();
    }

    // ---- Close lifecycle ----

    @Override
    public void close() {
        if (closed) {
            logger.debug("[Channel ch#{}] close() called but already closed, skipping", id);
            return;
        }
        closed = true;
        long uptimeMs = System.currentTimeMillis() - createdAtMillis;

        logger.info("[Channel ch#{}] CLOSING (uptime={}ms)", id, uptimeMs);
        logger.info("[Channel ch#{}] Final stats: bytesSent={}, bytesReceived={}, chunksSent={}, chunksReceived={}",
            id, totalBytesSent.get(), totalBytesReceived.get(), dataChunksSent.get(), dataChunksReceived.get());

        doClose();

        logger.info("[Channel ch#{}] DESTROYED", id);
    }

    /**
     * Subclass-specific resource cleanup (e.g. destroy process, close socket).
     * Called exactly once from {@link #close()}.
     */
    protected abstract void doClose();
}
