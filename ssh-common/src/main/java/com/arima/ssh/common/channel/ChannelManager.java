package com.arima.ssh.common.channel;

import com.arima.ssh.common.SshBuffer;
import com.arima.ssh.common.SshConstants;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Manages the lifecycle of SSH channels for both server and client sessions.
 * <p>
 * Protocol-level dispatch (data, window-adjust, close, EOF, open-confirmation,
 * open-failure, channel-request) is identical on both sides and lives here.
 * <p>
 * Channel-open handling is side-specific: override
 * {@link #handleChannelOpen(SshBuffer)} in a subclass, or use it as-is and
 * initiate opens from the client side via {@link #sendChannelOpen}.
 */
public class ChannelManager {

    private final Map<Long, Channel> channels = new ConcurrentHashMap<>();
    private int nextChannelId = 0;
    protected final Session session;
    protected final Logger logger = LoggerFactory.getLogger(getClass());

    public ChannelManager(Session session) {
        this.session = session;
    }

    // ========== Handlers (incoming from remote) ==========

    /**
     * Override in server-side subclass to create channels from incoming open
     * requests. The default implementation rejects all opens with
     * SSH_OPEN_UNKNOWN_CHANNEL_TYPE.
     */
    public byte[] handleChannelOpen(SshBuffer buffer) {
        String type = buffer.readString();
        long senderChannel = buffer.readUInt32();
        buffer.readUInt32(); // initialWindow
        buffer.readUInt32(); // maxPacket

        logger.warn("Rejecting unsupported channel open: type={}", type);

        SshBuffer reply = new SshBuffer();
        reply.writeByte(SshConstants.SSH_MSG_CHANNEL_OPEN_FAILURE);
        reply.writeUInt32(senderChannel);
        reply.writeUInt32(SshConstants.SSH_OPEN_UNKNOWN_CHANNEL_TYPE);
        reply.writeString("Unsupported channel type: " + type);
        reply.writeString("");
        return reply.getCompactData();
    }

    public byte[] handleChannelRequest(SshBuffer buffer) {

        long recipientId = buffer.readUInt32();
        String type = buffer.readString();
        boolean wantReply = buffer.readBoolean();

        logger.info("Received channel request: recipientId={}, type={}, wantReply={}", recipientId, type, wantReply);

        Channel channel = channels.get(recipientId);

        if (channel == null) {
            logger.warn("Received request for unknown channel ID: {}", recipientId);
            if (wantReply) {
                SshBuffer reply = new SshBuffer();
                reply.writeByte(SshConstants.SSH_MSG_CHANNEL_FAILURE);
                reply.writeUInt32(recipientId);
                return reply.getCompactData();
            }
            return null;
        }

        boolean success = channel.handleRequest(type, buffer);
        logger.info("Handled channel request: recipientId={}, type={}, success={}", recipientId, type, success);

        if (wantReply) {
            SshBuffer reply = new SshBuffer();
            if (success) {
                reply.writeByte(SshConstants.SSH_MSG_CHANNEL_SUCCESS);
            } else {
                reply.writeByte(SshConstants.SSH_MSG_CHANNEL_FAILURE);
            }
            reply.writeUInt32(channel.getRemoteId());
            return reply.getCompactData();
        }

        return null;
    }

    public void handleChannelData(SshBuffer buffer) {

        long recipientId = buffer.readUInt32();
        byte[] data = buffer.readByteString();

        logger.info("Received channel data: recipientId={}, dataLength={}", recipientId, data.length);

        Channel channel = channels.get(recipientId);

        if (channel != null) {
            channel.handleData(data);

            // Send SSH_MSG_CHANNEL_WINDOW_ADJUST to replenish the local window
            try {
                SshBuffer windowAdjust = new SshBuffer();
                windowAdjust.writeByte(SshConstants.SSH_MSG_CHANNEL_WINDOW_ADJUST);
                windowAdjust.writeUInt32(channel.getRemoteId());
                windowAdjust.writeUInt32(data.length);
                session.sendPacket(windowAdjust);
            } catch (Exception e) {
                logger.error("Failed to send window adjust for channel {}: {}", recipientId, e.getMessage());
            }
        } else {
            logger.warn("Received data for unknown channel ID: {}", recipientId);
        }
    }

    public void handleChannelWindowAdjust(SshBuffer buffer) {

        long recipientId = buffer.readUInt32();
        long bytesToAdd = buffer.readUInt32();

        logger.debug("Received channel window adjust: recipientId={}, bytesToAdd={}", recipientId, bytesToAdd);

        Channel channel = channels.get(recipientId);
        if (channel != null) {
            channel.handleWindowAdjust(bytesToAdd);
        } else {
            logger.warn("Received window adjust for unknown channel ID: {}", recipientId);
        }
    }

    public void handleChannelClose(SshBuffer buffer) {

        long recipientId = buffer.readUInt32();
        logger.info("Received channel close: recipientId={}", recipientId);

        Channel channel = channels.get(recipientId);
        if (channel != null) {
            channels.remove(recipientId);
            try {
                channel.sendClose();
            } catch (Exception e) {
                logger.debug("Failed to send channel close reply for channel {} (remote likely already disconnected): {}", recipientId, e.getMessage());
            }
            logger.info("Closed channel: recipientId={}", recipientId);
        } else {
            logger.warn("Received close for unknown channel ID: {}", recipientId);
        }
    }

    public void handleChannelOpenConfirmation(SshBuffer buffer) {
        long recipientId = buffer.readUInt32();
        long senderChannel = buffer.readUInt32();
        long initialWindow = buffer.readUInt32();
        long maxPacket = buffer.readUInt32();

        logger.info("Received channel open confirmation: recipientId={}, senderChannel={}, initialWindow={}, maxPacket={}",
            recipientId, senderChannel, initialWindow, maxPacket);

        Channel channel = channels.get(recipientId);
        if (channel != null) {
            channel.init(session, recipientId, senderChannel, initialWindow, maxPacket);
            logger.info("Channel open confirmed for channel ID {}", recipientId);
        } else {
            logger.warn("Received channel open confirmation for unknown channel ID: {}", recipientId);
        }
    }

    public void handleChannelOpenFailure(SshBuffer buffer) {

        long recipientId = buffer.readUInt32();
        long reasonCode = buffer.readUInt32();
        String description = buffer.readString();

        logger.warn("Channel open failed: recipientId={}, reasonCode={}, description={}", recipientId, reasonCode, description);

        Channel channel = channels.get(recipientId);
        if (channel != null) {
            channel.close();
            channels.remove(recipientId);
        } else {
            logger.warn("Received channel open failure for unknown channel ID: {}", recipientId);
        }
    }

    public void handleChannelEOF(SshBuffer buffer) {
        long recipientId = buffer.readUInt32();
        logger.info("Received channel EOF: recipientId={}", recipientId);

        Channel channel = channels.get(recipientId);
        if (channel == null) {
            logger.warn("Received EOF for unknown channel ID: {}", recipientId);
            return;
        }
        channel.handleEof();
    }

    // ========== Senders (outgoing to remote) ==========

    /**
     * Send a channel open request to the remote side.
     * @param type           channel type (e.g. "session", "direct-tcpip", "forwarded-tcpip")
     * @param extraData      type-specific payload (may be null)
     * @param channel        the locally-created channel to register
     * @return the local channel ID assigned
     */
    public long sendChannelOpen(String type, SshBuffer extraData, Channel channel) throws IOException {
        long myId = registerChannel(channel);

        SshBuffer buf = new SshBuffer();
        buf.writeByte(SshConstants.SSH_MSG_CHANNEL_OPEN);
        buf.writeString(type);
        buf.writeUInt32(myId);
        buf.writeUInt32(2 * 1024 * 1024); // initial window
        buf.writeUInt32(32 * 1024);        // max packet

        if (extraData != null) {
            byte[] extra = extraData.getCompactData();
            buf.writeBytes(extra, 0, extra.length);
        }

        session.sendPacket(buf);
        logger.info("Sent channel open: type={}, localId={}", type, myId);
        return myId;
    }

    // ========== Channel registry ==========

    public long registerChannel(Channel channel) {
        long myId = nextChannelId++;
        channels.put(myId, channel);
        return myId;
    }

    public void closeAllChannels() {
        logger.info("Closing all channels");
        for (Channel channel : channels.values()) {
            try {
                channel.close();
            } catch (Exception e) {
                logger.error("Error closing channel " + channel.getChannelId(), e);
            }
        }
        channels.clear();
    }

    public Channel getChannel(long id) {
        return channels.get(id);
    }
}
