package com.arima.ssh.server.channel;

import com.arima.ssh.common.SshBuffer;
import com.arima.ssh.common.SshConstants;
import com.arima.ssh.server.ServerSession;
import java.util.HashMap;
import java.util.Map;
import org.slf4j.Logger;

import org.slf4j.LoggerFactory;

public class ChannelManager {

    private final Map<Long, Channel> channels = new HashMap<>();
    private int nextChannelId = 0;
    private final ServerSession session;
    private final Logger logger = LoggerFactory.getLogger(ServerSession.class);

    public ChannelManager(ServerSession session) {
        this.session = session;
    }

    public byte[] handleChannelOpen(SshBuffer buffer) {

        String type = buffer.readString();
        long senderChannel = buffer.readUInt32();     // Client's ID
        long initialWindow = buffer.readUInt32(); // Client's Window
        long maxPacket = buffer.readUInt32();         // Client's Max Packet

        logger.info("Received channel open request: type={}, senderChannel={}, initialWindow={}, maxPacket={}", 
            type, senderChannel, initialWindow, maxPacket);


        Channel channel = null;


        if ("session".equals(type)) {

            channel = new SessionChannel();

        } else if( "direct-tcpip".equals(type)) {

            String targetHost = buffer.readString();
            long targetPort = buffer.readUInt32();
            String originatorHost = buffer.readString();
            long originatorPort = buffer.readUInt32();

            try {
                channel = new DirectTcpipChannel(targetHost, targetPort, originatorHost, originatorPort);
            } catch (Exception e) {
                logger.error("Error creating DirectTcpipChannel: ", e);
                SshBuffer reply = new SshBuffer();
                reply.writeByte(SshConstants.SSH_MSG_CHANNEL_OPEN_FAILURE);
                reply.writeUInt32(senderChannel); // Recipient Channel
                reply.writeUInt32(SshConstants.SSH_OPEN_CONNECT_FAILED); // Reason Code
                reply.writeString("Failed to connect to " + targetHost + ":" + targetPort); // Description
                reply.writeString(""); // Language Tag (empty for now)
                return reply.getCompactData();
            }

        }else {

            logger.warn("Client requested unsupported channel type: {}", type);
            SshBuffer reply = new SshBuffer();
            reply.writeByte(SshConstants.SSH_MSG_CHANNEL_OPEN_FAILURE);
            reply.writeUInt32(senderChannel); // Recipient Channel
            reply.writeUInt32(SshConstants.SSH_OPEN_UNKNOWN_CHANNEL_TYPE); // Reason Code
            reply.writeString("Unsupported channel type: " + type); // Description
            reply.writeString(""); // Language Tag (empty for now)
            return reply.getCompactData();

        }

        long myId = nextChannelId++;
        channel.init(session, myId, senderChannel, initialWindow, maxPacket);
        
        channels.put(myId, channel);

        // Payload: [recipient channel] [sender channel] [initial window] [max packet]
        SshBuffer reply = new SshBuffer();
        reply.writeByte(SshConstants.SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
        
        reply.writeUInt32(senderChannel); // Recipient Channel
        reply.writeUInt32(myId);          // Sender Channel
        reply.writeUInt32(2 * 1024 * 1024); // RFC 4253 recommends at least 2 MB for the initial window size
        reply.writeUInt32(32 * 1024);     // RFC 4253 recommends at least 32 KB for the max packet size
        
        logger.info("Channel opened: id {}, type={}, senderChannel={}, initialWindow={}, maxPacket={}", myId, type, senderChannel, initialWindow, maxPacket);

        return reply.getCompactData();
    }
    

    public byte[] handleChannelRequest(SshBuffer buffer){


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
                reply.writeUInt32(recipientId); // Recipient Channel
                return reply.getCompactData();
            }

            return null;

        }

        boolean success = channel.handleRequest(type, buffer);

        logger.info("Handled channel request: recipientId={}, type={}, success={}", recipientId, type, success);


        if (wantReply) {
            SshBuffer reply = new SshBuffer();

            logger.info("Sending channel request reply: recipientId={}, type={}, success={}", recipientId, type, success);

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
            // so the client can continue sending data
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

        logger.info("Handled channel data: recipientId={}, dataLength={}", recipientId, data.length);

    }

    public void handleChannelWindowAdjust(SshBuffer buffer) {

        long recipientId = buffer.readUInt32();
        long bytesToAdd = buffer.readUInt32();

        logger.info("Received channel window adjust: recipientId={}, bytesToAdd={}", recipientId, bytesToAdd);

        Channel channel = channels.get(recipientId);

        if (channel != null) {
            channel.handleWindowAdjust(bytesToAdd);
        } else {
            logger.warn("Received window adjust for unknown channel ID: {}", recipientId);
        }

        logger.info("Handled channel window adjust: recipientId={}, bytesToAdd={}", recipientId, bytesToAdd);

    }

    public void handleChannelClose(SshBuffer buffer) {

        long recipientId = buffer.readUInt32();

        logger.info("Received channel close: recipientId={}", recipientId);

        Channel channel = channels.get(recipientId);

        if (channel != null) {
            channel.close();
            channels.remove(recipientId);

            //send channel close back 

            SshBuffer reply = new SshBuffer();
            reply.writeByte(SshConstants.SSH_MSG_CHANNEL_CLOSE);
            reply.writeUInt32(channel.getRemoteId()); // Recipient Channel

            try {
                session.sendPacket(reply);
            } catch (Exception e) {
                logger.error("Failed to send channel close for channel {}: {}", recipientId, e.getMessage());
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

        logger.info("Received channel open failure: recipientId={}: reasonCode={}, description={}", recipientId, reasonCode, description);

        Channel channel = channels.get(recipientId);
        if (channel != null) {
            logger.warn("Channel open failed for channel ID {}: reasonCode={}, description={}", recipientId, reasonCode, description);
            channel.close(); // free any pre-allocated resources
            channels.remove(recipientId);
        } else {
            logger.warn("Received channel open failure for unknown channel ID: {}", recipientId);
        }
    }

    public void handleChannelEOF(SshBuffer buffer) {
        long recipientId = buffer.readUInt32();

        logger.info("Received channel EOF: recipientId={}", recipientId);

        Channel channel = channels.get(recipientId);
        if (channel != null) {
            logger.info("Channel EOF received for channel ID {}", recipientId);

            try {
                // Send SSH_MSG_CHANNEL_EOF back to the client
                SshBuffer eofReply = new SshBuffer();
                eofReply.writeByte(SshConstants.SSH_MSG_CHANNEL_EOF);
                eofReply.writeUInt32(channel.getRemoteId());
                session.sendPacket(eofReply);
                logger.info("Sent channel EOF for channel ID {}", recipientId);

                // Send SSH_MSG_CHANNEL_CLOSE to the client
                SshBuffer closeReply = new SshBuffer();
                closeReply.writeByte(SshConstants.SSH_MSG_CHANNEL_CLOSE);
                closeReply.writeUInt32(channel.getRemoteId());
                session.sendPacket(closeReply);
                logger.info("Sent channel close for channel ID {}", recipientId);
            } catch (Exception e) {
                logger.error("Failed to send EOF/close for channel {}: {}", recipientId, e.getMessage());
            }

            // Clean up channel resources
            channel.close();
            channels.remove(recipientId);
        } else {
            logger.warn("Received channel EOF for unknown channel ID: {}", recipientId);
        }
    }


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