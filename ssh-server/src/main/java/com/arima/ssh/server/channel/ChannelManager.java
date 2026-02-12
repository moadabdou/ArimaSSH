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

        // for now, we only support "session" channels. In the future, we can add "direct-tcpip", "x11", etc.
        
        Channel channel = null;


        if ("session".equals(type)) {

            channel = new SessionChannel();

        } else {

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
        
        logger.info("Channel opened: type={}, senderChannel={}, initialWindow={}, maxPacket={}", type, senderChannel, initialWindow, maxPacket);

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

        boolean success = channel.handleRequest(type, wantReply, buffer);

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
        } else {
            logger.warn("Received data for unknown channel ID: {}", recipientId);
        }

        logger.info("Handled channel data: recipientId={}, dataLength={}", recipientId, data.length);

    }

    public void handleChannelClose(SshBuffer buffer) {

        long recipientId = buffer.readUInt32();

        logger.info("Received channel close: recipientId={}", recipientId);

        Channel channel = channels.get(recipientId);

        if (channel != null) {
            channel.close();
            channels.remove(recipientId);
            logger.info("Closed channel: recipientId={}", recipientId);
        } else {
            logger.warn("Received close for unknown channel ID: {}", recipientId);
        }

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