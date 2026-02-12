package com.arima.ssh.server.channel;

import com.arima.ssh.common.PacketWriter;
import com.arima.ssh.common.SshBuffer;
import com.arima.ssh.common.SshConstants;
import com.arima.ssh.server.ServerSession;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import org.slf4j.Logger;

import org.slf4j.LoggerFactory;

public class ChannelManager {

    private final Map<Integer, Channel> channels = new HashMap<>();
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

        // for now, we only support "session" channels. In the future, we can add "direct-tcpip", "x11", etc.
        if (!"session".equals(type)) {
            // return SSH_MSG_CHANNEL_OPEN_FAILURE with reason SSH_OPEN_UNKNOWN_CHANNEL_TYPE
            logger.warn("Client requested unsupported channel type: {}", type);
            SshBuffer reply = new SshBuffer();
            reply.writeByte(SshConstants.SSH_MSG_CHANNEL_OPEN_FAILURE);
            reply.writeUInt32(senderChannel); // Recipient Channel
            reply.writeUInt32(SshConstants.SSH_OPEN_UNKNOWN_CHANNEL_TYPE); // Reason Code
            reply.writeString("Unsupported channel type: " + type); // Description
            reply.writeString(""); // Language Tag (empty for now)
            return reply.getCompactData();
        }


        int myId = nextChannelId++;
        SessionChannel channel = new SessionChannel();
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
    
    public Channel getChannel(int id) {
        return channels.get(id);
    }
}