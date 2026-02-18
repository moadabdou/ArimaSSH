package com.arima.ssh.server.channel;

import com.arima.ssh.common.SshBuffer;
import com.arima.ssh.common.SshConstants;
import com.arima.ssh.common.channel.Channel;
import com.arima.ssh.common.channel.ChannelManager;
import com.arima.ssh.common.channel.RemoteTcpIpChannel;
import com.arima.ssh.server.ServerSession;

/**
 * Server-side channel manager that knows how to create channels from incoming
 * SSH_MSG_CHANNEL_OPEN requests.
 */
public class ServerChannelManager extends ChannelManager {

    private final ServerSession serverSession;

    public ServerChannelManager(ServerSession serverSession) {
        super(serverSession);
        this.serverSession = serverSession;
    }

    @Override
    public byte[] handleChannelOpen(SshBuffer buffer) {

        String type = buffer.readString();
        long senderChannel = buffer.readUInt32();
        long initialWindow = buffer.readUInt32();
        long maxPacket = buffer.readUInt32();

        logger.info("Received channel open request: type={}, senderChannel={}, initialWindow={}, maxPacket={}",
            type, senderChannel, initialWindow, maxPacket);

        Channel channel = null;

        if ("session".equals(type)) {

            channel = new SessionChannel(serverSession);

        } else if ("direct-tcpip".equals(type)) {

            String targetHost = buffer.readString();
            long targetPort = buffer.readUInt32();
            String originatorHost = buffer.readString();
            long originatorPort = buffer.readUInt32();

            logger.info("Received direct-tcpip channel open request: targetHost={}, targetPort={}, originatorHost={}, originatorPort={}",
                targetHost, targetPort, originatorHost, originatorPort);

            try {
                channel = new RemoteTcpIpChannel(targetHost, targetPort, originatorHost, originatorPort);
            } catch (Exception e) {
                logger.error("Error creating RemoteTcpIpChannel: ", e);
                SshBuffer reply = new SshBuffer();
                reply.writeByte(SshConstants.SSH_MSG_CHANNEL_OPEN_FAILURE);
                reply.writeUInt32(senderChannel);
                reply.writeUInt32(SshConstants.SSH_OPEN_CONNECT_FAILED);
                reply.writeString("Failed to connect to " + targetHost + ":" + targetPort);
                reply.writeString("");
                return reply.getCompactData();
            }

        } else {

            logger.warn("Client requested unsupported channel type: {}", type);
            SshBuffer reply = new SshBuffer();
            reply.writeByte(SshConstants.SSH_MSG_CHANNEL_OPEN_FAILURE);
            reply.writeUInt32(senderChannel);
            reply.writeUInt32(SshConstants.SSH_OPEN_UNKNOWN_CHANNEL_TYPE);
            reply.writeString("Unsupported channel type: " + type);
            reply.writeString("");
            return reply.getCompactData();
        }

        long myId = registerChannel(channel);
        channel.init(serverSession, myId, senderChannel, initialWindow, maxPacket);

        SshBuffer reply = new SshBuffer();
        reply.writeByte(SshConstants.SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
        reply.writeUInt32(senderChannel);
        reply.writeUInt32(myId);
        reply.writeUInt32(2 * 1024 * 1024);
        reply.writeUInt32(32 * 1024);

        logger.info("Channel opened: id {}, type={}, senderChannel={}, initialWindow={}, maxPacket={}", myId, type, senderChannel, initialWindow, maxPacket);

        return reply.getCompactData();
    }
}
