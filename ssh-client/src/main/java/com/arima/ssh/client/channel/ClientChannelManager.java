package com.arima.ssh.client.channel;

import com.arima.ssh.client.ClientSession;
import com.arima.ssh.common.SshBuffer;
import com.arima.ssh.common.SshConstants;
import com.arima.ssh.common.channel.Channel;
import com.arima.ssh.common.channel.ChannelManager;
import com.arima.ssh.common.channel.RemoteTcpIpChannel;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

public class ClientChannelManager extends ChannelManager {

    private final ClientSession clientSession;
    private final ConcurrentMap<String, String> remoteTcpIpMap = new ConcurrentHashMap<>();

    public ClientChannelManager(ClientSession session) {
        super(session);
        this.clientSession = session;
    }

    public void registerRemoteTcpIp(String bindAddress, int bindPort, String targetHost, int targetPort) {
        String key = bindAddress + ":" + bindPort;
        String val = targetHost + ":" + targetPort;
        remoteTcpIpMap.put(key, val);
        logger.info("Registered remote forwarding: {} -> {}", key, val);
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

        if ("forwarded-tcpip".equals(type)) {

            String connectedHost = buffer.readString();
            long connectedPort = buffer.readUInt32();
            String originatorAddr = buffer.readString();
            long originatorPort = buffer.readUInt32();

            String targetKey = connectedHost + ":" + connectedPort;
            String targetVal = remoteTcpIpMap.get(targetKey);

            if (targetVal == null) {
                logger.error("No target registered for remote forwarding on {}:{}", connectedHost, connectedPort);
                SshBuffer reply = new SshBuffer();
                reply.writeByte(SshConstants.SSH_MSG_CHANNEL_OPEN_FAILURE);
                reply.writeUInt32(senderChannel);
                reply.writeUInt32(SshConstants.SSH_OPEN_ADMINISTRATIVELY_PROHIBITED);
                reply.writeString("No forwarding registered for " + connectedHost + ":" + connectedPort);
                reply.writeString("");
                return reply.getCompactData();
            }

            String[] parts = targetVal.split(":");
            String targetAddr = parts[0];
            int targetPort = Integer.parseInt(parts[1]);

            try {
                channel = new RemoteTcpIpChannel(targetAddr, targetPort, originatorAddr, originatorPort);
            } catch (Exception e) {
                logger.error("Error creating RemoteTcpIpChannel: ", e);
                SshBuffer reply = new SshBuffer();
                reply.writeByte(SshConstants.SSH_MSG_CHANNEL_OPEN_FAILURE);
                reply.writeUInt32(senderChannel);
                reply.writeUInt32(SshConstants.SSH_OPEN_CONNECT_FAILED);
                reply.writeString("Failed to connect to " + targetAddr + ":" + targetPort);
                reply.writeString("");
                return reply.getCompactData();
            }

        } else {

            logger.warn("Server requested unsupported channel type: {}", type);
            SshBuffer reply = new SshBuffer();
            reply.writeByte(SshConstants.SSH_MSG_CHANNEL_OPEN_FAILURE);
            reply.writeUInt32(senderChannel);
            reply.writeUInt32(SshConstants.SSH_OPEN_UNKNOWN_CHANNEL_TYPE);
            reply.writeString("Unsupported channel type: " + type);
            reply.writeString("");
            return reply.getCompactData();
        }

        long myId = registerChannel(channel);
        channel.init(clientSession, myId, senderChannel, initialWindow, maxPacket);

        SshBuffer reply = new SshBuffer();
        reply.writeByte(SshConstants.SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
        reply.writeUInt32(senderChannel);
        reply.writeUInt32(myId);
        reply.writeUInt32(2 * 1024 * 1024);
        reply.writeUInt32(32 * 1024);

        logger.info("Channel opened: id {}, type={}, senderChannel={}", myId, type, senderChannel);

        return reply.getCompactData();
    }
}
