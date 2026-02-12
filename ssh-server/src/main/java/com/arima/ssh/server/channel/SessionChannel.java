package com.arima.ssh.server.channel;


import java.util.HashMap;
import java.util.Map;

import com.arima.ssh.common.SshBuffer;
import com.arima.ssh.server.ServerSession;

public class SessionChannel implements Channel {
    
    private long id;
    private long remoteId;
    private long remoteWindow;
    private long remoteMaxPacket;
    private String term;
    private long termCols;
    private long termRows;
    private long termWidth;
    private long termHeight;
    private byte[] terminalModes;

    private final Map<String, String> environment = new HashMap<>();


    private ServerSession session;

    private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(SessionChannel.class);

    @Override
    public void init(ServerSession session, long id, long remoteId, long remoteWindow, long remoteMaxPacket) {
        this.session = session;
        this.id = id;
        this.remoteId = remoteId;
        this.remoteWindow = remoteWindow;
        this.remoteMaxPacket = remoteMaxPacket;
    }

    @Override
    public boolean handleRequest(String type, boolean wantReply, SshBuffer buffer){

        if ("pty-req".equals(type)) {

            this.term = buffer.readString();
            this.termCols = buffer.readUInt32();
            this.termRows = buffer.readUInt32();
            this.termWidth = buffer.readUInt32();
            this.termHeight = buffer.readUInt32();
            this.terminalModes = buffer.readByteString(); 

            logger.info("PTY Request: term={}, cols={}, rows={}, width={}, height={}", 
                term, termCols, termRows, termWidth, termHeight);

            return true;

        }else if ("env".equals(type)){

            String name = buffer.readString(); 
            String value = buffer.readString(); 
            environment.put(name, value); 
            logger.info("Environment variable set: {}={}", name, value); 
            
            return true;

        }

        logger.warn("Unsupported channel request type: {}", type);

        return false; // Unsupported request

    }

    @Override
    public long getChannelId() { return id; }

    @Override
    public long getRemoteId() { return remoteId; }


    public Map<String, String> getEnvironment() {
        return environment;
    }
}