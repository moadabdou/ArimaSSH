package com.arima.ssh.server.channel;


import java.util.HashMap;
import java.util.Map;

import com.arima.ssh.common.SshBuffer;
import com.arima.ssh.server.ServerSession;
import com.pty4j.PtyProcess;
import com.pty4j.PtyProcessBuilder;
import com.pty4j.WinSize;
import com.pty4j.unix.Pty;

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

    private PtyProcess shellProcess;

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

        }else if("shell".equals(type)){

            logger.info("Starting shell for channel {}", id); 

            try {

                String[] command;

                if (System.getProperty("os.name").toLowerCase().contains("win")) {
                    // Windows: Use PowerShell or Cmd
                    command = new String[]{"powershell.exe"}; 
                } else {
                    // Linux/Mac: Use Login Shell (bash -l or zsh -l)
                    String shell = System.getenv("SHELL");
                    if (shell == null || shell.isEmpty()) {
                        shell = "/bin/bash";
                    }
                    command = new String[]{shell, "-l"};
                }
                Map<String, String> env = new HashMap<>(System.getenv());
                env.putAll(this.environment);
                

                if (this.term != null) {
                    env.put("TERM", this.term);
                } else {
                    env.put("TERM", "xterm-256color"); // Fallback
                }


                this.shellProcess = new PtyProcessBuilder(command)
                        .setEnvironment(env)
                        .start();

                
                if (termCols > 0 && termRows > 0) {
                    this.shellProcess.setWinSize(new WinSize((int) termCols, (int) termRows));
                }

                logger.info("Shell started for channel {}: PID={}, command={}", id, shellProcess.pid(), String.join(" ", command));

                return true;

            } catch (Exception e) {
                logger.error("Failed to start shell for channel " + id, e);
                return false;
            }

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