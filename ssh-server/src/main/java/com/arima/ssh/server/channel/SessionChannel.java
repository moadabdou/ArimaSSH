package com.arima.ssh.server.channel;


import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;

import com.arima.ssh.common.SshBuffer;
import com.arima.ssh.common.SshConstants;
import com.arima.ssh.server.ServerSession;
import com.arima.ssh.server.subsystem.SftpSubsystem;
import com.pty4j.PtyProcess;
import com.pty4j.PtyProcessBuilder;
import com.pty4j.WinSize;

public class SessionChannel implements Channel {
    
    private long id;
    private long remoteId;
    private long remoteWindow;
    private long remoteMaxPacket;
    private ServerSession session;

    private final Object lock = new Object();

    private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(SessionChannel.class);


    private String term;
    private long termCols;
    private long termRows;
    private long termWidth;
    private long termHeight;
    @SuppressWarnings("unused")
    private byte[] terminalModes;

    private final Map<String, String> environment = new HashMap<>();

    private Process shellProcess;
    private SftpSubsystem sftpSubsystem;


    @Override
    public void init(ServerSession session, long id, long remoteId, long remoteWindow, long remoteMaxPacket) {
        this.session = session;
        this.id = id;
        this.remoteId = remoteId;
        this.remoteWindow = remoteWindow;
        this.remoteMaxPacket = remoteMaxPacket;
    }

    public long getRemoteMaxPacket() {
        return remoteMaxPacket;
    }

    @Override
    public boolean handleRequest(String type, SshBuffer buffer){

        if ("pty-req".equals(type)) {

            this.term = buffer.readString(); // Terminal type (e.g., "xterm-256color")
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


                PtyProcess process = new PtyProcessBuilder(command)
                        .setEnvironment(env)
                        .start();

                
                if (termCols > 0 && termRows > 0) {
                    process.setWinSize(new WinSize((int) termCols, (int) termRows));
                }

                this.shellProcess = process;

                logger.info("Shell started for channel {}: PID={}, command={}", id, shellProcess.pid(), String.join(" ", command));

                // Send colored banner through the PTY channel (bypasses OpenSSH's banner sanitization)
                if (session.getServer().getBannerProvider() != null) {
                    try {
                        byte[] bannerBytes = session.getServer().getBannerProvider().getBanner()
                                .getBytes(java.nio.charset.StandardCharsets.UTF_8);
                        waitForWindow(bannerBytes.length);
                        SshBuffer bannerData = new SshBuffer();
                        bannerData.writeByte(SshConstants.SSH_MSG_CHANNEL_DATA);
                        bannerData.writeUInt32(remoteId);
                        bannerData.writeByteString(bannerBytes, 0, bannerBytes.length);
                        session.sendPacket(bannerData);
                    } catch (Exception e) {
                        logger.error("Failed to send banner through channel {}: {}", id, e.getMessage());
                    }
                }

                // Start pumping data from the shell to the client
                startPump();   

                return true;

            } catch (Exception e) {
                logger.error("Failed to start shell for channel " + id, e);
                return false;
            }

        }else if ("exec".equals(type)){

            String commandString = buffer.readString();
            logger.info("Exec request for channel {}: command={}", id, commandString);

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
                    command = new String[]{shell, "-c", commandString};
                }

                Map<String, String> env = new HashMap<>(System.getenv());
                env.putAll(this.environment);
                
                if (term != null) {

                    env.put("TERM", this.term != null ? this.term : "xterm-256color");

                    PtyProcess process  = new PtyProcessBuilder(command)
                        .setEnvironment(env)
                        .start();

                    if (termCols > 0 && termRows > 0) {
                        process.setWinSize(new WinSize((int) termCols, (int) termRows));
                    }

                    this.shellProcess = process;

                    logger.info("Exec process using shell started for channel {}: PID={}, command={}", id, shellProcess.pid(), command);


                }else {

                    ProcessBuilder pb = new ProcessBuilder(command);
                    pb.environment().putAll(this.environment);
                    pb.redirectErrorStream(true); 

                    this.shellProcess = pb.start();

                    logger.info("Exec process using process builder started for channel {}: PID={}, command={}", id, shellProcess.pid(), command);

                }

                startPump();  

                return true;

            } catch (Exception e) {
                logger.error("Failed to execute command for channel " + id, e);
                return false;
            }

        }else if ("window-change".equals(type)) {

            int newCols = (int)buffer.readUInt32();
            int newRows = (int)buffer.readUInt32();
            buffer.readUInt32();
            buffer.readUInt32();

            logger.info("Window resized to {}x{}", newCols, newRows);

            if (this.shellProcess instanceof PtyProcess) {
                PtyProcess pty = (PtyProcess) this.shellProcess;
                
                pty.setWinSize(new WinSize(newCols, newRows));
            }
            
            return true;
        }else if ("subsystem".equals(type)) {

            String subsystemName = buffer.readString();
            logger.info("Subsystem request for channel {}: subsystem={}", id, subsystemName);

            if ("sftp".equals(subsystemName)) {
                this.sftpSubsystem = new SftpSubsystem(this);
                return true;
            } else {
                logger.warn("Unsupported subsystem requested: {}", subsystemName);
                return false;
            }

        }

        logger.warn("Unsupported channel request type: {}", type);

        return false; // Unsupported request

    }

    @Override
    public void handleData(byte[] data) {


        if (sftpSubsystem != null) {
            sftpSubsystem.handleInput(data);
            return;
        }

        if (shellProcess != null && shellProcess.isAlive() ) {
            try {
                shellProcess.getOutputStream().write(data);
                shellProcess.getOutputStream().flush();
            } catch (IOException e) {
                logger.error("Failed to write data to shell process for channel " + id, e);
            }  
        } else {
            logger.warn("Received data for channel {} but shell process is not started", id);
        }

    }

    @Override
    public void close() {

        if (sftpSubsystem != null) {
            sftpSubsystem.close();
        }

        if (shellProcess != null) {
            logger.info("Destroying shell process for channel {}: PID={}", id, shellProcess.pid());
            shellProcess.destroy();
            try {
                shellProcess.waitFor();
                logger.info("Shell process for channel {} exited with code {}", id, shellProcess.exitValue());
            } catch (InterruptedException e) {
                logger.error("Interrupted while waiting for shell process to exit for channel " + id, e);
            }
        }
    }

    @Override
    public long getChannelId() { return id; }

    @Override
    public long getRemoteId() { return remoteId; }


    @Override 
    public ServerSession getSession() {
        return session;
    }

    @Override
    public void handleWindowAdjust(long bytesToAdd) {
        synchronized (lock) {
            remoteWindow += bytesToAdd;
            logger.info("Window adjusted +{}. New size: {}", bytesToAdd, remoteWindow);
            lock.notifyAll();
        }
    }

    public void startPump() {
        new Thread( ()->{
            try (InputStream shellOut = shellProcess.getInputStream()) {
                byte[] buffer = new byte[(int)remoteMaxPacket];
                int read;
                while ((read = shellOut.read(buffer)) != -1) {
                    if (read > 0) {

                        try{ 
                            
                            waitForWindow((int)read); // Ensure we have window space is enough for the data we want to send

                        } catch (InterruptedException e) {
                            logger.error("Interrupted while waiting for window space for channel " + id, e);
                            Thread.currentThread().interrupt();
                            break;
                        }

                        SshBuffer sshBuffer = new SshBuffer();
                        sshBuffer.writeByte(SshConstants.SSH_MSG_CHANNEL_DATA);
                        sshBuffer.writeUInt32(remoteId); // Recipient Channel
                        sshBuffer.writeByteString(buffer, 0, read); // Data

                        session.sendPacket(sshBuffer);
                    }
                }
            } catch (IOException e) {
                logger.error("Error pumping data for channel " + id, e);
            } finally {
                try {

                    sendEof();

                    if (!shellProcess.isAlive()) {
                        int exitCode = shellProcess.exitValue();
                        sendExitStatus(exitCode);
                    }

                    sendClose();
                } catch (IOException e) {
                    logger.error("Error sending EOF/Close for channel " + id, e);
                }
            }
        }, "SessionChannel-Pump-" + id).start();

    }


    private void waitForWindow(int len) throws InterruptedException {
        synchronized (lock) {
            while (remoteWindow < len) {
                logger.info("Window exhausted ({} < {}). Waiting...", remoteWindow, len);
                lock.wait(); // Blocks here until 'handleWindowAdjust' wakes us up
            }
            remoteWindow -= len;
        }
    }


    private void sendEof() throws IOException {
        logger.info("Sending EOF for channel {}", id);
        SshBuffer buffer = new SshBuffer();
        buffer.writeByte(SshConstants.SSH_MSG_CHANNEL_EOF);
        buffer.writeUInt32(this.remoteId);
        session.sendPacket(buffer);
    }

    private void sendExitStatus(int exitCode) throws IOException {
        logger.info("Sending exit status {} for channel {}", exitCode, id);
        SshBuffer buffer = new SshBuffer();
        buffer.writeByte(SshConstants.SSH_MSG_CHANNEL_REQUEST);
        buffer.writeUInt32(this.remoteId);
        buffer.writeString("exit-status");
        buffer.writeBoolean(false);
        buffer.writeUInt32(exitCode); 
        session.sendPacket(buffer);
    }

    private void sendClose() throws IOException {
        logger.info("Sending close for channel {}", id);
        SshBuffer buffer = new SshBuffer();
        buffer.writeByte(SshConstants.SSH_MSG_CHANNEL_CLOSE);
        buffer.writeUInt32(this.remoteId);
        session.sendPacket(buffer);
        close(); // Ensure we clean up resources 
    }


    public Map<String, String> getEnvironment() {
        return environment;
    }
}