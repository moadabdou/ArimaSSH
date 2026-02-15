package com.arima.ssh.server.channel;


import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

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

    private Thread pumpThread;

    private volatile boolean eofSent = false;
    private volatile boolean closeSent = false;
    private volatile boolean closed = false;
    private long createdAtMillis;

    private final AtomicLong totalBytesReceived = new AtomicLong(0);
    private final AtomicLong totalBytesSent = new AtomicLong(0);
    private final AtomicLong dataChunksReceived = new AtomicLong(0);
    private final AtomicLong dataChunksSent = new AtomicLong(0);


    @Override
    public void init(ServerSession session, long id, long remoteId, long remoteWindow, long remoteMaxPacket) {
        this.session = session;
        this.id = id;
        this.remoteId = remoteId;
        this.remoteWindow = remoteWindow;
        this.remoteMaxPacket = remoteMaxPacket;
        this.createdAtMillis = System.currentTimeMillis();

        logger.info("[SessionChannel ch#{}] INITIALIZED: localId={}, remoteId={}, remoteWindow={}, remoteMaxPacket={}",
            id, id, remoteId, remoteWindow, remoteMaxPacket);
    }

    public long getRemoteMaxPacket() {
        return remoteMaxPacket;
    }

    public SftpSubsystem getSftpSubsystem() {
        return sftpSubsystem;
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

            logger.info("[SessionChannel ch#{}] PTY_REQ: term={}, cols={}, rows={}, width={}, height={}", 
                id, term, termCols, termRows, termWidth, termHeight);

            return true;

        }else if ("env".equals(type)){

            String name = buffer.readString(); 
            String value = buffer.readString(); 
            environment.put(name, value); 
            logger.debug("[SessionChannel ch#{}] ENV: {}={}", id, name, value); 
            
            return true;

        }else if("shell".equals(type)){

            logger.info("[SessionChannel ch#{}] Starting shell", id); 

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

                logger.info("[SessionChannel ch#{}] Shell STARTED: PID={}, command={}", id, shellProcess.pid(), String.join(" ", command));

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
                        logger.error("[SessionChannel ch#{}] Failed to send banner: {}", id, e.getMessage());
                    }
                }

                // Start pumping data from the shell to the client
                startPump();   

                return true;

            } catch (Exception e) {
                logger.error("[SessionChannel ch#{}] Failed to start shell: {}", id, e.getMessage(), e);
                return false;
            }

        }else if ("exec".equals(type)){

            String commandString = buffer.readString();
            logger.info("[SessionChannel ch#{}] EXEC: command={}", id, commandString);

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

                    logger.info("[SessionChannel ch#{}] EXEC STARTED (pty): PID={}, command={}", id, shellProcess.pid(), String.join(" ", command));


                }else {

                    ProcessBuilder pb = new ProcessBuilder(command);
                    pb.environment().putAll(this.environment);
                    pb.redirectErrorStream(true); 

                    this.shellProcess = pb.start();

                    logger.info("[SessionChannel ch#{}] EXEC STARTED (process): PID={}, command={}", id, shellProcess.pid(), String.join(" ", command));

                }

                startPump();  

                return true;

            } catch (Exception e) {
                logger.error("[SessionChannel ch#{}] EXEC FAILED: {}", id, e.getMessage(), e);
                return false;
            }

        }else if ("window-change".equals(type)) {

            int newCols = (int)buffer.readUInt32();
            int newRows = (int)buffer.readUInt32();
            buffer.readUInt32();
            buffer.readUInt32();

            logger.debug("[SessionChannel ch#{}] WINDOW_CHANGE: {}x{}", id, newCols, newRows);

            if (this.shellProcess instanceof PtyProcess) {
                PtyProcess pty = (PtyProcess) this.shellProcess;
                
                pty.setWinSize(new WinSize(newCols, newRows));
            }
            
            return true;
        }else if ("subsystem".equals(type)) {

            String subsystemName = buffer.readString();
            logger.info("[SessionChannel ch#{}] SUBSYSTEM: {}", id, subsystemName);

            if ("sftp".equals(subsystemName)) {
                this.sftpSubsystem = new SftpSubsystem(this);
                return true;
            } else {
                logger.warn("[SessionChannel ch#{}] Unsupported subsystem: {}", id, subsystemName);
                return false;
            }

        }

        logger.warn("[SessionChannel ch#{}] Unsupported request type: {}", id, type);

        return false; // Unsupported request

    }

    @Override
    public void handleData(byte[] data) {

        if (sftpSubsystem != null) {
            sftpSubsystem.handleInput(data);
            return;
        }

        long chunkNum = dataChunksReceived.incrementAndGet();
        long totalRecv = totalBytesReceived.addAndGet(data.length);

        if (shellProcess != null && shellProcess.isAlive()) {
            try {
                shellProcess.getOutputStream().write(data);
                shellProcess.getOutputStream().flush();
                logger.debug("[SessionChannel ch#{}] DATA_IN: chunk #{}, {} bytes (totalReceived={})", id, chunkNum, data.length, totalRecv);
            } catch (IOException e) {
                logger.error("[SessionChannel ch#{}] DATA_IN ERROR: failed to write {} bytes to process - {}", id, data.length, e.getMessage(), e);
            }
        } else {
            logger.warn("[SessionChannel ch#{}] DATA_IN DROPPED: process is {} (alive={}), {} bytes lost",
                id, shellProcess == null ? "null" : "present", shellProcess != null && shellProcess.isAlive(), data.length);
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
    public void handleEof() {
        logger.info("[SessionChannel ch#{}] EOF received from client, closing process stdin", id);

        if (sftpSubsystem != null){
            sftpSubsystem.handleEof();
        }

        if (shellProcess != null) {
            try {
                shellProcess.getOutputStream().close();
                logger.info("[SessionChannel ch#{}] Process stdin closed successfully", id);
            } catch (IOException e) {
                logger.error("[SessionChannel ch#{}] Error closing process stdin: {}", id, e.getMessage(), e);
            }
        } else {
            logger.debug("[SessionChannel ch#{}] Process is null when handling EOF", id);
        }
    }

    @Override
    public void handleWindowAdjust(long bytesToAdd) {
        synchronized (lock) {
            long oldWindow = remoteWindow;
            remoteWindow += bytesToAdd;
            logger.debug("[SessionChannel ch#{}] WINDOW_ADJUST: +{} bytes (window {} -> {})", id, bytesToAdd, oldWindow, remoteWindow);
            lock.notifyAll();
        }
    }

    public void startPump() {
        logger.info("[SessionChannel ch#{}] Starting data pump thread (maxPacket={})", id, remoteMaxPacket);

        this.pumpThread = new Thread( ()->{
            logger.debug("[SessionChannel ch#{}] Pump thread started", id);
            try (InputStream shellOut = shellProcess.getInputStream()) {
                byte[] buffer = new byte[(int)remoteMaxPacket];
                int read;
                while ((read = shellOut.read(buffer)) != -1) {
                    if (read > 0) {

                        long chunkNum = dataChunksSent.incrementAndGet();
                        long totalSent = totalBytesSent.addAndGet(read);

                        try{ 
                            waitForWindow((int)read);
                        } catch (InterruptedException e) {
                            logger.error("[SessionChannel ch#{}] Pump INTERRUPTED while waiting for window (chunk #{}, {} bytes pending)", id, chunkNum, read, e);
                            Thread.currentThread().interrupt();
                            break;
                        }

                        try {
                            sendData(buffer, read);
                            logger.debug("[SessionChannel ch#{}] Pump: sent chunk #{}, {} bytes to client (totalSent={})", id, chunkNum, read, totalSent);
                        } catch (IOException e) {
                            logger.error("[SessionChannel ch#{}] Pump ERROR sending data to client for chunk #{}: {} ({} bytes)", 
                                id, chunkNum, e.getMessage(), read, e);
                            break;
                        }
                    }
                }
                logger.info("[SessionChannel ch#{}] Pump: process EOF reached (stream ended normally)", id);
            } catch (IOException e) {
                logger.error("[SessionChannel ch#{}] Pump ERROR: {} (totalBytesSent={}, totalBytesReceived={})",
                    id, e.getMessage(), totalBytesSent.get(), totalBytesReceived.get(), e);
            } finally {
                logger.info("[SessionChannel ch#{}] Pump thread finishing, sending EOF and Close...", id);
                try {
                    sendEof();

                    // Wait for the process to exit so we can capture its exit code.
                    // The stream EOF (read returning -1) may arrive before the process
                    // has fully terminated, so isAlive() alone is racy.
                    if (shellProcess.waitFor(5, java.util.concurrent.TimeUnit.SECONDS)) {
                        int exitCode = shellProcess.exitValue();
                        sendExitStatus(exitCode);
                    } else {
                        logger.warn("[SessionChannel ch#{}] Process did not exit within timeout, sending exit code 1", id);
                        sendExitStatus(1);
                    }

                    sendClose();
                } catch (IOException e) {
                    logger.error("[SessionChannel ch#{}] Pump cleanup: failed to send EOF/Close: {}", id, e.getMessage(), e);
                } catch (InterruptedException e) {
                    logger.error("[SessionChannel ch#{}] Pump cleanup: interrupted while waiting for process exit", id, e);
                    Thread.currentThread().interrupt();
                }
                logger.info("[SessionChannel ch#{}] Pump thread TERMINATED (totalBytesSent={}, totalBytesReceived={})",
                    id, totalBytesSent.get(), totalBytesReceived.get());
            }
        }, "SessionChannel-Pump-" + id);
        
        pumpThread.start();
    }


    private void waitForWindow(int len) throws InterruptedException {
        synchronized (lock) {
            if (remoteWindow < len) {
                logger.debug("[SessionChannel ch#{}] WINDOW_WAIT: need {} bytes, available={}, blocking...", id, len, remoteWindow);
            }
            while (remoteWindow < len) {
                lock.wait();
            }
            remoteWindow -= len;
            logger.debug("[SessionChannel ch#{}] WINDOW_CONSUMED: {} bytes (remaining={})", id, len, remoteWindow);
        }
    }


    public void sendData(byte[] data, int length) throws IOException {
        if (closed) {
            logger.warn("[SessionChannel ch#{}] Attempt to send data after channel is closed, dropping {} bytes", id, length);
            return;
        }
        SshBuffer buffer = new SshBuffer();
        buffer.writeByte(SshConstants.SSH_MSG_CHANNEL_DATA);
        buffer.writeUInt32(remoteId);
        buffer.writeByteString(data, 0, length);
        session.sendPacket(buffer);
        totalBytesSent.addAndGet(length);
        dataChunksSent.incrementAndGet();
        logger.debug("[SessionChannel ch#{}] Sent {} bytes to client (totalSent={})", id, length, totalBytesSent.get());
    }

    public void sendEof() throws IOException {
        if (eofSent) {
            logger.debug("[SessionChannel ch#{}] EOF already sent, skipping duplicate", id);
            return;
        }
        eofSent = true;
        logger.info("[SessionChannel ch#{}] Sending SSH_MSG_CHANNEL_EOF to remote (remoteId={})", id, remoteId);
        SshBuffer buffer = new SshBuffer();
        buffer.writeByte(SshConstants.SSH_MSG_CHANNEL_EOF);
        buffer.writeUInt32(this.remoteId);
        session.sendPacket(buffer);
        logger.debug("[SessionChannel ch#{}] SSH_MSG_CHANNEL_EOF sent", id);
    }

    private void sendExitStatus(int exitCode) throws IOException {
        logger.info("[SessionChannel ch#{}] Sending EXIT_STATUS: exitCode={} (remoteId={})", id, exitCode, remoteId);
        SshBuffer buffer = new SshBuffer();
        buffer.writeByte(SshConstants.SSH_MSG_CHANNEL_REQUEST);
        buffer.writeUInt32(this.remoteId);
        buffer.writeString("exit-status");
        buffer.writeBoolean(false);
        buffer.writeUInt32(exitCode); 
        session.sendPacket(buffer);
    }

    public void sendClose() throws IOException {
        if (closeSent) {
            logger.debug("[SessionChannel ch#{}] CLOSE already sent, skipping duplicate", id);
            return;
        }
        closeSent = true;
        logger.info("[SessionChannel ch#{}] Sending SSH_MSG_CHANNEL_CLOSE to remote (remoteId={})", id, remoteId);
        SshBuffer buffer = new SshBuffer();
        buffer.writeByte(SshConstants.SSH_MSG_CHANNEL_CLOSE);
        buffer.writeUInt32(this.remoteId);
        session.sendPacket(buffer);
        logger.debug("[SessionChannel ch#{}] SSH_MSG_CHANNEL_CLOSE sent, cleaning up resources...", id);
        close();
    }

    @Override
    public void close() {
        if (closed) {
            logger.debug("[SessionChannel ch#{}] close() called but already closed, skipping", id);
            return;
        }
        
        closed = true;
        long uptimeMs = System.currentTimeMillis() - createdAtMillis;

        logger.info("[SessionChannel ch#{}] CLOSING channel (uptime={}ms)", id, uptimeMs);
        logger.info("[SessionChannel ch#{}] Final stats: bytesSentToClient={}, bytesReceivedFromClient={}, chunksSent={}, chunksReceived={}", 
            id, totalBytesSent.get(), totalBytesReceived.get(), dataChunksSent.get(), dataChunksReceived.get());

        if (sftpSubsystem != null) {
            sftpSubsystem.close();
        }

        if (shellProcess != null) {
            logger.info("[SessionChannel ch#{}] Destroying shell process: PID={}", id, shellProcess.pid());
            shellProcess.destroy();
            try {
                shellProcess.waitFor();
                logger.info("[SessionChannel ch#{}] Shell process exited with code {}", id, shellProcess.exitValue());
            } catch (InterruptedException e) {
                logger.error("[SessionChannel ch#{}] Interrupted while waiting for shell process to exit", id, e);
            }
        }

        logger.info("[SessionChannel ch#{}] Channel DESTROYED", id);
    }


    public Map<String, String> getEnvironment() {
        return environment;
    }
}