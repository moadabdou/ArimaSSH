package com.arima.ssh.server.channel;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;

import com.arima.ssh.common.SshBuffer;
import com.arima.ssh.common.SshConstants;
import com.arima.ssh.common.channel.AbstractChannel;
import com.arima.ssh.common.channel.Session;
import com.arima.ssh.server.ServerSession;
import com.arima.ssh.server.subsystem.SftpSubsystem;
import com.pty4j.PtyProcess;
import com.pty4j.PtyProcessBuilder;
import com.pty4j.WinSize;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SessionChannel extends AbstractChannel {

    private static final Logger logger = LoggerFactory.getLogger(SessionChannel.class);

    private final ServerSession serverSession;

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

    public SessionChannel(ServerSession serverSession) {
        this.serverSession = serverSession;
    }

    @Override
    public void init(Session session, long channelId, long remoteId, long remoteWindow, long remoteMaxPacket) {
        super.init(session, channelId, remoteId, remoteWindow, remoteMaxPacket);
        logger.info("[SessionChannel ch#{}] INITIALIZED: localId={}, remoteId={}, remoteWindow={}, remoteMaxPacket={}",
            id, channelId, remoteId, remoteWindow, remoteMaxPacket);
    }

    public ServerSession getServerSession() {
        return serverSession;
    }

    public SftpSubsystem getSftpSubsystem() {
        return sftpSubsystem;
    }

    @Override
    public boolean handleRequest(String type, SshBuffer buffer) {

        if ("pty-req".equals(type)) {

            this.term = buffer.readString();
            this.termCols = buffer.readUInt32();
            this.termRows = buffer.readUInt32();
            this.termWidth = buffer.readUInt32();
            this.termHeight = buffer.readUInt32();
            this.terminalModes = buffer.readByteString();

            logger.info("[SessionChannel ch#{}] PTY_REQ: term={}, cols={}, rows={}, width={}, height={}",
                id, term, termCols, termRows, termWidth, termHeight);

            return true;

        } else if ("env".equals(type)) {

            String name = buffer.readString();
            String value = buffer.readString();
            environment.put(name, value);
            logger.debug("[SessionChannel ch#{}] ENV: {}={}", id, name, value);

            return true;

        } else if ("shell".equals(type)) {

            logger.info("[SessionChannel ch#{}] Starting shell", id);

            try {

                String[] command;

                if (System.getProperty("os.name").toLowerCase().contains("win")) {
                    command = new String[]{"powershell.exe"};
                } else {
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
                    env.put("TERM", "xterm-256color");
                }

                PtyProcess process = new PtyProcessBuilder(command)
                        .setEnvironment(env)
                        .start();

                if (termCols > 0 && termRows > 0) {
                    process.setWinSize(new WinSize((int) termCols, (int) termRows));
                }

                this.shellProcess = process;

                logger.info("[SessionChannel ch#{}] Shell STARTED: PID={}, command={}", id, shellProcess.pid(), String.join(" ", command));

                // Send colored banner through the PTY channel
                if (serverSession.getServer().getBannerProvider() != null) {
                    try {
                        byte[] bannerBytes = serverSession.getServer().getBannerProvider().getBanner()
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

                startPump();

                return true;

            } catch (Exception e) {
                logger.error("[SessionChannel ch#{}] Failed to start shell: {}", id, e.getMessage(), e);
                return false;
            }

        } else if ("exec".equals(type)) {

            String commandString = buffer.readString();
            logger.info("[SessionChannel ch#{}] EXEC: command={}", id, commandString);

            try {

                String[] command;

                if (System.getProperty("os.name").toLowerCase().contains("win")) {
                    command = new String[]{"powershell.exe"};
                } else {
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

                    PtyProcess process = new PtyProcessBuilder(command)
                        .setEnvironment(env)
                        .start();

                    if (termCols > 0 && termRows > 0) {
                        process.setWinSize(new WinSize((int) termCols, (int) termRows));
                    }

                    this.shellProcess = process;

                    logger.info("[SessionChannel ch#{}] EXEC STARTED (pty): PID={}, command={}", id, shellProcess.pid(), String.join(" ", command));

                } else {

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

        } else if ("window-change".equals(type)) {

            int newCols = (int) buffer.readUInt32();
            int newRows = (int) buffer.readUInt32();
            buffer.readUInt32();
            buffer.readUInt32();

            logger.debug("[SessionChannel ch#{}] WINDOW_CHANGE: {}x{}", id, newCols, newRows);

            if (this.shellProcess instanceof PtyProcess) {
                PtyProcess pty = (PtyProcess) this.shellProcess;
                pty.setWinSize(new WinSize(newCols, newRows));
            }

            return true;

        } else if ("subsystem".equals(type)) {

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
        return false;
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
    public void handleEof() {
        logger.info("[SessionChannel ch#{}] EOF received from client, closing process stdin", id);

        if (sftpSubsystem != null) {
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

    public void startPump() {
        logger.info("[SessionChannel ch#{}] Starting data pump thread (maxPacket={})", id, remoteMaxPacket);

        this.pumpThread = new Thread(() -> {
            logger.debug("[SessionChannel ch#{}] Pump thread started", id);
            try (InputStream shellOut = shellProcess.getInputStream()) {
                byte[] buffer = new byte[(int) remoteMaxPacket];
                int read;
                while ((read = shellOut.read(buffer)) != -1) {
                    if (read > 0) {

                        long chunkNum = dataChunksSent.incrementAndGet();
                        long totalSent = totalBytesSent.addAndGet(read);

                        try {
                            waitForWindow(read);
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

    @Override
    protected void doClose() {
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
    }

    public Map<String, String> getEnvironment() {
        return environment;
    }
}
