package com.arima.ssh.client.channel;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import org.jline.terminal.Attributes;
import org.jline.terminal.Size;
import org.jline.terminal.Terminal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.arima.ssh.client.ClientSession;
import com.arima.ssh.common.SshBuffer;
import com.arima.ssh.common.SshConstants;
import com.arima.ssh.common.channel.AbstractChannel;
import com.arima.ssh.common.channel.Session;

public class SessionChannel extends AbstractChannel {

    private static final Logger logger = LoggerFactory.getLogger(SessionChannel.class);

    private final ClientSession clientSession;

    private final Map<String, Object> envVariables = new HashMap<>();

    private final String execCommand;

    private Thread pumpThread;

    private long exitStatus = -1;

    private boolean ptyAvailable = false;

    /** Saved terminal attributes so we can restore them on close. */
    private Attributes savedAttributes;


    public SessionChannel(ClientSession clientSession, Map<String, Object> envVariables, String execCommand) {
        this.createdAtMillis = System.currentTimeMillis();
        this.clientSession = clientSession;
        this.execCommand = execCommand;
        if (envVariables != null) {
            this.envVariables.putAll(envVariables);
        }
    }

    public Map<String, Object> getEnvVariables() {
        return envVariables;
    }


    @Override
    public void init(Session session, long channelId, long remoteId, long remoteWindow, long remoteMaxPacket) {

        super.init(session, channelId, remoteId, remoteWindow, remoteMaxPacket);
        logger.info("[SessionChannel ch#{}] INITIALIZED: localId={}, remoteId={}, remoteWindow={}, remoteMaxPacket={}",
            id, channelId, remoteId, remoteWindow, remoteMaxPacket);

        if (!envVariables.isEmpty()) {
            logger.info("[SessionChannel ch#{}] Sending {} environment variable(s)", id, envVariables.size());
            for (Map.Entry<String, Object> entry : envVariables.entrySet()) {
                sendEnvironmentVariable(entry.getKey(), String.valueOf(entry.getValue()));
            }
        }

        if (execCommand != null) {
            logger.info("[SessionChannel ch#{}] Exec mode: sending exec request for '{}'", id, execCommand);
            sendExecRequest(execCommand);
        } else if (!ptyAvailable) {
            sendPtyRequest();
        } else {
            sendShellRequest();
        }
    }


    private void sendPtyRequest() {

        Terminal terminal = clientSession.getTerminal();

        String term = terminal.getType();
        if (term == null || term.isEmpty()) {
            term = "xterm-256color";
        }
        Size size = terminal.getSize();
        long termCols = size.getColumns();
        long termRows = size.getRows();
        long termWidth = 0;
        long termHeight = 0;
        byte[] termModes = encodeTerminalModes(terminal);

        SshBuffer buffer = new SshBuffer();
        buffer.writeByte(SshConstants.SSH_MSG_CHANNEL_REQUEST);
        buffer.writeUInt32(remoteId);
        buffer.writeString("pty-req");
        buffer.writeBoolean(true);
        buffer.writeString(term);
        buffer.writeUInt32(termCols);
        buffer.writeUInt32(termRows);
        buffer.writeUInt32(termWidth);
        buffer.writeUInt32(termHeight);
        buffer.writeByteString(termModes, 0, termModes.length);

        try {
            session.sendPacket(buffer);
            logger.info("[SessionChannel ch#{}] Sent PTY request: term={}, cols={}, rows={}", id, term, termCols, termRows);
        } catch (IOException e) {
            logger.error("[SessionChannel ch#{}] Failed to send PTY request", id, e);
        }
    }

    private void sendShellRequest() {

        SshBuffer buffer = new SshBuffer();
        buffer.writeByte(SshConstants.SSH_MSG_CHANNEL_REQUEST);
        buffer.writeUInt32(remoteId);
        buffer.writeString("shell");
        buffer.writeBoolean(true);

        try {
            session.sendPacket(buffer);
            logger.info("[SessionChannel ch#{}] Sent shell request to server", id);
        } catch (IOException e) {
            logger.error("[SessionChannel ch#{}] Failed to send shell request", id, e);
        }
    }


    private void sendExecRequest(String command) {

        SshBuffer buffer = new SshBuffer();
        buffer.writeByte(SshConstants.SSH_MSG_CHANNEL_REQUEST);
        buffer.writeUInt32(remoteId);
        buffer.writeString("exec");
        buffer.writeBoolean(false);
        buffer.writeString(command);

        try {
            session.sendPacket(buffer);
            logger.info("[SessionChannel ch#{}] Sent exec request: command='{}'", id, command);
        } catch (IOException e) {
            logger.error("[SessionChannel ch#{}] Failed to send exec request for command '{}'", id, command, e);
        }
    }

    private void sendEnvironmentVariable(String name, String value) {

        SshBuffer buffer = new SshBuffer();
        buffer.writeByte(SshConstants.SSH_MSG_CHANNEL_REQUEST);
        buffer.writeUInt32(remoteId);
        buffer.writeString("env");
        buffer.writeBoolean(false);
        buffer.writeString(name);
        buffer.writeString(value);

        try {
            session.sendPacket(buffer);
            logger.debug("[SessionChannel ch#{}] Sent env: {}={}", id, name, value);
        } catch (IOException e) {
            logger.error("[SessionChannel ch#{}] Failed to send env {}={}", id, name, value, e);
        }
    }

    @Override
    public void handleChannleReplay(byte Type) {

        boolean success = (Type == SshConstants.SSH_MSG_CHANNEL_SUCCESS);

        if (execCommand != null) {

            if (success) {
                logger.info("[SessionChannel ch#{}] Exec request accepted, starting pump", id);
                startPump();
            } else {
                logger.error("[SessionChannel ch#{}] Exec request REJECTED by server", id);
            }

        } else if (!ptyAvailable) {

            if (success) {
                ptyAvailable = true;
                logger.info("[SessionChannel ch#{}] PTY request accepted, sending shell request", id);
                sendShellRequest();
            } else {
                logger.error("[SessionChannel ch#{}] PTY request REJECTED by server", id);
            }

        } else if (pumpThread == null) {

            if (success) {
                logger.info("[SessionChannel ch#{}] Shell request accepted, starting pump", id);
                startPump();
            } else {
                logger.error("[SessionChannel ch#{}] Shell request REJECTED by server", id);
            }

        } else {
            logger.debug("[SessionChannel ch#{}] Reply received (success={}) but no pending request to match", id, success);
        }
    }

    /**
     * Maps an ASCII control character to its RFC 4254 signal name,
     * or {@code null} if the character is not a well-known signal character.
     */
    private static String controlCharToSignal(int ch) {
        return switch (ch) {
            case 3  -> "INT";   // Ctrl+C  → SIGINT
            case 26 -> "TSTP";  // Ctrl+Z  → SIGTSTP
            case 28 -> "QUIT";  // Ctrl+\  → SIGQUIT
            default -> null;
        };
    }

    /**
     * Encodes the local terminal's control-character settings as an
     * RFC 4254 §8 "encoded terminal modes" byte array for the pty-req.
     * This tells the remote PTY which bytes map to SIGINT, SIGQUIT, etc.
     */
    private byte[] encodeTerminalModes(Terminal terminal) {

        // RFC 4254 §8 opcodes for each control character
        final byte VINTR    =  1;
        final byte VQUIT    =  2;
        final byte VERASE   =  3;
        final byte VKILL    =  4;
        final byte VEOF     =  5;
        final byte VEOL     =  6;
        final byte VEOL2    =  7;
        final byte VSTART   =  8;
        final byte VSTOP    =  9;
        final byte VSUSP    = 10;
        final byte VREPRINT = 12;
        final byte VWERASE  = 13;
        final byte VLNEXT   = 14;
        final byte TTY_OP_END = 0;

        Attributes attr = terminal.getAttributes();
        SshBuffer modes = new SshBuffer();

        // Helper: write opcode (1 byte) + value (uint32)
        writeMode(modes, VINTR,    attr.getControlChar(Attributes.ControlChar.VINTR));
        writeMode(modes, VQUIT,    attr.getControlChar(Attributes.ControlChar.VQUIT));
        writeMode(modes, VERASE,   attr.getControlChar(Attributes.ControlChar.VERASE));
        writeMode(modes, VKILL,    attr.getControlChar(Attributes.ControlChar.VKILL));
        writeMode(modes, VEOF,     attr.getControlChar(Attributes.ControlChar.VEOF));
        writeMode(modes, VEOL,     attr.getControlChar(Attributes.ControlChar.VEOL));
        writeMode(modes, VEOL2,    attr.getControlChar(Attributes.ControlChar.VEOL2));
        writeMode(modes, VSTART,   attr.getControlChar(Attributes.ControlChar.VSTART));
        writeMode(modes, VSTOP,    attr.getControlChar(Attributes.ControlChar.VSTOP));
        writeMode(modes, VSUSP,    attr.getControlChar(Attributes.ControlChar.VSUSP));
        writeMode(modes, VREPRINT, attr.getControlChar(Attributes.ControlChar.VREPRINT));
        writeMode(modes, VWERASE,  attr.getControlChar(Attributes.ControlChar.VWERASE));
        writeMode(modes, VLNEXT,   attr.getControlChar(Attributes.ControlChar.VLNEXT));

        modes.writeByte(TTY_OP_END);

        return modes.getCompactData();
    }

    private static void writeMode(SshBuffer buf, byte opcode, int value) {
        buf.writeByte(opcode);
        buf.writeUInt32(value);
    }

    /**
     * Sends a "signal" channel request (RFC 4254 §6.9) to the remote side.
     * Used to forward Ctrl+C (INT), Ctrl+\ (QUIT), etc.
     */
    private void sendSignal(String signalName) {
        SshBuffer buffer = new SshBuffer();
        buffer.writeByte(SshConstants.SSH_MSG_CHANNEL_REQUEST);
        buffer.writeUInt32(remoteId);
        buffer.writeString("signal");
        buffer.writeBoolean(false);
        buffer.writeString(signalName);

        try {
            session.sendPacket(buffer);
            logger.debug("[SessionChannel ch#{}] Sent signal '{}' to remote", id, signalName);
        } catch (IOException e) {
            logger.error("[SessionChannel ch#{}] Failed to send signal '{}'", id, signalName, e);
        }
    }

    /**
     * Sends a "window-change" channel request (RFC 4254 §6.7) to the remote side.
     */
    private void sendWindowChange(int cols, int rows) {
        SshBuffer buffer = new SshBuffer();
        buffer.writeByte(SshConstants.SSH_MSG_CHANNEL_REQUEST);
        buffer.writeUInt32(remoteId);
        buffer.writeString("window-change");
        buffer.writeBoolean(false);
        buffer.writeUInt32(cols);
        buffer.writeUInt32(rows);
        buffer.writeUInt32(0); // pixel width
        buffer.writeUInt32(0); // pixel height

        try {
            session.sendPacket(buffer);
            logger.debug("[SessionChannel ch#{}] Sent window-change: cols={}, rows={}", id, cols, rows);
        } catch (IOException e) {
            logger.error("[SessionChannel ch#{}] Failed to send window-change", id, e);
        }
    }

    private void startPump() {
        pumpThread = new Thread(() -> {

            Terminal terminal = clientSession.getTerminal();

            // WINCH is OS-generated (not keystroke-generated), so this
            // handler fires reliably even with ISIG disabled.
            terminal.handle(Terminal.Signal.WINCH, sig -> {
                Size size = terminal.getSize();
                logger.debug("[SessionChannel ch#{}] Terminal resized to {}x{}", id, size.getColumns(), size.getRows());
                sendWindowChange(size.getColumns(), size.getRows());
            });

            try {
                savedAttributes = terminal.enterRawMode();

                // JLine's enterRawMode() does NOT disable ISIG, so the OS
                // would still convert Ctrl+C/Ctrl+Z/Ctrl+\ into signals
                // instead of delivering the raw bytes to our reader.
                // Disable ISIG explicitly so every control character arrives
                // as a normal byte that we can forward to the remote side.
                Attributes attr = terminal.getAttributes();
                attr.setLocalFlag(Attributes.LocalFlag.ISIG, false);
                terminal.setAttributes(attr);

                logger.debug("[SessionChannel ch#{}] Terminal entered raw mode (ISIG disabled)", id);

                while (!closed) {

                    int ch = terminal.reader().read();

                    if (ch == -1) {
                        logger.info("[SessionChannel ch#{}] Terminal input EOF, sending EOF to server", id);
                        sendEof();
                        break;
                    }

                    // In raw mode with ISIG disabled, control characters
                    // (Ctrl+C, Ctrl+Z, Ctrl+\) arrive as plain bytes.
                    // For non-PTY sessions (exec) there is no remote PTY to
                    // interpret them, so we send an explicit SSH signal
                    // message (RFC 4254 §6.9) instead of the raw byte.
                    if (execCommand != null) {
                        String signal = controlCharToSignal(ch);
                        if (signal != null) {
                            sendSignal(signal);
                            continue;
                        }
                    }

                    // For PTY sessions the raw byte goes to the remote PTY
                    // which has the terminal modes we sent in pty-req and
                    // will raise the appropriate signal on the server side.
                    byte[] data = new byte[]{(byte) ch};

                    waitForWindow(data.length);
                    sendData(data, 1);
                }

            } catch (Exception e) {
                if (!closed) {
                    logger.error("[SessionChannel ch#{}] Pump thread error: {}", id, e.getMessage(), e);
                    try {
                        sendEof();
                        sendClose();
                    } catch (Exception ex) {
                        logger.error("[SessionChannel ch#{}] Failed to send EOF/close after pump error", id, ex);
                    }
                }
            } finally {
                restoreTerminal();
            }

        }, "SessionChannel-Pump-ch#" + id);

        pumpThread.start();
    }

    private void restoreTerminal() {
        try {
            Terminal terminal = clientSession.getTerminal();
            if (savedAttributes != null) {
                terminal.setAttributes(savedAttributes);
                savedAttributes = null;
                logger.debug("[SessionChannel ch#{}] Terminal attributes restored", id);
            }
        } catch (Exception e) {
            logger.warn("[SessionChannel ch#{}] Failed to restore terminal attributes: {}", id, e.getMessage());
        }
    }

    @Override
    public boolean handleRequest(String type, SshBuffer buffer) {

        if ("exit-status".equals(type)) {
            exitStatus = buffer.readUInt32();
            logger.info("Received exit status from server: {}", exitStatus);
            return true;
        }

        return false;
    }

    @Override
    public void handleData(byte[] data) {

        Terminal terminal = clientSession.getTerminal();

        if (terminal != null) {
            try {
                terminal.output().write(data);
                terminal.output().flush();
            } catch (Exception e) {
                logger.error("[SessionChannel ch#{}] Failed to write {} bytes to terminal", id, data.length, e);
            }
        } else {
            logger.warn("[SessionChannel ch#{}] Received {} bytes but terminal is null", id, data.length);
        }
    }

    @Override
    public void handleEof() {
        logger.info("[SessionChannel ch#{}] Received EOF from server", id);
    }

    @Override
    protected void doClose() {
        restoreTerminal();

        if (pumpThread != null && pumpThread.isAlive()) {
            pumpThread.interrupt();
            logger.debug("[SessionChannel ch#{}] Pump thread interrupted", id);
        }

        if (exitStatus >= 0) {
            logger.info("[SessionChannel ch#{}] Session ended with exit status {}", id, exitStatus);
        }

    }

}

