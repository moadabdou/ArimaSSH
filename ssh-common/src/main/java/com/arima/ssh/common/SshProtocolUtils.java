package com.arima.ssh.common;

import java.io.IOException;
import java.io.InputStream;

/**
 * Low-level SSH protocol helpers shared between client and server.
 */
public final class SshProtocolUtils {

    private SshProtocolUtils() {} // utility class


    /**
     * Reads a single line from a stream byte-by-byte (no buffering),
     * as required for the SSH version-string exchange (RFC 4253 §4.2).
     * Stops at {@code \n}, ignores {@code \r}, enforces a 255-byte limit
     * to prevent memory attacks.
     *
     * @param in the raw socket input stream
     * @return the line content (without CR/LF)
     * @throws IOException if the stream ends before a newline is found or the line exceeds 255 bytes
     */
    public static String readLine(InputStream in) throws IOException {
        StringBuilder sb = new StringBuilder();
        int b;
        while (sb.length() < 255 && (b = in.read()) != -1) {
            if (b == '\n') {
                return sb.toString();
            }
            if (b != '\r') {
                sb.append((char) b);
            }
        }
        throw new IOException("Stream ended or line too long before version received");
    }


    /**
     * Builds a SSH_MSG_DISCONNECT packet (RFC 4253 §11.1).
     *
     * @param reasonCode one of the {@code SSH_DISCONNECT_*} constants
     * @param message    human-readable description
     * @return an SshBuffer ready to be sent
     */
    public static SshBuffer buildDisconnectPacket(int reasonCode, String message) {
        SshBuffer buf = new SshBuffer();
        buf.writeByte(SshConstants.SSH_MSG_DISCONNECT);
        buf.writeUInt32(reasonCode);
        buf.writeString(message);
        buf.writeString(""); // language tag (unused)
        return buf;
    }
}
