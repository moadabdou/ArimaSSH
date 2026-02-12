package com.arima.ssh.common;

import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.SecureRandom;

import com.arima.ssh.common.crypto.SshCipher;
import com.arima.ssh.common.crypto.SshMac;

/**
 * Thread-safe packet writer. Accepts a fully-built SshBuffer payload
 * and handles framing, encryption, MAC, and writing atomically.
 */
public class PacketWriter {

    private final DataOutputStream out;
    private final SecureRandom random;
    private long sequenceNumber = 0;

    private SshCipher cipher;
    private SshMac mac;

    public PacketWriter(OutputStream out) {
        this.out = (out != null) ? new DataOutputStream(out) : null;
        this.random = new SecureRandom();
    }

    /**
     * Frames, encrypts, MACs, and writes the payload atomically.
     * The caller builds the payload (message type + fields) in a thread-local SshBuffer.
     */
    public synchronized void writePacket(SshBuffer payload) throws IOException {
        if (out == null) {
            throw new SshBufferException("Output stream not set for PacketWriter");
        }

        byte[] payloadBytes = payload.getCompactData();
        int payloadLength = payloadBytes.length;

        int blockSize = 8;
        if (cipher != null) {
            blockSize = Math.max(8, cipher.getBlockSize());
        }

        int paddingLength = blockSize - ((payloadLength + 5) % blockSize);
        if (paddingLength < 4) {
            paddingLength += blockSize;
        }

        int packetLength = 1 + payloadLength + paddingLength;

        if (packetLength + 4 > 35000) {
            throw new SshBufferException("Packet too large: " + (packetLength + 4) + " bytes (max 35000)");
        }

        // Build frame: [packet_length(4)] [padding_length(1)] [payload] [random_padding]
        SshBuffer frame = new SshBuffer();
        frame.writeUInt32(packetLength);
        frame.writeByte((byte) paddingLength);
        frame.writeBytes(payloadBytes, 0, payloadLength);

        byte[] padding = new byte[paddingLength];
        random.nextBytes(padding);
        frame.writeBytes(padding, 0, padding.length);

        byte[] frameBytes = frame.getCompactData();

        // MAC on unencrypted frame (RFC 4253)
        byte[] macBytes = null;
        if (mac != null) {
            macBytes = mac.calculate(sequenceNumber, frameBytes);
        }

        // Encrypt frame (not the MAC)
        if (cipher != null) {
            try {
                byte[] encrypted = new byte[frameBytes.length];
                cipher.transform(frameBytes, 0, frameBytes.length, encrypted, 0);
                frameBytes = encrypted;
            } catch (javax.crypto.ShortBufferException e) {
                throw new IOException("Encryption failed", e);
            }
        }

        out.write(frameBytes);
        if (macBytes != null) {
            out.write(macBytes);
        }
        out.flush();

        sequenceNumber++;
    }

    public long getSequenceNumber() {
        return sequenceNumber;
    }

    public synchronized void setCipher(SshCipher cipher) {
        this.cipher = cipher;
    }

    public synchronized void setMac(SshMac mac) {
        this.mac = mac;
    }
}