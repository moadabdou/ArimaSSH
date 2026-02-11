package com.arima.ssh.common;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;

import javax.crypto.Cipher;
import javax.crypto.ShortBufferException;

import com.arima.ssh.common.crypto.SshCipher;

/**
 * This class will read packets according to the SSH spec.
 * It will read from an InputStream, parse the packet length and padding,
 * and return a clean SshBuffer containing just the payload for further processing.
*/

public class PacketReader {

    private long lastPacketLength = 0;
    private long lastPaddingLength = 0;
    private final DataInputStream in;

    private SshCipher cipher;
    private long sequenceNumber = 0;


    public PacketReader(InputStream inputStream) {

        this.in = new DataInputStream(inputStream);

    }

    public void setCipher(SshCipher cipher) {
        this.cipher = cipher;
    }

    public long getLastPacketLength() {
        return lastPacketLength;
    }

    public long getLastPaddingLength() {
        return lastPaddingLength;
    }

    public SshBuffer readPacket() throws IOException, SshBufferException, ShortBufferException {
        
        byte[] packetLengthBuffer = new byte[4];

        in.readFully(packetLengthBuffer);

        if (cipher != null) {
            byte[] decryptedLength = new byte[4];
            cipher.transform(packetLengthBuffer, 0, 4, decryptedLength, 0);
            packetLengthBuffer = decryptedLength;
        }

        long packetLength = ((packetLengthBuffer[0] & 0xFF) << 24) |
                          ((packetLengthBuffer[1] & 0xFF) << 16) |
                          ((packetLengthBuffer[2] & 0xFF) << 8) |
                          (packetLengthBuffer[3] & 0xFF);

        this.lastPacketLength = packetLength;

        if (packetLength > 35000 || packetLength < 1) {
            throw new SshBufferException("Packet length out of bounds: " + packetLength);
        }

        byte[] paddingLengthByte = new byte[1];
        in.readFully(paddingLengthByte);

        if (cipher != null) {
            byte[] decryptedPaddingLength = new byte[1];
            cipher.transform(paddingLengthByte, 0, 1, decryptedPaddingLength, 0);
            paddingLengthByte = decryptedPaddingLength;
        }

        int paddingLength = paddingLengthByte[0] & 0xFF; // Convert to unsigned
        this.lastPaddingLength = paddingLength;
       

        int payloadLength = (int)packetLength - paddingLength - 1;
        
        if (payloadLength < 0) {
             throw new SshBufferException("Invalid packet: Padding length exceeds packet length");
        }

        byte[] payload = new byte[payloadLength];

        in.readFully(payload);

        if (cipher != null) {
            byte[] decryptedPayload = new byte[payloadLength];
            cipher.transform(payload, 0, payloadLength, decryptedPayload, 0);
            payload = decryptedPayload;
        }

        // Consume the padding and ignore it
        byte[] padding = new byte[paddingLength];
        in.readFully(padding);

        if (cipher != null) {
            byte[] decryptedPadding = new byte[paddingLength];
            cipher.transform(padding, 0, paddingLength, decryptedPadding, 0);
            // We ignore the content of padding but we MUST decrypt it to keep cipher state in sync
            // aka : update the KetStream counter for the padding bytes
        }

        return new SshBuffer(payload);

    }
}

