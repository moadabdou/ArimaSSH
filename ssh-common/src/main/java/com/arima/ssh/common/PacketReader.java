package com.arima.ssh.common;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * This class will read packets according to the SSH spec.
 * It will read from an InputStream, parse the packet length and padding,
 * and return a clean SshBuffer containing just the payload for further processing.
*/

public class PacketReader {

    private int lastPacketLength = 0;
    private int lastPaddingLength = 0;
    private final DataInputStream in;

    public PacketReader(InputStream inputStream) {

        this.in = new DataInputStream(inputStream);

    }

    public int getLastPacketLength() {
        return lastPacketLength;
    }

    public int getLastPaddingLength() {
        return lastPaddingLength;
    }

    public SshBuffer readPacket() throws IOException, SshBufferException {
        
        int packetLength = in.readInt();
        this.lastPacketLength = packetLength;

         int paddingLength = in.readByte() & 0xFF; // Convert to unsigned
         this.lastPaddingLength = paddingLength;
        
        if (packetLength > 35000 || packetLength < 1) {
            throw new SshBufferException("Packet length out of bounds: " + packetLength);
        }

        int payloadLength = packetLength - paddingLength - 1;
        
        if (payloadLength < 0) {
             throw new SshBufferException("Invalid packet: Padding length exceeds packet length");
        }

        byte[] payload = new byte[payloadLength];
        in.readFully(payload);

        return new SshBuffer(payload);

    }
}

