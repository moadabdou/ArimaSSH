package com.arima.ssh.common;

import java.security.SecureRandom;

/**
 * This class will write packets according to the SSH spec. 
 * It will use SshBuffer internally to build the packet, 
 * and then provide a method to get the final byte array to send over the network.
 */
public class PacketWriter {

    private final SshBuffer buffer;
    private final SecureRandom random;
    private boolean built = false;

    public PacketWriter() {
        this.buffer = new SshBuffer();
        this.random = new SecureRandom();
        // The first 5 bytes are reserved for the packet length and padding length.
        this.buffer.wpos(5);
    }

    public PacketWriter(SshBuffer payload) {
        this();
        this.buffer.writeBytes(payload.getCompactData(), 0, payload.wpos());
    }

    //--- WRITING METHODS ---

    private void checkState() {
        if (built) {
            throw new SshBufferException("Packet already generated. Cannot write more data.");
        }
    }

    public void writeByte(byte b) {
        checkState();
        buffer.writeByte(b);
    }
    

    public void writeBoolean(boolean b) {
        checkState();
        buffer.writeBoolean(b);
    }

    public void writeUInt32(long value) {
        checkState();
        buffer.writeUInt32(value);
    }

    public void writeString(String s) {
        checkState();
        buffer.writeString(s);
    }
    
    // Get the final raw bytes to send over network
    public byte[] toByteArray() {
        if (built) {
             return buffer.getCompactData();
        }

        // First, we need to calculate the packet length and padding length
        int payloadLength = buffer.wpos() - 5; // Exclude the 5 bytes reserved
        int blockSize = 8; // SSH packets must be a multiple of the block size
        
        // RFC 4253: The total length of the packet (including the length field but not the MAC) 
        // MUST be a multiple of the cipher block size or 8, whichever is larger.
        // Formula: packet_length (4) + padding_length (1) + payload + padding % 8 == 0
        int paddingLength = blockSize - ((payloadLength + 5) % blockSize);
        
        // RFC 4253: The minimum size of the random padding is 4 bytes.
        if (paddingLength < 4) {
            paddingLength += blockSize;
        }

        int packetLength = 1 + payloadLength + paddingLength; // 1 byte for padding_length field

        // RFC 4253: Implementations MUST be able to process ... total packet size of 35000 bytes or less.
        if (packetLength + 4 > 35000) {
            throw new SshBufferException("Packet too large: " + (packetLength + 4) + " bytes (max 35000)");
        }

        // Now we can fill in the packet length and padding length at the beginning of the buffer
        int currentWpos = buffer.wpos();
        buffer.wpos(0);
        buffer.writeUInt32(packetLength);
        buffer.writeByte((byte) paddingLength);

        // Restore wpos to the end of the payload to append padding
        buffer.wpos(currentWpos);
        
        // Add random padding bytes
        // Using SecureRandom as per RFC recommendation for security (obfuscation)
        byte[] padding = new byte[paddingLength];
        random.nextBytes(padding);
        for (byte b : padding) {
            buffer.writeByte(b);
        }

        built = true;
        return buffer.getCompactData();
    }
}