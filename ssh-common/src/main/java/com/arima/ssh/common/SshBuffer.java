package com.arima.ssh.common;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class SshBuffer {

    private byte[] data;
    private int rpos = 0; // Read Position
    private int wpos = 0; // Write Position

    // Constructor for READING (wrapping incoming bytes)
    public SshBuffer(byte[] data) {
        this.data = data;
        this.wpos = data.length;
    }

    // Constructor for WRITING (creating a new packet)
    public SshBuffer() {
        this.data = new byte[256]; // Start small, grow as needed
    }

    // --- READING METHODS ---

    public byte readByte() {
        return data[rpos++];
    }

    public boolean readBoolean() {
        return readByte() != 0;
    }

    public long readUInt32() {
        int res = 0;
        res |= (readByte() & 0xFF) << 24;
        res |= (readByte() & 0xFF) << 16;
        res |= (readByte() & 0xFF) << 8;
        res |= (readByte() & 0xFF);
        
        return res & 0xFFFFFFFFL; 
    }

    public String readString() {
        int length = (int) readUInt32(); // First 4 bytes tell us the length
        String s = new String(data, rpos, length, StandardCharsets.UTF_8);
        rpos += length;
        return s;
    }
    
    // Used for Crypto Keys (BigInteger)
    public BigInteger readMpint() {
        int length = (int) readUInt32();
        byte[] bytes = new byte[length];
        System.arraycopy(data, rpos, bytes, 0, length);
        rpos += length;
        return new BigInteger(bytes);
    }

    public byte[] readBytes(int length) {
        byte[] b = new byte[length];
        System.arraycopy(data, rpos, b, 0, length);
        rpos += length;
        return b;
    }

    // --- WRITING METHODS ---
    
    public void ensureCapacity(int capacity) {
        if (data.length - wpos < capacity) {
            // Double the array size if we run out of space
            int newSize = Math.max(data.length * 2, wpos + capacity);
            data = Arrays.copyOf(data, newSize);
        }
    }

    public void writeByte(byte b) {
        ensureCapacity(1);
        data[wpos++] = b;
    }
    
    public void writeBoolean(boolean v) {
        writeByte(v ? (byte) 1 : (byte) 0);
    }

    public void writeUInt32(long v) {
        ensureCapacity(4);
        data[wpos++] = (byte) (v >> 24);
        data[wpos++] = (byte) (v >> 16);
        data[wpos++] = (byte) (v >> 8);
        data[wpos++] = (byte) (v);
    }

    public void writeString(String s) {
        byte[] bytes = s.getBytes(StandardCharsets.UTF_8);
        writeUInt32(bytes.length);
        ensureCapacity(bytes.length);
        System.arraycopy(bytes, 0, data, wpos, bytes.length);
        wpos += bytes.length;
    }

    // Get the final raw bytes to send over network
    public byte[] getCompactData() {
        return Arrays.copyOf(data, wpos);
    }
}