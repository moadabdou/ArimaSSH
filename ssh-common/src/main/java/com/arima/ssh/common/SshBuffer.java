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

    //--- HELPER METHODS ---

    public void reset() {
        rpos = 0;
        wpos = 0;
    }

    public int available() {
        return wpos - rpos;
    }

    // Get current read position
    public int rpos() {
        return rpos;
    }

    // Move read position safely
    public void rpos(int rpos) {
        if (rpos < 0 || rpos > wpos) {
            throw new SshBufferException("Invalid read position: " + rpos + " (must be 0.." + wpos + ")");
        }
        this.rpos = rpos;
    }

    // Get current write position
    public int wpos() {
        return wpos;
    }

    // Move write position safely (expanding buffer if needed)
    public void wpos(int wpos) {
        if (wpos < 0) {
            throw new SshBufferException("Invalid write position: " + wpos);
        }
        // Expand if extending beyond current capacity
        if (wpos > data.length) {
            ensureCapacity(wpos - this.wpos);
        }
        // If we moved wpos back, we should probably ensure rpos isn't beyond it
        if (wpos < rpos) {
            rpos = wpos;
        }
        this.wpos = wpos;
    }

    public void compact() {
        if (rpos > 0) {
            int len = available();
            System.arraycopy(data, rpos, data, 0, len);
            wpos = len;
            rpos = 0;
        }
    }


    // --- READING METHODS ---

    public byte readByte() {
        if (available() < 1) {
            throw new SshBufferUnderflowException("Underflow: cannot read byte");
        }
        return data[rpos++];
    }

    public boolean readBoolean() {
        return readByte() != 0;
    }

    public long readUInt32() {
        if (available() < 4) {
            throw new SshBufferUnderflowException("Underflow: cannot read uint32");
        }
        int res = 0;
        res |= (readByte() & 0xFF) << 24;
        res |= (readByte() & 0xFF) << 16;
        res |= (readByte() & 0xFF) << 8;
        res |= (readByte() & 0xFF);
        
        return res & 0xFFFFFFFFL; 
    }

    public String readString() {
        int length = (int) readUInt32(); // First 4 bytes tell us the length
        if (length < 0) {
             throw new SshBufferException("Invalid string length: " + length);
        }
        if (available() < length) {
            throw new SshBufferUnderflowException("Underflow: cannot read string of length " + length);
        }
        String s = new String(data, rpos, length, StandardCharsets.UTF_8);
        rpos += length;
        return s;
    }
    
    // Used for Crypto Keys (BigInteger)
    public BigInteger readMpint() {
        int length = (int) readUInt32();
        if (length < 0) {
             throw new SshBufferException("Invalid mpint length: " + length);
        }
        if (available() < length) {
             throw new SshBufferUnderflowException("Underflow: cannot read mpint of length " + length);
        }
        byte[] bytes = new byte[length];
        System.arraycopy(data, rpos, bytes, 0, length);
        rpos += length;
        return new BigInteger(bytes);
    }

    public byte[] readBytes(int length) {
        if (length < 0) {
             throw new SshBufferException("Invalid byte array length: " + length);
        }
        if (available() < length) {
            throw new SshBufferUnderflowException("Underflow: cannot read " + length + " bytes");
        }
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

    public void writeBytes(byte[] bytes, int offset, int length) {
        if (bytes == null) {
            throw new SshBufferException("Cannot write null byte array");
        }
        if (offset < 0 || length < 0 || offset + length > bytes.length) {
            throw new SshBufferException("Invalid offset/length for byte array");
        }
        ensureCapacity(length);
        System.arraycopy(bytes, offset, data, wpos, length);
        wpos += length;
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
        if (s == null) {
            throw new SshBufferException("Cannot write null string");
        }
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