package com.arima.ssh.common;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class SshBufferTest {

    @Test
    void testStringRoundTrip() {
        SshBuffer buffer = new SshBuffer();
        buffer.writeString("Hello Arima");
        
        // Simulate sending over network
        byte[] rawBytes = buffer.getCompactData();
        
        // Simulate receiving
        SshBuffer reader = new SshBuffer(rawBytes);
        String result = reader.readString();
        
        assertEquals("Hello Arima", result);
    }

    @Test
    void testUInt32() {
        SshBuffer buffer = new SshBuffer();
        long bigNumber = 3000000000L; // Bigger than standard Java int
        buffer.writeUInt32(bigNumber);
        
        SshBuffer reader = new SshBuffer(buffer.getCompactData());
        assertEquals(bigNumber, reader.readUInt32());
    }
}