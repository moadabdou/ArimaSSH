package com.arima.ssh.common;

import org.junit.jupiter.api.Test;
import java.io.ByteArrayInputStream;
import java.io.IOException;

import javax.crypto.ShortBufferException;

import static org.junit.jupiter.api.Assertions.*;

class PacketIntegrationTest {

    @Test
    void testWriterReaderCoherence() throws IOException, SshBufferException, ShortBufferException{
        // 1. CREATE PACKET
        PacketWriter writer = new PacketWriter();
        
        String testString = "Integration Test";
        boolean testBool = true;
        long testUInt = 0xDEADBEEFL;
        byte testByte = 42;

        writer.writeString(testString);
        writer.writeBoolean(testBool);
        writer.writeUInt32(testUInt);
        writer.writeByte(testByte);

        byte[] packetBytes = writer.toByteArray();

        // 2. READ PACKET
        ByteArrayInputStream is = new ByteArrayInputStream(packetBytes);
        PacketReader reader = new PacketReader(is);
        
        SshBuffer buffer = reader.readPacket();

        // 3. VERIFY CONTENTS
        // The order must match the write order
        assertEquals(testString, buffer.readString(), "String mismatch");
        assertEquals(testBool, buffer.readBoolean(), "Boolean mismatch");
        assertEquals(testUInt, buffer.readUInt32(), "UInt32 mismatch");
        assertEquals(testByte, buffer.readByte(), "Byte mismatch");
        
        // 4. VERIFY METADATA
        // The packet length in the reader should match the writer's logic validation
        // Reader's lastPacketLength = packet bytes length - 4 (length field itself)
        assertEquals(packetBytes.length - 4, reader.getLastPacketLength(), "Packet length metadata mismatch");
        
        // Ensure padding was stripped and buffer is now at the end (or check available)
        // Note: The buffer returned by readPacket only contains the payload.
        // So valid bytes available should be effectively 0 now if we read everything.
        assertEquals(0, buffer.available(), "Buffer should be empty after reading all fields");
    }

    @Test
    void testEmptyPayloadCoherence() throws IOException, SshBufferException, ShortBufferException {
        PacketWriter writer = new PacketWriter();
        // No payload
        byte[] packetBytes = writer.toByteArray();

        ByteArrayInputStream is = new ByteArrayInputStream(packetBytes);
        PacketReader reader = new PacketReader(is);
        SshBuffer buffer = reader.readPacket();

        assertEquals(0, buffer.available(), "Payload should be empty");
    }
}
