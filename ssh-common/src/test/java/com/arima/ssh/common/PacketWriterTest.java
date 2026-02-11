package com.arima.ssh.common;

import org.junit.jupiter.api.Test;
import java.nio.ByteBuffer;
import static org.junit.jupiter.api.Assertions.*;

class PacketWriterTest {

    @Test
    void testWritePacketStructure() throws Exception {
        PacketWriter writer = new PacketWriter(null);
        writer.writeString("Test");
        writer.writeBoolean(true);
        writer.writeUInt32(12345);
        
        byte[] packet = writer.toByteArray();
        
        // 1. Basic Checks
        assertNotNull(packet);
        assertTrue(packet.length > 5);
        assertTrue(packet.length % 8 == 0, "Packet length must be multiple of 8 (block size)");
        
        // 2. Parse it back manually to verify headers
        ByteBuffer buf = ByteBuffer.wrap(packet);
        int packetLength = buf.getInt();
        int paddingLength = buf.get() & 0xFF;
        
        // The total byte array size should represent:
        // [Packet Length Field (4 bytes)] + [Remained of Packet (packetLength bytes)]
        assertEquals(packet.length, packetLength + 4);
        
        // 3. Verify Payload size
        // We wrote: 
        // - String("Test"): 4 bytes len + 4 bytes text = 8 bytes
        // - Boolean: 1 byte
        // - UInt32: 4 bytes
        // Total expected payload = 13 bytes.
        
        // Formula: packetLength = 1 (padding_len field) + payload + padding
        // So: payload = packetLength - 1 - paddingLength
        int calculatedPayloadLength = packetLength - 1 - paddingLength;
        assertEquals(13, calculatedPayloadLength);
        
        // 4. Verify Padding
        assertTrue(paddingLength >= 4, "Padding must be at least 4 bytes as per RFC");
    }

    @Test
    void testWriteAfterBuilt() throws Exception {
        PacketWriter writer = new PacketWriter(null);
        writer.writeString("Data");
        writer.toByteArray(); // Finalizes the packet
        
        // Attempting to write more should fail
        assertThrows(SshBufferException.class, () -> writer.writeString("More"));
    }
    
    @Test
    void testPacketSizeLimit() {
        PacketWriter writer = new PacketWriter(null);
        
        // Create a string that pushes the packet over 35000 bytes
        // 35000 bytes max -> if we create a string of 34990, + 4 bytes header + padding etc it should fail
        StringBuilder sb = new StringBuilder();
        for(int i=0; i<35000; i++) {
            sb.append("a");
        }
        
        writer.writeString(sb.toString());
        
        SshBufferException exception = assertThrows(SshBufferException.class, () -> writer.toByteArray());
        assertTrue(exception.getMessage().contains("Packet too large"));
    }
}