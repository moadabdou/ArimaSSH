package com.arima.ssh.common;

import org.junit.jupiter.api.Test;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import static org.junit.jupiter.api.Assertions.*;

class PacketWriterTest {

    @Test
    void testWritePacketStructure() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PacketWriter writer = new PacketWriter(baos);

        SshBuffer payload = new SshBuffer();
        payload.writeString("Test");
        payload.writeBoolean(true);
        payload.writeUInt32(12345);

        writer.writePacket(payload);

        byte[] packet = baos.toByteArray();
        
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
    void testMultipleSends() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PacketWriter writer = new PacketWriter(baos);

        SshBuffer p1 = new SshBuffer();
        p1.writeString("First");
        writer.writePacket(p1);

        SshBuffer p2 = new SshBuffer();
        p2.writeString("Second");
        writer.writePacket(p2);

        assertEquals(2, writer.getSequenceNumber());
        assertTrue(baos.size() > 0);
    }
    
    @Test
    void testPacketSizeLimit() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PacketWriter writer = new PacketWriter(baos);

        SshBuffer payload = new SshBuffer();
        StringBuilder sb = new StringBuilder();
        for(int i=0; i<35000; i++) {
            sb.append("a");
        }
        payload.writeString(sb.toString());
        
        SshBufferException exception = assertThrows(SshBufferException.class, () -> writer.writePacket(payload));
        assertTrue(exception.getMessage().contains("Packet too large"));
    }
}