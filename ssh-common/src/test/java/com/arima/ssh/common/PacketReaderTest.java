package com.arima.ssh.common;

import org.junit.jupiter.api.Test;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;

import javax.crypto.ShortBufferException;

import static org.junit.jupiter.api.Assertions.*;

class PacketReaderTest {

    @Test
    void testReadValidPacket() throws IOException, SshBufferException, ShortBufferException {
        // Construct a valid packet payload
        // Payload data: "Hello"
        // String encoding in SSH: 4 bytes length, then bytes.
        String testString = "Hello";
        byte[] rawString = testString.getBytes();
        int stringEncodingLength = 4 + rawString.length; 
        
        // Create the payload part manually
        ByteBuffer payloadBuf = ByteBuffer.allocate(stringEncodingLength);
        payloadBuf.putInt(rawString.length);
        payloadBuf.put(rawString);
        byte[] payloadData = payloadBuf.array();

        // Padding (Random bytes usually, here just zeros)
        int paddingLength = 4; // Minimum is 4
        byte[] padding = new byte[paddingLength];

        // Packet Length field value: 1 (padding_len size) + payloadSize + paddingLength
        int packetLengthVal = 1 + payloadData.length + paddingLength;
        
        // Full packet structure: [Packet Length (4)] [Padding Length (1)] [Payload] [Padding]
        ByteBuffer packetBuf = ByteBuffer.allocate(4 + 1 + payloadData.length + padding.length);
        packetBuf.putInt(packetLengthVal);
        packetBuf.put((byte) paddingLength);
        packetBuf.put(payloadData);
        packetBuf.put(padding);

        ByteArrayInputStream is = new ByteArrayInputStream(packetBuf.array());
        PacketReader reader = new PacketReader(is);
        
        // Perform the read
        SshBuffer resultBuffer = reader.readPacket();
        
        // Verification
        assertNotNull(resultBuffer);
        // The reader returns a buffer containing ONLY the payload
        assertEquals(testString, resultBuffer.readString());
        assertEquals(packetLengthVal, reader.getLastPacketLength());
        assertEquals(paddingLength, reader.getLastPaddingLength());
    }

    @Test
    void testPacketTooLarge() {
        // Max is 35000
        int invalidLength = 35001;
        ByteBuffer buf = ByteBuffer.allocate(5);
        buf.putInt(invalidLength); // Packet length
        
        ByteArrayInputStream is = new ByteArrayInputStream(buf.array());
        PacketReader reader = new PacketReader(is);
        
        SshBufferException exception = assertThrows(SshBufferException.class, () -> reader.readPacket());
        assertTrue(exception.getMessage().contains("Packet length out of bounds"));
    }

    @Test
    void testPaddingExceedsPacketLength() {
        // Packet Length = 5
        // Padding Length = 10 (invalid, impossible to fit)
        ByteBuffer buf = ByteBuffer.allocate(4 + 1);
        buf.putInt(5);     // Packet Length
        buf.put((byte) 10); // Padding Length
        
        ByteArrayInputStream is = new ByteArrayInputStream(buf.array());
        PacketReader reader = new PacketReader(is);
        
        SshBufferException exception = assertThrows(SshBufferException.class, () -> reader.readPacket());
        assertTrue(exception.getMessage().contains("Padding length exceeds packet length"));
    }
}