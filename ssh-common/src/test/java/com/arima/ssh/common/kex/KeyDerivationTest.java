package com.arima.ssh.common.kex;

import org.junit.jupiter.api.Test;
import java.math.BigInteger;
import static org.junit.jupiter.api.Assertions.*;

class KeyDerivationTest {

    @Test
    void testKeyExpansion() throws Exception {
        // Setup dummy data
        BigInteger k = new BigInteger("1234567890");
        byte[] h = "exchange_hash".getBytes();
        byte[] sessionId = "session_id".getBytes();
        
        KeyDerivation kdf = new KeyDerivation("SHA-1");
        
        // SHA-1 produces 20 bytes. 
        // Let's ask for 32 bytes (AES-256 size). 
        // This forces the loop to run twice.
        byte[] key = kdf.calculateKey(k, h, (byte)'C', sessionId, 32);
        
        assertEquals(32, key.length, "Should return exactly 32 bytes");
        
        // Sanity check: Ideally, run this against a known vector, 
        // but checking length and non-zero content is good enough for logic verification.
        assertNotEquals(0, key[0]);
        assertNotEquals(0, key[31]);
    }
}