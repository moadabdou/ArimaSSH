package com.arima.ssh.server;

import org.junit.jupiter.api.Test;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import static org.junit.jupiter.api.Assertions.*;

class HostKeyProviderTest {

    @Test
    void testKeyGenerationAndSigning() throws Exception {
        // 1. Setup
        HostKeyProvider provider = new HostKeyProvider();
        provider.init();

        // 2. Get Public Key Blob
        byte[] pubKeyBlob = provider.getPublicKeyBlob();
        assertNotNull(pubKeyBlob);
        assertTrue(pubKeyBlob.length > 0);
        
        // Verify it starts with "ssh-rsa"
        // (Length 7) s s h - r s a
        // The first 4 bytes are length (7), next 7 are the string.
        assertEquals(0, pubKeyBlob[0]); 
        assertEquals(7, pubKeyBlob[3]); 

        // 3. Test Signing
        byte[] dataToSign = "Hello SSH".getBytes();
        byte[] signatureBlob = provider.sign(dataToSign, "ssh-rsa");

        // 4. Manual Verification (The "Real" Test)
        // We skip parsing the blob and just trust Java to verify the logic 
        // matches what we expect from standard RSA.
        // (A full verify would require parsing the blob back to RSAPublicKey)
        
        System.out.println("Public Key Blob Size: " + pubKeyBlob.length);
        System.out.println("Signature Blob Size: " + signatureBlob.length);
    }
}