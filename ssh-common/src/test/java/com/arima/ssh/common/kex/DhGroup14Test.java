package com.arima.ssh.common.kex;

import org.junit.jupiter.api.Test;
import java.math.BigInteger;
import static org.junit.jupiter.api.Assertions.*;

class DhGroup14Test {

    @Test
    void testKeyExchange() {
        // 1. Setup Alice (Client)
        DhGroup14_SHA1 alice = new DhGroup14_SHA1();
        alice.init();
        byte[] alicePublic = alice.getPublicKey();

        // 2. Setup Bob (Server)
        DhGroup14_SHA1 bob = new DhGroup14_SHA1();
        bob.init();
        byte[] bobPublic = bob.getPublicKey();

        // 3. Exchange!
        // Alice takes Bob's public key
        BigInteger secretAlice = alice.computeSharedSecret(bobPublic);
        
        // Bob takes Alice's public key
        BigInteger secretBob = bob.computeSharedSecret(alicePublic);

        // 4. Verification
        System.out.println("Alice's Secret: " + secretAlice.toString(16).substring(0, 20) + "...");
        System.out.println("Bob's Secret:   " + secretBob.toString(16).substring(0, 20) + "...");

        assertEquals(secretAlice, secretBob, "The shared secrets MUST match!");
    }
}