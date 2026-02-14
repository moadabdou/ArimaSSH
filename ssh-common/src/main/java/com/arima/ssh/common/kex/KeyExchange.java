package com.arima.ssh.common.kex;

import java.math.BigInteger;

public interface KeyExchange {
    
    /**.
     * Generates the random Private Key (x) and calculates the Public Key (e).
     */
    void init();

    BigInteger getP();
    BigInteger getG();

    /**
     * @return My Public Key (e) to send to the other party.
     */
    byte[] getPublicKey();

    /**
     * @param otherKey The bytes received from the network.
     * @return The calculated Shared Secret (K).
     */
    BigInteger computeSharedSecret(byte[] otherKey);
    
    /**
     * @return The hashing algorithm used by this method (e.g., "SHA-1").
     */
    String getHashAlgorithm();
}