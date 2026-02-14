package com.arima.ssh.common.kex;

import java.math.BigInteger;
import java.security.SecureRandom;

public class DhGroup_SHA256 implements KeyExchange, DhGroup14 {

    
    private static final BigInteger P = G14_P;
    private static final BigInteger G = G14_G;

    private BigInteger x; // Private Key (Random)
    private BigInteger e; // Public Key = g^x mod p
    private BigInteger K; // The Shared Secret

    public DhGroup_SHA256(BigInteger p, BigInteger g) {

        if (p == null && g == null) {
            p = G14_P;
            g = G14_G;
            return;
        }

        throw new IllegalArgumentException("Custom p and g parameters are not supported in this implementation");

    }


    @Override
    public void init() {

        SecureRandom random = new SecureRandom();
        this.x = new BigInteger(2048, random);
        
        this.e = G.modPow(x, P);

    }

    @Override
    public byte[] getPublicKey() {

        return e.toByteArray();

    }

    @Override
    public BigInteger computeSharedSecret(byte[] otherKeyBytes) {

        BigInteger f = new BigInteger(otherKeyBytes);
        
        // Safety Check (RFC 4253): Public key must be in range [1, p-1]
        if (f.compareTo(BigInteger.ONE) <= 0 || f.compareTo(P.subtract(BigInteger.ONE)) >= 0) {
            throw new IllegalArgumentException("Invalid public key received");
        }

        this.K = f.modPow(x, P);
        
        return this.K;
    }
    
    @Override
    public String getHashAlgorithm() {
        return "SHA-256";
    }

    @Override
    public BigInteger getP() {
        return P;
    }

    @Override
    public BigInteger getG() {
        return G;   
    }

    
}
