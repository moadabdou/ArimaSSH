package com.arima.ssh.common.kex;

import java.math.BigInteger;
import java.security.SecureRandom;

public class DhGroup14_SHA1 implements KeyExchange {

    // RFC 3526: 2048-bit MODP Group
    private static final BigInteger P = new BigInteger(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
            "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
            "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
            "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
            "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
            "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
            "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
            "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
            "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
            "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
            "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16);


    private static final BigInteger G = BigInteger.valueOf(2);

    private BigInteger x; // Private Key (Random)
    private BigInteger e; // Public Key = g^x mod p
    private BigInteger K; // The Shared Secret

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
        if (f.compareTo(BigInteger.ONE) < 0 || f.compareTo(P) >= 0) {
            throw new IllegalArgumentException("Invalid public key received");
        }

        this.K = f.modPow(x, P);
        
        return this.K;
    }
    
    @Override
    public String getHashAlgorithm() {
        return "SHA-1";
    }
}