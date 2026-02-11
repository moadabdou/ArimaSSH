package com.arima.ssh.common.crypto;

import com.arima.ssh.common.SshBuffer;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.math.BigInteger;

public class SshKeyDecoder {

    public static PublicKey decodePublicKey(byte[] blob) throws Exception {
        SshBuffer buffer = new SshBuffer(blob);
        
        // The blob starts with the algorithm name 
        String algo = buffer.readString();
        
        if ("ssh-rsa".equals(algo)) {
            BigInteger e = buffer.readMpint();
            BigInteger n = buffer.readMpint();
            
            RSAPublicKeySpec spec = new RSAPublicKeySpec(n, e);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(spec);
        }else if ("ssh-ed25519".equals(algo)) {
            // Ed25519 keys are 32 bytes of public key data after the algo name
            byte[] keyData = buffer.readByteString();
            if (keyData.length != 32) {
                throw new IllegalArgumentException("Invalid ed25519 key length: " + keyData.length);
            }
            // Java's Ed25519 PublicKey is just the raw 32 bytes
            KeyFactory kf = KeyFactory.getInstance("Ed25519");
            return kf.generatePublic(new java.security.spec.X509EncodedKeySpec(encodeEd25519PublicKey(keyData)));
        }
        
        throw new IllegalArgumentException("Unsupported key type: " + algo);
    }
    
    private static byte[] encodeEd25519PublicKey(byte[] keyData) {
        // Ed25519 public key encoding: 0x302a300506032b6570032100 + 32 bytes of key data
        byte[] header = new byte[] {
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00
        };
        byte[] encoded = new byte[header.length + keyData.length];
        System.arraycopy(header, 0, encoded, 0, header.length);
        System.arraycopy(keyData, 0, encoded, header.length, keyData.length);
        return encoded;
    }
}