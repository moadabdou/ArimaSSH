package com.arima.ssh.common.kex;

import java.security.MessageDigest;
import java.math.BigInteger;
import com.arima.ssh.common.SshBuffer;

public class KeyDerivation {
    
    private MessageDigest digest;


    public KeyDerivation(String hashAlgorithm) throws Exception {
        this.digest = MessageDigest.getInstance(hashAlgorithm);
    }


    public  byte[] calculateKey(BigInteger K, byte[] H, byte discriminator, byte[] sessionId, int keyLength) {
        // The SSH spec defines how to derive keys from K and H. 
        // key = HASH(K || H || discriminator || session_id)
        // where : discriminator is a single byte that differs for each key type (e.g., 'A' for client IV, 'B' for server IV, 'C' for client encryption key, etc.)
        // K : as MPINT (BigInteger) is encoded as a string of bytes with the most significant bit first, and a leading zero byte if the most significant bit is set (to avoid being interpreted as a negative number).
        // H : is the exchange hash, which is already a byte array.
        // session_id : is also a byte array.
        
        // For example, the initial IV for the client is HASH(K || H || "A" || session_id)
        // The initial IV for the server is HASH(K || H || "B" || session_id)
        // The encryption key for the client is HASH(K || H || "C" || session_id)
        // The encryption key for the server is HASH(K || H || "D" || session_id)
        // The integrity key for the client is HASH(K || H || "E" || session_id)
        // The integrity key for the server is HASH(K || H || "F" || session_id)

        SshBuffer buffer = new SshBuffer();
        buffer.writeMpint(K);
        buffer.writeBytes(H, 0, H.length);
        buffer.writeByte(discriminator);
        buffer.writeBytes(sessionId, 0, sessionId.length);

        digest.reset();
        byte[] result = digest.digest(buffer.getCompactData());

        SshBuffer keyBuffer = new SshBuffer();
        keyBuffer.writeBytes(result, 0, result.length);


        while(keyBuffer.available() < keyLength) {
            // If the required key length is longer than the hash output, we need to hash again with K and H and the previous result
            buffer.reset();
            buffer.writeMpint(K);
            buffer.writeBytes(H, 0, H.length);
            buffer.writeBytes(result, 0, result.length);

            digest.reset();
            result = digest.digest(buffer.getCompactData());

            keyBuffer.writeBytes(result, 0, result.length);
        }


        byte[] finalKey = new byte[keyLength];
        System.arraycopy(keyBuffer.getCompactData(), 0, finalKey, 0, keyLength);
        return finalKey;
    }


}
