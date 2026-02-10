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
        // For example, the initial IV for the client is HASH(K || H || "A" || session_id)
        // The initial IV for the server is HASH(K || H || "B" || session_id)
        // The encryption key for the client is HASH(K || H || "C" || session_id)
        // The encryption key for the server is HASH(K || H || "D" || session_id)
        // The integrity key for the client is HASH(K || H || "E" || session_id)
        // The integrity key for the server is HASH(K || H || "F" || session_id)

        SshBuffer buffer = new SshBuffer();
        buffer.writeMpint(K);
        buffer.writeByteString(H, 0, H.length);
        buffer.writeByte(discriminator);
        buffer.writeByteString(sessionId, 0, sessionId.length);

        digest.reset();
        byte[] result = digest.digest(buffer.getCompactData());

        SshBuffer keyBuffer = new SshBuffer();
        keyBuffer.writeBytes(result, 0, result.length);


        while(keyBuffer.available() < keyLength) {
            // If the required key length is longer than the hash output, we need to hash again with K and H and the previous result
            buffer.reset();
            buffer.writeMpint(K);
            buffer.writeByteString(H, 0, H.length);
            buffer.writeByteString(result, 0, result.length);

            digest.reset();
            result = digest.digest(buffer.getCompactData());

            keyBuffer.writeBytes(result, 0, result.length);
        }


        byte[] finalKey = new byte[keyLength];
        System.arraycopy(keyBuffer.getCompactData(), 0, finalKey, 0, keyLength);
        return finalKey;
    }


}
