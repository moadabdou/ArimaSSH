package com.arima.ssh.common.crypto;

import com.arima.ssh.common.SshBuffer;
import java.security.PublicKey;
import java.security.Signature;

public class SshSignatureVerifier {

    public static boolean verify(PublicKey key, byte[] data, byte[] signatureBlob) throws Exception {

        // The signature blob is: [string algo_name] [string signature_bytes]
        SshBuffer sigBuf = new SshBuffer(signatureBlob);
        String algo = sigBuf.readString(); 
        byte[] rawSig = sigBuf.readByteString(); // The actual signature bytes
        
        // Map SSH Algo -> Java Algo
        String javaAlgo;
        if ("ssh-rsa".equals(algo)) {
            javaAlgo = "SHA1withRSA";
        } else if ("rsa-sha2-256".equals(algo)) {
            javaAlgo = "SHA256withRSA";
        } else if ("rsa-sha2-512".equals(algo)) {
            javaAlgo = "SHA512withRSA";
        } else if ("ssh-ed25519".equals(algo)) {
            javaAlgo = "Ed25519";
        }else {
            throw new IllegalArgumentException("Unknown sig algo: " + algo);
        }
        
        Signature verifier = Signature.getInstance(javaAlgo);
        verifier.initVerify(key);
        verifier.update(data);
        return verifier.verify(rawSig);
    }
}