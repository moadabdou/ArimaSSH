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
        
        Signature verifier = Signature.getInstance(SignatureUtils.mapSshAlgoToJava(algo));
        verifier.initVerify(key);
        verifier.update(data);
        return verifier.verify(rawSig);
    }
}