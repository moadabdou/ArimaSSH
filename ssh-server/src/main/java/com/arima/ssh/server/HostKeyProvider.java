package com.arima.ssh.server;

import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.RSAPrivateKey;

import com.arima.ssh.common.SshBuffer;


public class HostKeyProvider {
    
    private KeyPair hostKeyPair;

    public void init() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048); 
        hostKeyPair = keyGen.generateKeyPair();
    }

    // Get the public key blob to send to the client during KEX, according to RFC 4253 section 6.6

    public byte[] getPublicKeyBlob() {

        RSAPublicKey publicKey = (RSAPublicKey) hostKeyPair.getPublic();

        // Fblob : "ssh-rsa" || e || n

        // "ssh-rsa" did not change in the new RFCs, so we can hardcode it here.

        SshBuffer buffer = new SshBuffer();
        buffer.writeString("ssh-rsa");
        buffer.writeMpint(publicKey.getPublicExponent());
        buffer.writeMpint(publicKey.getModulus());

        return buffer.getCompactData();
    }


    // calculate the signature of the given data using the host private key, and return the signature blob

    public byte[] sign(byte[] data, String algoName) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {

        Signature signature = Signature.getInstance(mapSshToJava(algoName));
        signature.initSign((RSAPrivateKey) hostKeyPair.getPrivate());
        signature.update(data);

        byte[] rawSignature = signature.sign();


        // RFC 8332 : the signature blob is a string containing the name of the signature algorithm, 
        // followed by a string containing the raw signature bytes 
        // (without the SSH header that some Java libraries add, 
        // which is just an ASN.1 structure wrapping the raw signature)

        SshBuffer buffer = new SshBuffer();
        buffer.writeString(algoName);
        buffer.writeByteString(rawSignature, 0, rawSignature.length);

        return buffer.getCompactData();
    }    

    // mapper from SSH signature algorithm names to Java Signature algorithm names, for use in the sign() method above

    private String mapSshToJava(String sshName) {
        switch (sshName) {
            case "ssh-rsa":
                return "SHA1withRSA";
            case "rsa-sha2-256":
                return "SHA256withRSA";
            case "rsa-sha2-512":
                return "SHA512withRSA";
            default:
                throw new IllegalArgumentException("Unsupported signature algorithm: " + sshName);
        }
    }


}
