package com.arima.ssh.server;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;


import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.slf4j.LoggerFactory;

import java.security.interfaces.RSAPrivateKey;

import com.arima.ssh.common.SshBuffer;
import com.arima.ssh.common.kex.KexUtils;


public class HostKeyProvider {
    
    private KeyPair hostKeyPair;

    private Path hostKeyPath; 

    org.slf4j.Logger logger = LoggerFactory.getLogger(HostKeyProvider.class);

    public HostKeyProvider( Path hostKeyPath) {
        
        if (hostKeyPath != null) {
            this.hostKeyPath = hostKeyPath;
        } else {
            this.hostKeyPath = Path.of("arima_ssh/hostkey.pem"); // default path
        }
        this.hostKeyPath = hostKeyPath;
    }

    public void init() throws NoSuchAlgorithmException {

        if (Files.exists(hostKeyPath)) {
            this.hostKeyPair = readPemFile();
        } else {
            this.hostKeyPair = generateAndSave();
        }
        
    }


    private KeyPair readPemFile() {

        try (
            FileReader reader = new FileReader(hostKeyPath.toFile());
            PEMParser pemParser = new PEMParser(reader)
        ) {

            Object object = pemParser.readObject();

            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();

            if (object instanceof PEMKeyPair) {
                // PKCS#1 (Legacy "BEGIN RSA PRIVATE KEY")
                logger.info("Loading legacy PKCS#1 host key...");
                return converter.getKeyPair((PEMKeyPair) object);
            } 
            else if (object instanceof PrivateKeyInfo) {
                // PKCS#8 (Modern "BEGIN PRIVATE KEY")
                logger.info("Loading modern PKCS#8 host key...");
                PrivateKey privateKey = converter.getPrivateKey((PrivateKeyInfo) object);
                RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) privateKey;
                java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance("RSA");
                RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(
                    new RSAPublicKeySpec(rsaPrivateKey.getModulus(), java.math.BigInteger.valueOf(65537))
                );
                return new KeyPair(publicKey, privateKey);
            } 

            else {
                throw new IllegalArgumentException("Unknown PEM object type: " + object.getClass().getName());
            }

        } catch (Exception e) {
            throw new RuntimeException("Failed to load host key from " + hostKeyPath, e);
        }
    }

    private KeyPair generateAndSave() {

        logger.info("Host key not found at {}, generating new RSA host key...", hostKeyPath);

        try {

            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(2048);
            KeyPair keys = gen.generateKeyPair();

            try (FileWriter writer = new FileWriter(hostKeyPath.toFile());
                 JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
                pemWriter.writeObject(keys);
            }

            File file = hostKeyPath.toFile();
            if (file.setReadable(false, false) && file.setWritable(false, false)) {
                file.setReadable(true, true);  // Owner Read
                file.setWritable(true, true);  // Owner Write
            }

            logger.info("Generated new host key and saved to {}", hostKeyPath);
            return keys;

        } catch (Exception e) {
            throw new RuntimeException("Failed to generate/save host key", e);
        }
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

        Signature signature = Signature.getInstance(KexUtils.mapSshToJava(algoName));
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

}
