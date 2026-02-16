package com.arima.ssh.common.crypto;

import java.io.FileReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.util.OpenSSHPrivateKeyUtil;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PemUtils {

    private static final Logger logger = LoggerFactory.getLogger(PemUtils.class);

    private static final String OPENSSH_HEADER = "-----BEGIN OPENSSH PRIVATE KEY-----";

    public static KeyPair readPemFile(Path keyPath) {

        logger.info("Reading PEM file: {}", keyPath);

        try {
            // Peek at the file to detect OpenSSH format
            String content = Files.readString(keyPath);

            if (content.trim().startsWith(OPENSSH_HEADER)) {
                return readOpenSshKey(content);
            }

            return readStandardPem(keyPath);

        } catch (Exception e) {
            throw new RuntimeException("Failed to load host key from " + keyPath, e);
        }
    }

    /**
     * Parses OpenSSH private key format ("BEGIN OPENSSH PRIVATE KEY"),
     * the default format produced by modern ssh-keygen (Ed25519, ECDSA, etc.).
     */
    private static KeyPair readOpenSshKey(String pemContent) throws Exception {
        logger.info("Detected OpenSSH private key format");

        // Strip PEM headers and decode base64
        String base64 = pemContent
                .replace("-----BEGIN OPENSSH PRIVATE KEY-----", "")
                .replace("-----END OPENSSH PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        byte[] blob = Base64.getDecoder().decode(base64);

        // BouncyCastle parses the OpenSSH binary format
        AsymmetricKeyParameter privateKeyParams = OpenSSHPrivateKeyUtil.parsePrivateKeyBlob(blob);

        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");

        if (privateKeyParams instanceof Ed25519PrivateKeyParameters) {
            Ed25519PrivateKeyParameters ed25519Private = (Ed25519PrivateKeyParameters) privateKeyParams;

            // Convert BC params -> standard JCE KeyPair via PKCS#8 / X.509 encoding
            PrivateKeyInfo privInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(ed25519Private);
            var pubInfo = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(ed25519Private.generatePublicKey());

            PrivateKey privateKey = converter.getPrivateKey(privInfo);
            PublicKey publicKey = converter.getPublicKey(pubInfo);

            logger.info("Loaded Ed25519 key from OpenSSH format");
            return new KeyPair(publicKey, privateKey);

        } else if (privateKeyParams instanceof RSAPrivateCrtKeyParameters) {
            PrivateKeyInfo privInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(privateKeyParams);
            var pubInfo = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(
                    ((RSAPrivateCrtKeyParameters) privateKeyParams));

            PrivateKey privateKey = converter.getPrivateKey(privInfo);
            PublicKey publicKey = converter.getPublicKey(pubInfo);

            logger.info("Loaded RSA key from OpenSSH format");
            return new KeyPair(publicKey, privateKey);
        }

        throw new IllegalArgumentException("Unsupported OpenSSH key type: " + privateKeyParams.getClass().getName());
    }

    /**
     * Parses standard PEM formats:
     * PKCS#1 ("BEGIN RSA PRIVATE KEY") and PKCS#8 ("BEGIN PRIVATE KEY").
     */
    private static KeyPair readStandardPem(Path keyPath) throws Exception {

        try (
            FileReader reader = new FileReader(keyPath.toFile());
            PEMParser pemParser = new PEMParser(reader)
        ) {
            Object object = pemParser.readObject();

            logger.info("PEM file read successfully, object type: {}", object.getClass().getName());

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
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(
                    new RSAPublicKeySpec(rsaPrivateKey.getModulus(), java.math.BigInteger.valueOf(65537))
                );
                return new KeyPair(publicKey, privateKey);
            } 

            else {
                throw new IllegalArgumentException("Unknown PEM object type: " + object.getClass().getName());
            }
        }
    }
}
