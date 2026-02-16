package com.arima.ssh.common.kex;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.Cipher;

import com.arima.ssh.common.SshBuffer;
import com.arima.ssh.common.SshConstants;
import com.arima.ssh.common.crypto.CipherFactory;
import com.arima.ssh.common.crypto.CipherFactory.CipherConstants;
import com.arima.ssh.common.crypto.SshCipher;
import com.arima.ssh.common.crypto.SshMac;


/**
 * Shared key-exchange utilities used by both client and server sessions.
 */
public final class KexUtils {

    private KexUtils() {} // utility class


    /**
     * Creates a {@link KeyExchange} implementation from a KEX algorithm name.
     *
     * @param kexAlgo the negotiated algorithm name (e.g. "diffie-hellman-group14-sha1")
     * @return a new, un-initialised KeyExchange instance
     * @throws IllegalArgumentException if the algorithm is not supported
     */
    public static KeyExchange kexAlgoFromName(String kexAlgo) {
        if (kexAlgo.startsWith("diffie-hellman-group14-sha1")) {
            return new DhGroup14_SHA1();
        } else if (kexAlgo.startsWith("diffie-hellman-group-exchange-sha256")) {
            return new DhGroup_SHA256(null, null);
        } else {
            throw new IllegalArgumentException("Unsupported KEX algorithm: " + kexAlgo);
        }
    }

    /**
     * map ssh signature algorithm name (e.g. "ssh-rsa") to Java signature algorithm name (e.g. "SHA256withRSA")
     * @param sshName the SSH signature algorithm name
     * @return the corresponding Java signature algorithm name
     * @throws IllegalArgumentException if the SSH algorithm name is not recognized
     */


    public static String mapSshToJava(String sshName) {
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



    /**
     * Builds a SSH_MSG_KEXINIT payload (RFC 4253 §7.1).
     * The returned buffer is ready to be sent and also serves as the raw payload
     * needed later for exchange-hash computation.
     *
     * @return the KEXINIT payload as an SshBuffer
     */
    public static SshBuffer buildKexInitPayload() {
        SshBuffer payload = new SshBuffer();

        byte[] randomBytes = new byte[16];
        new SecureRandom().nextBytes(randomBytes);

        payload.writeByte(SshConstants.SSH_MSG_KEXINIT);
        payload.writeBytes(randomBytes, 0, randomBytes.length);
        payload.writeString(SshConstants.PROPOSAL_KEX);
        payload.writeString(SshConstants.PROPOSAL_HOST_KEY);
        payload.writeString(SshConstants.PROPOSAL_CIPHER);
        payload.writeString(SshConstants.PROPOSAL_CIPHER);
        payload.writeString(SshConstants.PROPOSAL_MAC);
        payload.writeString(SshConstants.PROPOSAL_MAC);
        payload.writeString(SshConstants.PROPOSAL_COMPRESSION);
        payload.writeString(SshConstants.PROPOSAL_COMPRESSION);
        payload.writeString(SshConstants.PROPOSAL_LANG);
        payload.writeString(SshConstants.PROPOSAL_LANG);
        payload.writeByte((byte) 0);  // first_kex_packet_follows = false
        payload.writeUInt32(0);        // reserved

        return payload;
    }


    /**
     * Builds a SSH_MSG_KEX_DH_GEX_REQUEST packet (RFC 4419 §2.1).
     * @param gexMin minimum acceptable group size in bits (e.g. 2048)
     * @param gexPreferred preferred group size in bits (e.g. 4096
     * @param gexMax maximum acceptable group size in bits (e.g. 8192)
     * @return an SshBuffer ready to be sent
     */


    public static SshBuffer buildGexRequest(long gexMin, long gexPreferred, long gexMax) {
        SshBuffer buffer = new SshBuffer();
        buffer.writeByte(SshConstants.SSH_MSG_KEXDH_GEX_REQUEST);
        buffer.writeUInt32(gexMin);
        buffer.writeUInt32(gexPreferred);
        buffer.writeUInt32(gexMax);
        return buffer;
    }

    /**
     * Builds a SSH_MSG_KEX_DH_INIT packet (RFC 4253 §8).
     * @param e the client's DH public value as a byte array
     * @return an SshBuffer ready to be sent
    */

    public static SshBuffer buildKexDhInit(byte[] e,boolean isGroupExchange) {
        SshBuffer buffer = new SshBuffer();
        buffer.writeByte(isGroupExchange ? SshConstants.SSH_MSG_KEXDH_GEX_INIT : SshConstants.SSH_MSG_KEXDH_INIT);
        buffer.writeByteString(e, 0, e.length);
        return buffer;
    }

    /**
     * Builds a SSH_MSG_KEX_DH_REPLY packet (RFC 4253 §8).
     * @param hostKeyBlob the server's public host key blob (K_S)
     * @param f the server's DH public value as a byte array
     * @param signatureBlob the signature blob (contains the signature of H using the host key)
     * @return an SshBuffer ready to be sent
    */

    public static SshBuffer buildKexDhReply(byte[] hostKeyBlob, byte[] f, byte[] signatureBlob) {
        SshBuffer buffer = new SshBuffer();
        buffer.writeByte(SshConstants.SSH_MSG_KEXDH_REPLY);
        buffer.writeByteString(hostKeyBlob, 0, hostKeyBlob.length);
        buffer.writeByteString(f, 0, f.length);
        buffer.writeByteString(signatureBlob, 0, signatureBlob.length);
        return buffer;
    }

    /**
     * verify server's signature blob against the exchange hash H using the host public key from the host key blob
     * @param hostKeyBlob the server's public host key blob (K_S)
     * @param signatureBlob the signature blob (contains the signature of H using the host key)
     * @param H the exchange hash to verify
     * @return true if the signature is valid, false otherwise
     * @throws Exception if any error occurs during signature verification (e.g. unsupported key type
    */

    public static boolean verifyServerSignature(byte[] hostKeyBlob, byte[] signatureBlob, byte[] H) throws Exception {
        SshBuffer hostKeyBuf = new SshBuffer(hostKeyBlob);
        hostKeyBuf.readString(); // skip the key type (e.g. "ssh-rsa")
        BigInteger e = hostKeyBuf.readMpint();
        BigInteger n = hostKeyBuf.readMpint();

        SshBuffer sigBuf = new SshBuffer(signatureBlob);
        String sigAlgo = sigBuf.readString();
        byte[] sigData = sigBuf.readByteString();

        
        Signature signature = Signature.getInstance(KexUtils.mapSshToJava(sigAlgo));

        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(n, e);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        signature.initVerify(keyFactory.generatePublic(keySpec));

        signature.update(H);

        return signature.verify(sigData);

    }


    /**
     * Parses a SSH_MSG_KEXINIT packet into a {@link KexInitData} record.
     * The message-type byte must already have been read/verified by the caller;
     * this method begins by skipping the 16 random bytes.
     *
     * @param buffer the packet buffer positioned right after the message-type byte
     * @return the parsed KEXINIT data
     */
    public static KexInitData parseKexInit(SshBuffer buffer) {
        buffer.readBytes(16); // skip 16 random bytes (cookie)

        String kexAlgos        = buffer.readString();
        String hostKeyAlgos    = buffer.readString();
        String cipherC2S       = buffer.readString();
        String cipherS2C       = buffer.readString();
        String macC2S          = buffer.readString();
        String macS2C          = buffer.readString();
        String compC2S         = buffer.readString();
        String compS2C         = buffer.readString();
        String langC2S         = buffer.readString();
        String langS2C         = buffer.readString();
        boolean firstFollows   = buffer.readByte() != 0;
        long reserved          = buffer.readUInt32();

        return new KexInitData(
            kexAlgos, hostKeyAlgos,
            cipherC2S, cipherS2C,
            macC2S, macS2C,
            compC2S, compS2C,
            langC2S, langS2C,
            firstFollows, reserved
        );
    }


    /**
     * Computes the exchange hash H as specified by RFC 4253 §8 (and RFC 4419 for GEX).
     *
     * @param hashAlgo           the hash algorithm name (e.g. "SHA-256")
     * @param clientVersion      the client's identification string (V_C)
     * @param serverVersion      the server's identification string (V_S)
     * @param clientKexInit      the raw payload of the client's KEXINIT (I_C)
     * @param serverKexInit      the raw payload of the server's KEXINIT (I_S)
     * @param hostKeyBlob        the server's public host key blob (K_S)
     * @param e                  the client's DH public value
     * @param f                  the server's DH public value
     * @param K                  the shared secret
     * @param kexAlgoName        the negotiated kex algorithm name (to detect GEX)
     * @param gexMin             GEX min bits  (only used when kexAlgoName starts with "diffie-hellman-group-exchange")
     * @param gexPreferred       GEX preferred bits
     * @param gexMax             GEX max bits
     * @param gexP               GEX prime p
     * @param gexG               GEX generator g
     * @return the computed exchange hash H
     */
    public static byte[] calculateExchangeHash(
            String hashAlgo,
            String clientVersion, String serverVersion,
            byte[] clientKexInit, byte[] serverKexInit,
            byte[] hostKeyBlob,
            byte[] e, byte[] f,
            BigInteger K,
            String kexAlgoName,
            long gexMin, long gexPreferred, long gexMax,
            BigInteger gexP, BigInteger gexG) throws Exception {

        MessageDigest hash = MessageDigest.getInstance(hashAlgo);

        SshBuffer buffer = new SshBuffer();
        buffer.writeString(clientVersion);
        buffer.writeString(serverVersion);
        buffer.writeByteString(clientKexInit, 0, clientKexInit.length);
        buffer.writeByteString(serverKexInit, 0, serverKexInit.length);
        buffer.writeByteString(hostKeyBlob, 0, hostKeyBlob.length);

        if (kexAlgoName.startsWith("diffie-hellman-group-exchange")) {
            buffer.writeUInt32(gexMin);
            buffer.writeUInt32(gexPreferred);
            buffer.writeUInt32(gexMax);
            buffer.writeMpint(gexP);
            buffer.writeMpint(gexG);
        }

        buffer.writeByteString(e, 0, e.length);
        buffer.writeByteString(f, 0, f.length);
        buffer.writeMpint(K);

        return hash.digest(buffer.getCompactData());
    }


    /**
     * Derives the six session keys and creates the cipher / MAC instances.
     * <p>
     * The discriminators are fixed by RFC 4253 §7.2:
     * <ul>
     *   <li>A/B = IV   for C2S / S2C</li>
     *   <li>C/D = enc  for C2S / S2C</li>
     *   <li>E/F = mac  for C2S / S2C</li>
     * </ul>
     * The {@code isServer} flag determines which direction is inbound (decrypt)
     * and which is outbound (encrypt).
     *
     * @param K            the shared secret
     * @param H            the exchange hash
     * @param sessionId    the session identifier
     * @param cipherC2S    negotiated cipher name client-to-server
     * @param cipherS2C    negotiated cipher name server-to-client
     * @param macC2S       negotiated MAC name client-to-server
     * @param macS2C       negotiated MAC name server-to-client
     * @param hashAlgo     hash algorithm for key derivation (from the KEX)
     * @param isServer     true on the server side (decrypt=C2S, encrypt=S2C),
     *                     false on the client side (decrypt=S2C, encrypt=C2S)
     * @return a {@link DerivedKeys} record containing the ready-to-use cipher and MAC instances
     */
    public static DerivedKeys deriveKeys(
            BigInteger K, byte[] H, byte[] sessionId,
            String cipherC2S, String cipherS2C,
            String macC2S, String macS2C,
            String hashAlgo, boolean isServer) throws Exception {

        KeyDerivation keyDerivation = new KeyDerivation(hashAlgo);

        CipherConstants cipherC2S_Constants = CipherFactory.getConstants(cipherC2S);
        CipherConstants cipherS2C_Constants = CipherFactory.getConstants(cipherS2C);

        int macKeySizeC2S = SshMac.getMacSize(macC2S);
        int macKeySizeS2C = SshMac.getMacSize(macS2C);

        // Discriminators are always the same regardless of side
        byte[] ivC2S     = keyDerivation.calculateKey(K, H, (byte) 'A', sessionId, cipherC2S_Constants.ivSize);
        byte[] ivS2C     = keyDerivation.calculateKey(K, H, (byte) 'B', sessionId, cipherS2C_Constants.ivSize);
        byte[] encKeyC2S = keyDerivation.calculateKey(K, H, (byte) 'C', sessionId, cipherC2S_Constants.keySize);
        byte[] encKeyS2C = keyDerivation.calculateKey(K, H, (byte) 'D', sessionId, cipherS2C_Constants.keySize);
        byte[] macKeyC2S = keyDerivation.calculateKey(K, H, (byte) 'E', sessionId, macKeySizeC2S);
        byte[] macKeyS2C = keyDerivation.calculateKey(K, H, (byte) 'F', sessionId, macKeySizeS2C);

        SshCipher decryptor;
        SshCipher encryptor;
        SshMac inboundMac;
        SshMac outboundMac;

        if (isServer) {
            // Server: incoming = C2S (decrypt), outgoing = S2C (encrypt)
            decryptor   = new SshCipher(cipherC2S_Constants.transformation, encKeyC2S, ivC2S, Cipher.DECRYPT_MODE);
            encryptor   = new SshCipher(cipherS2C_Constants.transformation, encKeyS2C, ivS2C, Cipher.ENCRYPT_MODE);
            inboundMac  = new SshMac(macC2S, macKeyC2S);
            outboundMac = new SshMac(macS2C, macKeyS2C);
        } else {
            // Client: incoming = S2C (decrypt), outgoing = C2S (encrypt)
            decryptor   = new SshCipher(cipherS2C_Constants.transformation, encKeyS2C, ivS2C, Cipher.DECRYPT_MODE);
            encryptor   = new SshCipher(cipherC2S_Constants.transformation, encKeyC2S, ivC2S, Cipher.ENCRYPT_MODE);
            inboundMac  = new SshMac(macS2C, macKeyS2C);
            outboundMac = new SshMac(macC2S, macKeyC2S);
        }

        return new DerivedKeys(decryptor, encryptor, inboundMac, outboundMac);
    }
}
