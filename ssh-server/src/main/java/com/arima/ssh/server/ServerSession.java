
package com.arima.ssh.server;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

import java.security.SecureRandom;
import com.arima.ssh.common.*;
import com.arima.ssh.common.kex.*;

import java.security.MessageDigest;

public class ServerSession implements Runnable {

    private static final Logger logger = LoggerFactory.getLogger(ServerSession.class);

    // RFC 4253: The version string MUST begin with "SSH-2.0-"
    private static final String SERVER_VERSION = "SSH-2.0-ArimaSSH_1.0";

    private final Socket clientSocket;
    private InputStream inputStream;
    private OutputStream outputStream;

    private String clientVersion;

    private String kexAlgo;
    private String hostKeyAlgo;
    private String cipherC2S;
    private String cipherS2C;
    private String macC2S;
    private String macS2C;
    private String compC2S;
    private String compS2C;


    private byte[] serverKexInitPayload; 
    private byte[] clientKexInitPayload;

    private byte[] SessionId; // The session ID is the exchange hash of the first key exchange, and is used in subsequent key exchanges and authentication.


    public ServerSession(Socket clientSocket) {
        this.clientSocket = clientSocket;
    }

    @Override
    public void run() {

        logger.info("Session started for {}", clientSocket.getRemoteSocketAddress());
        
        try {

            this.inputStream = clientSocket.getInputStream();
            this.outputStream = clientSocket.getOutputStream();


            //send version string immediately upon connection
            outputStream.write((SERVER_VERSION + "\r\n").getBytes(StandardCharsets.UTF_8));
            outputStream.flush();
            logger.debug("Sent version: {}", SERVER_VERSION);


            // --------  TEXT PROTOCOL PHASE --------

            //read client's version string
            this.clientVersion = readLine(inputStream);
            
            if (!clientVersion.startsWith("SSH-2.0-")) {
                logger.error("Unsupported protocol version: {}", clientVersion);
                close();
                return;
            }
            
            logger.info("Client Identification: {}", clientVersion);


            // --------  BINARY PROTOCOL PHASE --------


            PacketReader packetReader = new PacketReader(inputStream);

            // send KEXINIT
            sendKexInit();

            logger.info("Sent KEXINIT to client, waiting for client's KEXINIT...");

            // read client's KEXINIT

            SshBuffer clientKexInitBuffer = packetReader.readPacket();

            logger.info("Received client's KEXINIT packet, length: {}", clientKexInitBuffer.wpos());

            this.clientKexInitPayload = clientKexInitBuffer.getCompactData();

            // For demonstration, we just log the client's KEXINIT and end the session.

            byte kexInitType = clientKexInitBuffer.readByte();
            if (kexInitType != SshConstants.SSH_MSG_KEXINIT) {
                logger.error("Expected SSH_MSG_KEXINIT, but got message type: {}", kexInitType);
                close();
                return;
            }

            clientKexInitBuffer.readBytes(16); // Skip the 16 random bytes

            String clientKexAlgos = clientKexInitBuffer.readString();
            String clientHostKeyAlgos = clientKexInitBuffer.readString();
            String clientCipherAlgoC2S = clientKexInitBuffer.readString();
            String clientCipherAlgoS2C = clientKexInitBuffer.readString();
            String clientMacAlgoC2S = clientKexInitBuffer.readString();
            String clientMacAlgoS2C = clientKexInitBuffer.readString();
            String clientCompressionAlgoC2S = clientKexInitBuffer.readString();
            String clientCompressionAlgoS2C = clientKexInitBuffer.readString();
            String clientLangC2S = clientKexInitBuffer.readString();
            String clientLangS2C = clientKexInitBuffer.readString();
            boolean clientFirstKexPacketFollows = clientKexInitBuffer.readByte() != 0;
            long clientReserved = clientKexInitBuffer.readUInt32();

            logger.info("Received client's KEXINIT:");
            logger.info("  Kex Algos: {}", clientKexAlgos);
            logger.info("  Host Key Algos: {}", clientHostKeyAlgos);
            logger.info("  Cipher Algos C->S: {}", clientCipherAlgoC2S);
            logger.info("  Cipher Algos S->C: {}", clientCipherAlgoS2C);
            logger.info("  MAC Algos C->S: {}", clientMacAlgoC2S);
            logger.info("  MAC Algos S->C: {}", clientMacAlgoS2C);
            logger.info("  Compression Algos C->S: {}", clientCompressionAlgoC2S);
            logger.info("  Compression Algos S->C: {}", clientCompressionAlgoS2C);
            logger.info("  Lang C->S: {}", clientLangC2S);
            logger.info("  Lang S->C: {}", clientLangS2C);  
            logger.info("  First KEX Packet Follows: {}", clientFirstKexPacketFollows);
            logger.info("  Reserved: {}", clientReserved);


            SecurityUtils securityUtils = new SecurityUtils();

            this.kexAlgo = securityUtils.negotiate(clientKexAlgos, SshConstants.PROPOSAL_KEX);
            this.hostKeyAlgo = securityUtils.negotiate(clientHostKeyAlgos, SshConstants.PROPOSAL_HOST_KEY);
            this.cipherC2S = securityUtils.negotiate(clientCipherAlgoC2S, SshConstants.PROPOSAL_CIPHER);
            this.cipherS2C = securityUtils.negotiate(clientCipherAlgoS2C, SshConstants.PROPOSAL_CIPHER);
            this.macC2S = securityUtils.negotiate(clientMacAlgoC2S, SshConstants.PROPOSAL_MAC);
            this.macS2C = securityUtils.negotiate(clientMacAlgoS2C, SshConstants.PROPOSAL_MAC);
            this.compC2S = securityUtils.negotiate(clientCompressionAlgoC2S, SshConstants.PROPOSAL_COMPRESSION);
            this.compS2C = securityUtils.negotiate(clientCompressionAlgoS2C, SshConstants.PROPOSAL_COMPRESSION);

            if (kexAlgo == null ||
                hostKeyAlgo == null ||
                cipherC2S == null || 
                cipherS2C == null ||
                macC2S == null ||
                macS2C == null ||
                compC2S == null ||
                compS2C == null) 
            {
                logger.error("Negotiation failed!");
                logger.error("Agreed Kex Algo: {}", kexAlgo);
                logger.error("Agreed Host Key Algo: {}", hostKeyAlgo);
                logger.error("Agreed Cipher C->S: {}", cipherC2S);
                logger.error("Agreed Cipher S->C: {}", cipherS2C); 
                logger.error("Agreed MAC C->S: {}", macC2S);
                logger.error("Agreed MAC S->C: {}", macS2C);
                logger.error("Agreed Compression C->S: {}", compC2S);
                logger.error("Agreed Compression S->C: {}", compS2C);
                close();
                return;
            }

            logger.info("Negotiation Complete:");
            logger.info("  Kex: {}", kexAlgo);
            logger.info("  Host Key: {}", hostKeyAlgo);
            logger.info("  CipherC2S: {}", cipherC2S);
            logger.info("  CipherS2C: {}", cipherS2C);
            logger.info("  MAC_C2S: {}", macC2S);
            logger.info("  MAC_S2C: {}", macS2C);
            logger.info("  Compression_C2S: {}", compC2S);
            logger.info("  Compression_S2C: {}", compS2C);


            // --------  KEY EXCHANGE PHASE --------


            // init the KEX algorithm with the agreed parameters

            KeyExchange kex = KEXAlgoFromName(kexAlgo);
            kex.init();

            HostKeyProvider hostKeyProvider = new HostKeyProvider();

            try {
                hostKeyProvider.init();
            } catch (Exception e) {
                logger.error("Host key initialization failed: {}", e.getMessage());
                close();
                return;
            } 

            // read client's KEXDH_INIT message

            SshBuffer kexDhInitBuffer = packetReader.readPacket();
            byte kexDhInitType = kexDhInitBuffer.readByte();
            if (kexDhInitType != SshConstants.SSH_MSG_KEXDH_INIT) {
                logger.error("Expected SSH_MSG_KEXDH_INIT, but got message type: {}", kexDhInitType);
                close();
                return;
            }

            // get client's public key e
            BigInteger clientE_BigInteger = kexDhInitBuffer.readMpint();
            byte[] clientE = clientE_BigInteger.toByteArray();
            
            logger.info("Received client's KEXDH_INIT, e length: {}", clientE.length);

            // get server's public key f = g^x mod p
            byte[] serverF = kex.getPublicKey();
            

            // caclulate shared secret K = e^x mod p
            BigInteger sharedSecretK = kex.computeSharedSecret(clientE);


            // get host public key blob
            byte[] hostKeyBlob = hostKeyProvider.getPublicKeyBlob();


            // calculate exchange hash H
            byte[] exchangeHash = null;
            try {
                exchangeHash = calculateExchangeHash(kex.getHashAlgorithm() , hostKeyBlob, clientE, serverF, sharedSecretK);
            } catch (Exception e) {
                logger.error("Failed to calculate exchange hash: {}", e.getMessage());
                close();
                return;
            }

            this.SessionId = exchangeHash; // For the first key exchange, the session ID is the exchange hash

            // sign the exchange hash with the host private key to create the signature blob
            byte[] signatureBlob = null;
            try {
                signatureBlob = hostKeyProvider.sign(exchangeHash, hostKeyAlgo);
            } catch (Exception e) {
                logger.error("Failed to sign exchange hash: {}", e.getMessage());
                close();
                return;
            }

            // send KEXDH_REPLY message containing host key blob, server public key f, and signature blob

            PacketWriter kexDhReply = new PacketWriter();
            kexDhReply.writeByte(SshConstants.SSH_MSG_KEXDH_REPLY);
            kexDhReply.writeByteString(hostKeyBlob, 0, hostKeyBlob.length);
            kexDhReply.writeByteString(serverF, 0, serverF.length);
            kexDhReply.writeByteString(signatureBlob, 0, signatureBlob.length);

            outputStream.write(kexDhReply.toByteArray());
            outputStream.flush();

            logger.info("Sent KEXDH_REPLY to client, key exchange complete! Closing session.");


            try{Thread.sleep(5000);}catch(InterruptedException e){/* Ignore */}

        } catch (IOException e) {
            logger.error("Session error: {}", e.getMessage());
        } finally {
            close();
        }
    }

    /**
     * Reads a line byte-by-byte to avoid over-reading the stream.
     * Stops at \n. Ignores \r.
     */
    private String readLine(InputStream in) throws IOException {
        StringBuilder sb = new StringBuilder();
        int b;
        // Limit to 255 bytes to prevent memory attacks
        while (sb.length() < 255 && (b = in.read()) != -1) {
            if (b == '\n') {
                return sb.toString(); 
            }
            if (b != '\r') { // specific SSH requirement: ignore CR, keep only other bytes
                sb.append((char) b);
            }
        }
        throw new IOException("Stream ended or line too long before version received");
    }

    // send SSH_MSG_KEXINIT 

    public void sendKexInit() throws IOException {

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
        payload.writeByte((byte) 0); // first_kex_packet_follows = false
        payload.writeUInt32(0); // reserved

        this.serverKexInitPayload = payload.getCompactData();

        PacketWriter packet = new PacketWriter(payload);

        outputStream.write(packet.toByteArray());
        outputStream.flush();

    }

    /**
     * calculate the exchange hash H for the KEXINIT messages, according to RFC 4253 section 8.
     */

    private byte[] calculateExchangeHash(String HashAlgo, byte[] k_s, byte[] e, byte[] f, BigInteger k ) throws Exception {

        MessageDigest hash = MessageDigest.getInstance(HashAlgo);

        SshBuffer buffer = new SshBuffer();

        buffer.writeString(clientVersion);
        buffer.writeString(SERVER_VERSION);
        buffer.writeByteString(clientKexInitPayload, 0, clientKexInitPayload.length);
        buffer.writeByteString(serverKexInitPayload, 0, serverKexInitPayload.length);
        buffer.writeByteString(k_s, 0, k_s.length);
        buffer.writeByteString(e, 0, e.length);
        buffer.writeByteString(f, 0, f.length);
        buffer.writeMpint(k);

        byte[] exchangeHash = hash.digest(buffer.getCompactData());

        return exchangeHash;
    }


    /**
     * get the key exchange hash algorithm name from the KEX algorithm name
     */

    public KeyExchange KEXAlgoFromName(String kexAlgo) {
        if (kexAlgo.startsWith("diffie-hellman-group14-sha1")) {
            return new DhGroup14_SHA1();
        } else {
            throw new IllegalArgumentException("Unsupported KEX algorithm: " + kexAlgo);
        }
    }


    private void close() {
        try {
            logger.info("Closing session for {}", clientSocket.getRemoteSocketAddress());
            if (clientSocket != null && !clientSocket.isClosed()) {
                clientSocket.close();
            }
        } catch (IOException e) {
            logger.error("Error closing socket", e);
        }
    }
}