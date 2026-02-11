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

import javax.crypto.Cipher;

import com.arima.ssh.common.*;
import com.arima.ssh.common.crypto.CipherFactory;
import com.arima.ssh.common.crypto.SshCipher;
import com.arima.ssh.common.crypto.SshKeyDecoder;
import com.arima.ssh.common.crypto.SshMac;
import com.arima.ssh.common.crypto.SshSignatureVerifier;
import com.arima.ssh.common.crypto.CipherFactory.CipherConstants;
import com.arima.ssh.common.kex.*;
import com.arima.ssh.server.auth.PasswordAuthenticator;

import java.security.MessageDigest;
import java.security.PublicKey;

public class ServerSession implements Runnable {

    private static final Logger logger = LoggerFactory.getLogger(ServerSession.class);

    // RFC 4253: The version string MUST begin with "SSH-2.0-"
    private static final String SERVER_VERSION = "SSH-2.0-ArimaSSH_1.0";

    private final Socket clientSocket;
    private final SshServer server;

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

    private SshCipher currentDecryptor;
    private SshCipher currentEncryptor;

    private SshMac macClient; //C2S
    private SshMac macServer; //S2C


    public ServerSession(Socket clientSocket, SshServer server) {
        this.clientSocket = clientSocket;
        this.server = server;
    }

    @Override
    public void run() {

        logger.info("Session started for {}", clientSocket.getRemoteSocketAddress());
        
        try {


            this.inputStream = clientSocket.getInputStream();
            this.outputStream = clientSocket.getOutputStream();



            // --------  TEXT PROTOCOL PHASE --------


            //send version string immediately upon connection
            outputStream.write((SERVER_VERSION + "\r\n").getBytes(StandardCharsets.UTF_8));
            outputStream.flush();
            logger.debug("Sent version: {}", SERVER_VERSION);

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
            PacketWriter packetWriter = new PacketWriter(outputStream);

            // send KEXINIT
            sendKexInit(packetWriter);

            logger.info("Sent KEXINIT to client, waiting for client's KEXINIT...");

            // read client's KEXINIT
            SshBuffer clientKexInitBuffer = null;
            try {
                clientKexInitBuffer = packetReader.readPacket();
            } catch (Exception e) {
                logger.error("Failed to read client's KEXINIT: {}", e.getMessage());
                close();
                return;
            }

            logger.info("Received client's KEXINIT packet, length: {}", clientKexInitBuffer.wpos());

            this.clientKexInitPayload = clientKexInitBuffer.getCompactData();


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

            SshBuffer kexDhInitBuffer = null;

            try {
                kexDhInitBuffer = packetReader.readPacket();
            } catch (Exception e) {
                logger.error("Failed to read client's KEXDH_INIT: {}", e.getMessage());
                close();
                return;
            }

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

            //write the KEXDH_REPLY packet
            packetWriter.writeByte(SshConstants.SSH_MSG_KEXDH_REPLY);
            packetWriter.writeByteString(hostKeyBlob, 0, hostKeyBlob.length);
            packetWriter.writeByteString(serverF, 0, serverF.length);
            packetWriter.writeByteString(signatureBlob, 0, signatureBlob.length);


            try {
                packetWriter.writePacket();
            } catch (Exception e) {
                logger.error("Failed to send KEXDH_REPLY packet: {}", e.getMessage());
                close();
                return;
            }


            logger.info("Sent KEXDH_REPLY to client, key exchange complete!");


            // -------- NEWSKEY EXCHANGE PHASE --------


            packetWriter.writeByte(SshConstants.SSH_MSG_NEWKEYS);

            try {
                packetWriter.writePacket();
            } catch (Exception e) {
                logger.error("Failed to send NEWKEYS packet: {}", e.getMessage());
                close();
                return;
            }

            logger.info("Sent NEWKEYS to client.");

            // generate the encryption keys and MAC keys 

            KeyDerivation keyDerivation = null;
            try {
                keyDerivation = new KeyDerivation(kex.getHashAlgorithm());
            } catch (Exception e) {
                logger.error("Failed to initialize key derivation: {}", e.getMessage());
                close();
                return;
            }


            CipherConstants cipherC2S_Constants = CipherFactory.getConstants(cipherC2S);
            CipherConstants cipherS2C_Constants = CipherFactory.getConstants(cipherS2C);

            int macKeySizeC2S = SshMac.getMacSize(macC2S);
            int macKeySizeS2C = SshMac.getMacSize(macS2C);


            byte[] viC2S = keyDerivation.calculateKey(sharedSecretK, exchangeHash, (byte) 'A', SessionId, cipherC2S_Constants.ivSize);
            byte[] viS2C = keyDerivation.calculateKey(sharedSecretK, exchangeHash, (byte) 'B', SessionId, cipherS2C_Constants.ivSize);

            byte[] encKeyC2S = keyDerivation.calculateKey(sharedSecretK, exchangeHash, (byte) 'C', SessionId, cipherC2S_Constants.keySize);
            byte[] encKeyS2C = keyDerivation.calculateKey(sharedSecretK, exchangeHash, (byte) 'D', SessionId, cipherS2C_Constants.keySize);

            byte[] macKeyC2S = keyDerivation.calculateKey(sharedSecretK, exchangeHash, (byte) 'E', SessionId, macKeySizeC2S); 
            byte[] macKeyS2C = keyDerivation.calculateKey(sharedSecretK, exchangeHash, (byte) 'F', SessionId, macKeySizeS2C);

            try {
                this.currentDecryptor = new SshCipher(cipherC2S_Constants.transformation, encKeyC2S, viC2S, Cipher.DECRYPT_MODE);
                this.currentEncryptor = new SshCipher(cipherS2C_Constants.transformation, encKeyS2C, viS2C, Cipher.ENCRYPT_MODE);
            } catch (Exception e) {
                logger.error("Failed to initialize ciphers: {}", e.getMessage());
                close();
                return;
            }

            try {
                this.macClient = new SshMac(macC2S, macKeyC2S);
                this.macServer = new SshMac(macS2C, macKeyS2C);

            } catch (Exception e) {
                logger.error("Failed to initialize MACs: {}", e.getMessage());
                close();
                return;
            }


            // read NEWKEYS from client to confirm they are ready to switch to the new keys
            SshBuffer packet = null;
            try {
                packet = packetReader.readPacket();
            } catch (Exception e) {
                logger.error("Failed to read NEWKEYS from client: {}", e.getMessage());
                close();
                return;
            }

            byte msgId = packet.readByte();

            if (msgId != SshConstants.SSH_MSG_NEWKEYS) {
                throw new IOException("Expected NEWKEYS (21), got " + msgId);
            }

            logger.info("Received NEWKEYS");
        

            // activate the encryption for incoming packets

            packetReader.setCipher(currentDecryptor);
            packetReader.setMac(macClient);

            packetWriter.setCipher(currentEncryptor);
            packetWriter.setMac(macServer);


            logger.info("tunnel is now encrypted with {} for client->server and {} for server->client", cipherC2S, cipherS2C);

            // ------- HANDLE SSH USER AUTHENTICATION AND CHANNEL REQUESTS --------


            // client is expected to send a SSH_MSG_SERVICE_REQUEST with the service "ssh-userauth" to initiate the authentication phase.

            logger.info("Waiting for client's SERVICE_REQUEST ...");

            SshBuffer serviceReqBuffer = null;

            try {
                serviceReqBuffer = packetReader.readPacket();
            } catch (Exception e) {
                logger.error("Failed to read encrypted packet from client: {}", e.getMessage());
                close();
                return;
            }

            msgId = serviceReqBuffer.readByte();

   
            if (msgId != SshConstants.SSH_MSG_SERVICE_REQUEST) {
                logger.error("Expected SSH_MSG_SERVICE_REQUEST (5), got {}", msgId);
                sendDisconnectAndClose(packetWriter, SshConstants.SSH_DISCONNECT_PROTOCOL_ERROR, "Expected SERVICE_REQUEST");
                return;
            }


            String serviceName = serviceReqBuffer.readString();
            if (!serviceName.equals("ssh-userauth")) {
                logger.error("Unsupported service requested: {}", serviceName);
                sendDisconnectAndClose(packetWriter, SshConstants.SSH_DISCONNECT_SERVICE_NOT_AVAILABLE, serviceName);
                return;
            }

           
            logger.info("Received service request for ssh-userauth, sending SERVICE_ACCEPT...");

            packetWriter.writeByte(SshConstants.SSH_MSG_SERVICE_ACCEPT);
            packetWriter.writeString(serviceName);
            
            try {
                packetWriter.writePacket();
            } catch (Exception e) {
                logger.error("Failed to send SERVICE_ACCEPT packet: {}", e.getMessage());
                close();
                return;
            }
        
            // ----- handle user authentication requests -----
            boolean authenticated = false;
            String username = null;

            while (!authenticated) {

                try {
                    packet = packetReader.readPacket();
                } catch (Exception e) {
                    logger.error("Failed to read encrypted packet from client: {}", e.getMessage());
                    close();
                    return;
                }

                msgId = packet.readByte();

                if (msgId == SshConstants.SSH_MSG_USERAUTH_REQUEST) {
                            
       
                    String user = packet.readString();
                    String service = packet.readString();
                    String method = packet.readString();

                    logger.info("Auth Request: User={}, Service={}, Method={}", user, service, method);


                    if ("none".equals(method)) {

                        logger.info("Client requested 'none' auth. Sending supported methods.");
                                

                        try {
                            sendAuthFailure(packetWriter, true);
                        } catch (Exception e) {
                            logger.error("Failed to send USERAUTH_FAILURE packet: {}", e.getMessage());
                            close();
                            return;
                        }

                    }else if ("password".equals(method)) {

                        
                        boolean hasOldPassword = packet.readBoolean();
                        String password = packet.readString();

                        logger.info("Password auth attempt for user {}. Has old password: {}", user, hasOldPassword);


                        PasswordAuthenticator authenticator = server.getPasswordAuthenticator();

                        boolean success = false;

                        if(authenticator!= null){
                            success = authenticator.authenticate(user, password, this);
                        } else {
                            logger.warn("No PasswordAuthenticator configured on server. Rejecting all password auth attempts.");
                        }

                        if (success){

                            logger.info("User {} authenticated successfully with password!", user);

                            packetWriter.writeByte(SshConstants.SSH_MSG_USERAUTH_SUCCESS);

                            try {
                                packetWriter.writePacket();
                            } catch (Exception e) {
                                logger.error("Failed to send USERAUTH_SUCCESS packet: {}", e.getMessage());
                                close();
                                return;
                            }

                            authenticated = true;
                            username = user; 

                        }else{

                            logger.warn("User {} failed to authenticate with password.", user);

                            try {
                                sendAuthFailure(packetWriter, true); // allow retry for password auth
                            } catch (Exception e) {
                                logger.error("Failed to send USERAUTH_FAILURE packet: {}", e.getMessage());
                                close();
                                return;
                            }

                        }
                            
                    }else if ("publickey".equals(method)) {

                        logger.warn("KeyPublic auth attempt by user {}.", user);

                        boolean hasSignature = packet.readBoolean();
                        String keyAlgo = packet.readString();
                        byte[] keyBlob = packet.readByteString();

                        // check if its a query 
                        if (!hasSignature) {
                            logger.info("Public key query received for algo {}. Responding with allowed=true to indicate the server recognizes this key type.", keyAlgo);

                            packetWriter.writeByte(SshConstants.SSH_MSG_USERAUTH_PK_OK);
                            packetWriter.writeString(keyAlgo);
                            packetWriter.writeByteString(keyBlob, 0, keyBlob.length);


                            try {
                                packetWriter.writePacket();
                            } catch (Exception e) {
                                logger.error("Failed to send USERAUTH_PK_OK packet: {}", e.getMessage());
                                close();
                                return;
                            }

                        } else {
                            
                            logger.warn("Public key authentication with signature");

                            byte[] keySignatureBlob = packet.readByteString(); 
                    
                            // Reconstruct the "Signed Data"
                            SshBuffer buffer = new SshBuffer();
                            buffer.writeBytes(this.SessionId, 0 , this.SessionId.length); // 1. Session ID
                            buffer.writeByte(SshConstants.SSH_MSG_USERAUTH_REQUEST); // 2. Msg ID
                            buffer.writeString(user);      // 3. Username
                            buffer.writeString(service);   // 4. Service ("ssh-connection")
                            buffer.writeString("publickey"); // 5. Method
                            buffer.writeBoolean(true);     // 6. Has Signature (TRUE)
                            buffer.writeString(keyAlgo); // 7. Algo Name
                            buffer.writeBytes(keyBlob, 0, keyBlob.length); // 8. The Key Blob
                            
                            byte[] dataToVerify = buffer.getCompactData();

                            // decode the public key from the blob
                            
                            PublicKey clientPublicKey = null;

                            try {
                                clientPublicKey = SshKeyDecoder.decodePublicKey(keyBlob);
                            } catch (Exception e) {
                                logger.error("Failed to decode client's public key blob: {}", e.getMessage());
                                try {
                                    sendAuthFailure(packetWriter, false); // don't allow retry if key blob is invalid
                                } catch (Exception ex) {
                                    logger.error("Failed to send USERAUTH_FAILURE packet: {}", ex.getMessage());
                                    close();
                                    return;
                                }
                                continue;
                            }

                            // verify the signature using the client's public key

                            boolean signatureValid = false;

                            try {
                                signatureValid = SshSignatureVerifier.verify(clientPublicKey, dataToVerify, keySignatureBlob);
                            } catch (Exception e) {
                                logger.error("Failed to verify client's signature: {}", e.getMessage());
                                try {
                                    sendAuthFailure(packetWriter, false); // don't allow retry if signature verification fails
                                } catch (Exception ex) {
                                    logger.error("Failed to send USERAUTH_FAILURE packet: {}", ex.getMessage());
                                    close();
                                    return;
                                }
                                continue;
                            }
                            

                            if (!signatureValid){
                                logger.warn("Invalid signature in public key authentication attempt for user {}.", user);

                                try {
                                    sendAuthFailure(packetWriter, true); // allow retry for invalid signature
                                } catch (Exception e) {
                                    logger.error("Failed to send USERAUTH_FAILURE packet: {}", e.getMessage());
                                    close();
                                    return;
                                }
                            }

                            // TODO:
                            // we will check the username and the key blob against our list of authorized keys for that user. If it matches, we accept the authentication.
                            // but for now we will just accept any valid signature with a key type we support, to demonstrate the flow.


                            logger.info("Public key authentication successful for user {}!", user);


                            packetWriter.writeByte(SshConstants.SSH_MSG_USERAUTH_SUCCESS);

                            try {
                                packetWriter.writePacket();
                            } catch (Exception e) {
                                logger.error("Failed to send USERAUTH_SUCCESS packet: {}", e.getMessage());
                                close();
                                return;
                            }

                            authenticated = true;
                            username = user; 

                        }


                    }else {

                        logger.warn("Unsupported method: {}", method);
                                
                        try {
                            sendAuthFailure(packetWriter, false); // don't allow retry for unsupported methods
                        } catch (Exception e) {
                            logger.error("Failed to send USERAUTH_FAILURE packet: {}", e.getMessage());
                            close();
                            return;
                        }

                    }

                }else {
                    // Ignore other packets (like debug/ignore) or disconnect
                    logger.warn("Unexpected packet during auth: {}", msgId);
                }

            }
            
            logger.info("User {} Authenticated!", username);
                        

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

    public void sendKexInit(PacketWriter writer) throws IOException {

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

        writer.writeBytes(serverKexInitPayload);

        try {
            // write the KEXINIT packet to the stream and flush
            writer.writePacket();
        } catch (Exception e) {
            logger.error("Failed to generate KEXINIT packet: {}", e.getMessage());
            return;
        }

    }


    /**
     * send authentication failure with a list of supported methods 
     * and a boolean indicating whether the client can try again (false if max attempts reached or method was not recognized)
     */

    private  void sendAuthFailure(PacketWriter writer, boolean canRetry) throws Exception{
        writer.writeByte(SshConstants.SSH_MSG_USERAUTH_FAILURE);
        writer.writeString(SshConstants.SUPPORTED_AUTH_METHODS);
        writer.writeBoolean(canRetry);
        writer.writePacket();
    }

    /**
     * send SSH_MSG_DISCONNECT with a reason code and message, then close the connection
     */

    private void sendDisconnectAndClose(PacketWriter writer, int reasonCode, String message) {
        try {
            writer.writeByte(SshConstants.SSH_MSG_DISCONNECT);
            writer.writeUInt32(reasonCode);
            writer.writeString(message);
            writer.writeString(""); // language tag, not used
            writer.writePacket();
        } catch (Exception e) {
            logger.error("Failed to send DISCONNECT packet: {}", e.getMessage());
        } finally {
            close();
        }
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