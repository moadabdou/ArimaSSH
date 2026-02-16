package com.arima.ssh.server;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

import java.security.PublicKey;

import com.arima.ssh.common.*;
import com.arima.ssh.common.crypto.SshCipher;
import com.arima.ssh.common.crypto.SshKeyDecoder;
import com.arima.ssh.common.crypto.SshMac;
import com.arima.ssh.common.crypto.SshSignatureVerifier;
import com.arima.ssh.common.kex.*;
import com.arima.ssh.server.auth.PasswordAuthenticator;
import com.arima.ssh.server.channel.ChannelManager;


public class ServerSession implements Runnable {

    private static final Logger logger = LoggerFactory.getLogger(ServerSession.class);

    // RFC 4253: The version string MUST begin with "SSH-2.0-"
    private static final String SERVER_VERSION = "SSH-2.0-ArimaSSH_1.0";

    private final Socket clientSocket;
    private final SshServer server;

    private ChannelManager channelManager;
    private ForwardingManager forwardingManager;

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

    private KeyExchange kex;


    private byte[] serverKexInitPayload; 
    private byte[] clientKexInitPayload;

    private byte[] SessionId; // The session ID is the exchange hash of the first key exchange, and is used in subsequent key exchanges and authentication.

    private SshCipher currentDecryptor;
    private SshCipher currentEncryptor;

    private SshMac inboundMac;
    private SshMac outboundMac;

    private PacketWriter packetWriter;


    private long gexMin;
    private long gexPreferred;
    private long gexMax;


    public ServerSession(Socket clientSocket, SshServer server) {
        this.clientSocket = clientSocket;
        this.server = server;
        this.channelManager = new ChannelManager(this);
        this.forwardingManager = new ForwardingManager(this);
    }


    public SshServer getServer() {
        return server;
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
            this.clientVersion = SshProtocolUtils.readLine(inputStream);
            
            if (!clientVersion.startsWith("SSH-2.0-")) {
                logger.error("Unsupported protocol version: {}", clientVersion);
                close();
                return;
            }
            
            logger.info("Client Identification: {}", clientVersion);



            // --------  BINARY PROTOCOL PHASE --------


            PacketReader packetReader = new PacketReader(inputStream);
            this.packetWriter = new PacketWriter(outputStream);

            // send KEXINIT
            sendKexInit();

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

            this.clientKexInitPayload = clientKexInitBuffer.getCompactData();

            byte kexInitType = clientKexInitBuffer.readByte();
            if (kexInitType != SshConstants.SSH_MSG_KEXINIT) {
                logger.error("Expected SSH_MSG_KEXINIT, but got message type: {}", kexInitType);
                close();
                return;
            }

            logger.info("Received client's KEXINIT packet, length: {}", clientKexInitBuffer.wpos());

            KexInitData clientKexData = KexUtils.parseKexInit(clientKexInitBuffer);

            logger.info("Received client's KEXINIT:");
            logger.info("  Kex Algos: {}", clientKexData.kexAlgos());
            logger.info("  Host Key Algos: {}", clientKexData.hostKeyAlgos());
            logger.info("  Cipher Algos C->S: {}", clientKexData.cipherC2S());
            logger.info("  Cipher Algos S->C: {}", clientKexData.cipherS2C());
            logger.info("  MAC Algos C->S: {}", clientKexData.macC2S());
            logger.info("  MAC Algos S->C: {}", clientKexData.macS2C());
            logger.info("  Compression Algos C->S: {}", clientKexData.compC2S());
            logger.info("  Compression Algos S->C: {}", clientKexData.compS2C());
            logger.info("  Lang C->S: {}", clientKexData.langC2S());
            logger.info("  Lang S->C: {}", clientKexData.langS2C());
            logger.info("  First KEX Packet Follows: {}", clientKexData.firstKexPacketFollows());
            logger.info("  Reserved: {}", clientKexData.reserved());


            this.kexAlgo = NegotiationUtils.negotiate(clientKexData.kexAlgos(), SshConstants.PROPOSAL_KEX);
            this.hostKeyAlgo = NegotiationUtils.negotiate(clientKexData.hostKeyAlgos(), SshConstants.PROPOSAL_HOST_KEY);
            this.cipherC2S = NegotiationUtils.negotiate(clientKexData.cipherC2S(), SshConstants.PROPOSAL_CIPHER);
            this.cipherS2C = NegotiationUtils.negotiate(clientKexData.cipherS2C(), SshConstants.PROPOSAL_CIPHER);
            this.macC2S = NegotiationUtils.negotiate(clientKexData.macC2S(), SshConstants.PROPOSAL_MAC);
            this.macS2C = NegotiationUtils.negotiate(clientKexData.macS2C(), SshConstants.PROPOSAL_MAC);
            this.compC2S = NegotiationUtils.negotiate(clientKexData.compC2S(), SshConstants.PROPOSAL_COMPRESSION);
            this.compS2C = NegotiationUtils.negotiate(clientKexData.compS2C(), SshConstants.PROPOSAL_COMPRESSION);

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


            this.kex = KexUtils.kexAlgoFromName(kexAlgo);
            kex.init();

            HostKeyProvider hostKeyProvider = this.server.getHostKeyProvider() != null ? this.server.getHostKeyProvider() : new HostKeyProvider(null);

            try {
                hostKeyProvider.init();
            } catch (Exception e) {
                logger.error("Host key initialization failed: {}", e.getMessage());
                close();
                return;
            } 

            // read client's KEXDH_INIT message


            SshBuffer kexDhBuffer = null;

            try {
                kexDhBuffer = packetReader.readPacket();
            } catch (Exception e) {
                logger.error("Failed to read client's KEXDH_INIT: {}", e.getMessage());
                close();
                return;
            }


            byte kexDhType = kexDhBuffer.readByte();

            //check if the client sent a group exchange request instead of a regular KEXDH_INIT, and if so, handle it accordingly (RFC 8332)

            boolean isGroupExchange = false;

            if (kexDhType == SshConstants.SSH_MSG_KEXDH_GEX_REQUEST){


                long min = kexDhBuffer.readUInt32();
                long preferred = kexDhBuffer.readUInt32(); 
                long max = kexDhBuffer.readUInt32();

                logger.info("Received KEXDH_GEX_REQUEST: min={}, preferred={}, max={}", min, preferred, max);
                
                
                this.gexMin = min;
                this.gexPreferred = preferred;
                this.gexMax = max;


                SshBuffer groupMsg = new SshBuffer();
                groupMsg.writeByte(SshConstants.SSH_MSG_KEXDH_GEX_GROUP); // 31
                groupMsg.writeMpint(kex.getP());
                groupMsg.writeMpint(kex.getG());
                
                sendPacket(groupMsg);

                isGroupExchange = true;

                logger.info("Sent KEXDH_GEX_GROUP with p and g, waiting for client's KEXDH_INIT ...");

                try {
                    kexDhBuffer = packetReader.readPacket();
                } catch (Exception e) {
                    logger.error("Failed to read client's KEXDH_INIT after GEX_GROUP: {}", e.getMessage());
                    close();
                    return;
                }

            }


            byte kexDhInitType = isGroupExchange ? kexDhBuffer.readByte() : kexDhType;


            if (!(
                 (isGroupExchange && kexDhInitType == SshConstants.SSH_MSG_KEXDH_GEX_INIT) ||
                 (!isGroupExchange && kexDhInitType == SshConstants.SSH_MSG_KEXDH_INIT)
            )){
                
                if (isGroupExchange) {
                    logger.error("Expected SSH_MSG_KEXDH_GEX_INIT (32), but got message type: {}", kexDhInitType);
                } else {
                    logger.error("Expected SSH_MSG_KEXDH_INIT (30), but got message type: {}", kexDhInitType);
                }

                close();
                return;
            }

            SshBuffer kexDhInitBuffer = kexDhBuffer; // For clarity, rename this variable to indicate it's the KEXDH_INIT buffer

            // get client's public key e
            BigInteger clientE_BigInteger = kexDhInitBuffer.readMpint();
            byte[] clientE = clientE_BigInteger.toByteArray();
            
            logger.info("Received client's KEXDH_INIT with public key e ({} bytes)", clientE.length);

            // get server's public key f = g^x mod p
            byte[] serverF = kex.getPublicKey();
            

            // caclulate shared secret K = e^x mod p
            BigInteger sharedSecretK = kex.computeSharedSecret(clientE);


            // get host public key blob
            byte[] hostKeyBlob = hostKeyProvider.getPublicKeyBlob();


            // calculate exchange hash H
            byte[] exchangeHash = null;
            try {
                exchangeHash = KexUtils.calculateExchangeHash(
                    kex.getHashAlgorithm(),
                    clientVersion, SERVER_VERSION,
                    clientKexInitPayload, serverKexInitPayload,
                    hostKeyBlob, clientE, serverF, sharedSecretK,
                    kexAlgo, gexMin, gexPreferred, gexMax,
                    kex.getP(), kex.getG());
            } catch (Exception e) {
                logger.error("Failed to calculate exchange hash: {}", e.getMessage());
                close();
                return;
            }

            if (SessionId == null) {
                this.SessionId = exchangeHash; // For the first key exchange, the session ID is the exchange hash
            }

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

            SshBuffer kexReplyBuf = KexUtils.buildKexDhReply(hostKeyBlob, serverF, signatureBlob);

            try {
                sendPacket(kexReplyBuf);
            } catch (Exception e) {
                logger.error("Failed to send KEXDH_REPLY packet: {}", e.getMessage());
                close();
                return;
            }


            logger.info("Sent KEXDH_REPLY to client, key exchange complete!");


            // -------- NEWSKEY EXCHANGE PHASE --------


            SshBuffer newKeysBuf = new SshBuffer();
            newKeysBuf.writeByte(SshConstants.SSH_MSG_NEWKEYS);

            try {
                sendPacket(newKeysBuf);
            } catch (Exception e) {
                logger.error("Failed to send NEWKEYS packet: {}", e.getMessage());
                close();
                return;
            }

            logger.info("Sent NEWKEYS to client.");

            // generate the encryption keys and MAC keys 

            DerivedKeys keys = null;
            try {
                keys = KexUtils.deriveKeys(
                    sharedSecretK, exchangeHash, SessionId,
                    cipherC2S, cipherS2C,
                    macC2S, macS2C,
                    kex.getHashAlgorithm(), true);
            } catch (Exception e) {
                logger.error("Failed to derive keys: {}", e.getMessage());
                close();
                return;
            }

            this.currentDecryptor = keys.decryptor();
            this.currentEncryptor = keys.encryptor();
            this.inboundMac = keys.inboundMac();
            this.outboundMac = keys.outboundMac();


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
            packetReader.setMac(inboundMac);

            packetWriter.setCipher(currentEncryptor);
            packetWriter.setMac(outboundMac);


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
                sendDisconnectAndClose(SshConstants.SSH_DISCONNECT_PROTOCOL_ERROR, "Expected SERVICE_REQUEST");
                return;
            }


            String serviceName = serviceReqBuffer.readString();
            if (!serviceName.equals("ssh-userauth")) {
                logger.error("Unsupported service requested: {}", serviceName);
                sendDisconnectAndClose(SshConstants.SSH_DISCONNECT_SERVICE_NOT_AVAILABLE, serviceName);
                return;
            }

           
            logger.info("Received service request for ssh-userauth, sending SERVICE_ACCEPT...");

            SshBuffer serviceAcceptBuf = new SshBuffer();
            serviceAcceptBuf.writeByte(SshConstants.SSH_MSG_SERVICE_ACCEPT);
            serviceAcceptBuf.writeString(serviceName);

            try {
                sendPacket(serviceAcceptBuf);
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
                            sendAuthFailure(true);
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

                            SshBuffer authSuccessBuf = new SshBuffer();
                            authSuccessBuf.writeByte(SshConstants.SSH_MSG_USERAUTH_SUCCESS);

                            try {
                                sendPacket(authSuccessBuf);
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
                                sendAuthFailure(true); // allow retry for password auth
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

                            if (server.getPublicKeyAuthenticator() == null) {
                                logger.warn("No PublicKeyAuthenticator configured on server. Responding to all public key queries with allowed=false.");
                                try {
                                    sendAuthFailure(false); // respond with allowed=false to indicate we don't recognize this key type
                                } catch (Exception e) {
                                    logger.error("Failed to send USERAUTH_FAILURE packet: {}", e.getMessage());
                                    close();
                                    return;
                                }
                                continue;
                            }

                            if (!server.getPublicKeyAuthenticator().authenticate(user, keyBlob, this)) {
                                logger.warn("PublicKeyAuthenticator rejected the key query for user {}.", user);
                                try {
                                    sendAuthFailure(false); // respond with allowed=false to indicate the key is not authorized for this user
                                } catch (Exception e) {
                                    logger.error("Failed to send USERAUTH_FAILURE packet: {}", e.getMessage());
                                    close();
                                    return;
                                }
                                continue;
                            }

                            SshBuffer pkOkBuf = new SshBuffer();
                            pkOkBuf.writeByte(SshConstants.SSH_MSG_USERAUTH_PK_OK);
                            pkOkBuf.writeString(keyAlgo);
                            pkOkBuf.writeByteString(keyBlob, 0, keyBlob.length);

                            try {
                                sendPacket(pkOkBuf);
                            } catch (Exception e) {
                                logger.error("Failed to send USERAUTH_PK_OK packet: {}", e.getMessage());
                                close();
                                return;
                            }

                        } else {
                            
                            logger.warn("Public key authentication with signature");

                            byte[] keySignatureBlob = packet.readByteString(); 
                    
                            // Reconstruct the "Signed Data" per RFC 4252 Section 7
                            SshBuffer buffer = new SshBuffer();
                            buffer.writeByteString(this.SessionId, 0 , this.SessionId.length); // 1. Session ID (string)
                            buffer.writeByte(SshConstants.SSH_MSG_USERAUTH_REQUEST); // 2. Msg ID
                            buffer.writeString(user);      // 3. Username
                            buffer.writeString(service);   // 4. Service ("ssh-connection")
                            buffer.writeString("publickey"); // 5. Method
                            buffer.writeBoolean(true);     // 6. Has Signature (TRUE)
                            buffer.writeString(keyAlgo); // 7. Algo Name
                            buffer.writeByteString(keyBlob, 0, keyBlob.length); // 8. The Key Blob (string)
                            
                            byte[] dataToVerify = buffer.getCompactData();

                            // decode the public key from the blob
                            
                            PublicKey clientPublicKey = null;

                            try {
                                clientPublicKey = SshKeyDecoder.decodePublicKey(keyBlob);
                            } catch (Exception e) {
                                logger.error("Failed to decode client's public key blob: {}", e.getMessage());
                                try {
                                    sendAuthFailure(false); // don't allow retry if key blob is invalid
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
                                    sendAuthFailure(false); // don't allow retry if signature verification fails
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
                                    sendAuthFailure(true); // allow retry for invalid signature
                                } catch (Exception e) {
                                    logger.error("Failed to send USERAUTH_FAILURE packet: {}", e.getMessage());
                                    close();
                                    return;
                                }
                                continue; // Do not fall through to success
                            }

                            // TODO:
                            // we will check the username and the key blob against our list of authorized keys for that user. If it matches, we accept the authentication.
                            // but for now we will just accept any valid signature with a key type we support, to demonstrate the flow.


                            logger.info("Public key authentication successful for user {}!", user);


                            SshBuffer pubkeySuccessBuf = new SshBuffer();
                            pubkeySuccessBuf.writeByte(SshConstants.SSH_MSG_USERAUTH_SUCCESS);

                            try {
                                sendPacket(pubkeySuccessBuf);
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
                            sendAuthFailure(false); // don't allow retry for unsupported methods
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


            // ------ SERVER and CLIENT are now peered ----------- 

            logger.info("Entering main loop to handle client requests...");

            while (true) {

                try {

                    SshBuffer incomingPacket = packetReader.readPacket();
                    byte incomingMsgId = incomingPacket.readByte();

                    logger.info("Received packet with Msg ID: {}", incomingMsgId);
                    if (incomingMsgId == SshConstants.SSH_MSG_DISCONNECT) {
                        
                        int reasonCode = (int)incomingPacket.readUInt32();
                        String description = incomingPacket.readString();
                        logger.info("Client sent disconnect: {} - {}", reasonCode, description);
                        break;

                    }else if (incomingMsgId == SshConstants.SSH_MSG_CHANNEL_OPEN) {

                        byte[] channelOpenResponse = channelManager.handleChannelOpen(incomingPacket);
                        if (channelOpenResponse != null) {
                            sendPacket(new SshBuffer(channelOpenResponse));
                        }

                    }else if(incomingMsgId == SshConstants.SSH_MSG_CHANNEL_REQUEST) {

                        byte[] channelRequestResponse = channelManager.handleChannelRequest(incomingPacket);
                        if (channelRequestResponse != null) {
                            sendPacket(new SshBuffer(channelRequestResponse));
                        }

                    }else if(incomingMsgId == SshConstants.SSH_MSG_CHANNEL_DATA) {

                        channelManager.handleChannelData(incomingPacket);

                    }else if( incomingMsgId == SshConstants.SSH_MSG_CHANNEL_WINDOW_ADJUST){

                        channelManager.handleChannelWindowAdjust(incomingPacket);
                    
                    }else if (incomingMsgId == SshConstants.SSH_MSG_CHANNEL_CLOSE) {

                        channelManager.handleChannelClose(incomingPacket);

                    }else if (incomingMsgId == SshConstants.SSH_MSG_CHANNEL_EOF) {

                        channelManager.handleChannelEOF(incomingPacket);
                    
                    }else if (incomingMsgId == SshConstants.SSH_MSG_CHANNEL_OPEN_CONFIRMATION) {

                        channelManager.handleChannelOpenConfirmation(incomingPacket);
                    
                    }else if (incomingMsgId == SshConstants.SSH_MSG_CHANNEL_OPEN_FAILURE) {

                        channelManager.handleChannelOpenFailure(incomingPacket);
                    
                    }else if( incomingMsgId == SshConstants.SSH_MSG_GLOBAL_REQUEST){

                        logger.info("Received global request");

                        String requestName = incomingPacket.readString();
                        boolean wantReply = incomingPacket.readBoolean();

                        logger.info("Global Request: {}, wantReply={}", requestName, wantReply);

                        if ("tcpip-forward".equals(requestName)) {

                            String bindAddress = incomingPacket.readString();
                            int bindPort = (int)incomingPacket.readUInt32();                            

                            boolean success = forwardingManager.requestForwarding(bindAddress, bindPort);

                            if (wantReply) {
                                SshBuffer reply = new SshBuffer();
                                if (success) {
                                    reply.writeByte(SshConstants.SSH_MSG_REQUEST_SUCCESS);
                                } else {
                                    reply.writeByte(SshConstants.SSH_MSG_REQUEST_FAILURE);
                                }
                                sendPacket(reply);
                            }


                        } else { 

                            logger.warn("Unsupported global request: {}", requestName);
                            
                            if (wantReply) {
                                SshBuffer reply = new SshBuffer();
                                reply.writeByte(SshConstants.SSH_MSG_REQUEST_FAILURE);
                                sendPacket(reply);
                            }

                        }


                    }else{
                        logger.warn("Received unhandled message type: {}", incomingMsgId);
                    }

                } catch (Exception e) {

                    logger.error("Error reading or handling packet: ", e);
                    break;

                }
            }
                        
        } catch (Exception e) {
            logger.error("Session error: {}", e.getMessage());
        } finally {
            close();
        }
    }


    private void sendKexInit() throws IOException {

        SshBuffer payload = KexUtils.buildKexInitPayload();
        this.serverKexInitPayload = payload.getCompactData();

        try {
            sendPacket(payload);
        } catch (Exception e) {
            logger.error("Failed to generate KEXINIT packet: {}", e.getMessage());
            return;
        }

    }


    /**
     * send authentication failure with a list of supported methods 
     * and a boolean indicating whether the client can try again (false if max attempts reached or method was not recognized)
     */

    private void sendAuthFailure(boolean canRetry) throws Exception {
        SshBuffer buf = new SshBuffer();
        buf.writeByte(SshConstants.SSH_MSG_USERAUTH_FAILURE);
        buf.writeString(SshConstants.SUPPORTED_AUTH_METHODS);
        buf.writeBoolean(canRetry);
        sendPacket(buf);
    }

    /**
     * send SSH_MSG_DISCONNECT with a reason code and message, then close the connection
     */

    private void sendDisconnectAndClose(int reasonCode, String message) {
        try {
            sendPacket(SshProtocolUtils.buildDisconnectPacket(reasonCode, message));
        } catch (Exception e) {
            logger.error("Failed to send DISCONNECT packet: {}", e.getMessage());
        } finally {
            close();
        }
    }

    public void sendPacket(SshBuffer buffer) throws IOException {
        packetWriter.writePacket(buffer);
    }

    public ChannelManager getChannelManager() {
        return channelManager;
    }


    private void close() {
        
        try {

            logger.info("Closing session for {}", clientSocket.getRemoteSocketAddress());
            if (clientSocket != null && !clientSocket.isClosed()) {
                clientSocket.close();
            }

            // also close all channels
            channelManager.closeAllChannels();

            // also stop all forwarding listeners
            forwardingManager.closeAll();

        } catch (IOException e) {
            logger.error("Error closing socket", e);
        }
    }
}