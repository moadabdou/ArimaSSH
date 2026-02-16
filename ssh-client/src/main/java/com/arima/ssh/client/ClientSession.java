package com.arima.ssh.client;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.arima.ssh.common.NegotiationUtils;
import com.arima.ssh.common.PacketReader;
import com.arima.ssh.common.PacketWriter;
import com.arima.ssh.common.SshBuffer;
import com.arima.ssh.common.SshConstants;
import com.arima.ssh.common.SshProtocolUtils;
import com.arima.ssh.common.crypto.SshCipher;
import com.arima.ssh.common.crypto.SshMac;
import com.arima.ssh.common.kex.DerivedKeys;
import com.arima.ssh.common.kex.KexInitData;
import com.arima.ssh.common.kex.KexUtils;
import com.arima.ssh.common.kex.KeyExchange;

public class ClientSession {

    private static final String CLIENT_VERSION = "SSH-2.0-ArimaSSHClient_0.1";

    private static final Logger logger = LoggerFactory.getLogger(ClientSession.class);

    private final Socket serverSocket;
    private final SshClient client;
   
    private InputStream inputStream;
    private OutputStream outputStream;


    private String serverVersion;

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
    private PacketReader packetReader;


    private long gexMin; 
    private long gexPreferred;
    private long gexMax;


    public ClientSession(Socket serverSocket, SshClient client) {
        this.serverSocket = serverSocket;
        this.client = client;
    }

    public SshClient getClient() {
        return client;
    }

    public void init () throws Exception
    {

        logger.info("client session started for {}", serverSocket.getRemoteSocketAddress());

        try {
            

            inputStream = serverSocket.getInputStream();
            outputStream = serverSocket.getOutputStream();

            packetWriter = new PacketWriter(outputStream);

            // --------- TEXT PROTOCOL EXCHANGE ---------

            // version exchange

            serverVersion = SshProtocolUtils.readLine(inputStream);

            if (!serverVersion.startsWith("SSH-2.0-")) {
                throw new IOException("Unsupported SSH version: " + serverVersion);
            }

            logger.info("server Identification: {}", serverVersion);

            outputStream.write((CLIENT_VERSION + "\r\n").getBytes(StandardCharsets.UTF_8));
            outputStream.flush();
            logger.debug("Sent version: {}", CLIENT_VERSION);

            // --------- BINARY PROTOCOL EXCHANGE ---------

            packetReader = new PacketReader(inputStream);
            packetWriter = new PacketWriter(outputStream);


            // read server's KEXINIT
            SshBuffer serverKexInitBuffer = null;

            try {
                serverKexInitBuffer = packetReader.readPacket();
            } catch (Exception e) {
                throw new IOException("Failed to read server's KEXINIT: " + e.getMessage(), e);
            }

            serverKexInitPayload = serverKexInitBuffer.getCompactData();
            
            byte kexInitType = serverKexInitBuffer.readByte();
            if (kexInitType != SshConstants.SSH_MSG_KEXINIT) {
                throw new IOException("Expected SSH_MSG_KEXINIT, but got message type: " + kexInitType);
            }

            logger.info("Received server's KEXINIT packet, length: {}", serverKexInitBuffer.wpos());

            // send KEXINIT
            sendKexInit();

            logger.info("Sent KEXINIT to client, waiting for client's KEXINIT...");

            KexInitData serverKexData = KexUtils.parseKexInit(serverKexInitBuffer);

            logger.info("Received server's KEXINIT:");
            logger.info("  Kex Algos: {}", serverKexData.kexAlgos());
            logger.info("  Host Key Algos: {}", serverKexData.hostKeyAlgos());
            logger.info("  Cipher Algos C->S: {}", serverKexData.cipherC2S());
            logger.info("  Cipher Algos S->C: {}", serverKexData.cipherS2C());
            logger.info("  MAC Algos C->S: {}", serverKexData.macC2S());
            logger.info("  MAC Algos S->C: {}", serverKexData.macS2C());
            logger.info("  Compression Algos C->S: {}", serverKexData.compC2S());
            logger.info("  Compression Algos S->C: {}", serverKexData.compS2C());
            logger.info("  Lang C->S: {}", serverKexData.langC2S());
            logger.info("  Lang S->C: {}", serverKexData.langS2C());
            logger.info("  First KEX Packet Follows: {}", serverKexData.firstKexPacketFollows());
            logger.info("  Reserved: {}", serverKexData.reserved());


            this.kexAlgo = NegotiationUtils.negotiate(serverKexData.kexAlgos(), SshConstants.PROPOSAL_KEX);
            this.hostKeyAlgo = NegotiationUtils.negotiate(serverKexData.hostKeyAlgos(), SshConstants.PROPOSAL_HOST_KEY);
            this.cipherC2S = NegotiationUtils.negotiate(serverKexData.cipherC2S(), SshConstants.PROPOSAL_CIPHER);
            this.cipherS2C = NegotiationUtils.negotiate(serverKexData.cipherS2C(), SshConstants.PROPOSAL_CIPHER);
            this.macC2S = NegotiationUtils.negotiate(serverKexData.macC2S(), SshConstants.PROPOSAL_MAC);
            this.macS2C = NegotiationUtils.negotiate(serverKexData.macS2C(), SshConstants.PROPOSAL_MAC);
            this.compC2S = NegotiationUtils.negotiate(serverKexData.compC2S(), SshConstants.PROPOSAL_COMPRESSION);
            this.compS2C = NegotiationUtils.negotiate(serverKexData.compS2C(), SshConstants.PROPOSAL_COMPRESSION);

            if (kexAlgo == null ||
                hostKeyAlgo == null ||
                cipherC2S == null || 
                cipherS2C == null ||
                macC2S == null ||
                macS2C == null ||
                compC2S == null ||
                compS2C == null) 
            {
                throw new IOException("Algorithm negotiation failed:"
                    + " kex=" + kexAlgo
                    + ", hostKey=" + hostKeyAlgo
                    + ", cipherC2S=" + cipherC2S
                    + ", cipherS2C=" + cipherS2C
                    + ", macC2S=" + macC2S
                    + ", macS2C=" + macS2C
                    + ", compC2S=" + compC2S
                    + ", compS2C=" + compS2C);
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


            // If using a group exchange method, we need to request the group parameters from the server

            boolean isGroupExchange = kexAlgo.startsWith("diffie-hellman-group-exchange");

            if (isGroupExchange) {

                // init GEX parameters to some safe defaults (RFC 4419 recommends at least 1024 bits, but we'll use 2048 as a minimum)
                this.gexMin = 2048;
                this.gexPreferred = 4096;
                this.gexMax = 8192;
               
                //send the group request
                SshBuffer gexRequest = KexUtils.buildGexRequest(gexMin, gexPreferred, gexMax);
                sendPacket(gexRequest);

                //read the group reply
                SshBuffer gexReplyBuffer = packetReader.readPacket();
                byte gexReplyType = gexReplyBuffer.readByte();
                if (gexReplyType != SshConstants.SSH_MSG_KEXDH_GEX_GROUP) {
                    throw new IOException("Expected SSH_MSG_KEXDH_GEX_GROUP, but got message type: " + gexReplyType);
                }

                // read the group parameters
                BigInteger p = gexReplyBuffer.readMpint();
                BigInteger g = gexReplyBuffer.readMpint();

                logger.info("Received GEX group from server, p length: {}, g length: {}", p.toByteArray().length, g.toByteArray().length);

                kex.setP(p);
                kex.setG(g);


            }

            // send our public key (or the initial GEX message) to the server
            

            byte[] clientE = kex.getPublicKey();
            SshBuffer kexDhInit = KexUtils.buildKexDhInit(clientE, isGroupExchange);
            sendPacket(kexDhInit);

            logger.info("Sending client's KEXDH_INIT message to server...");

            // read server's reply containing host key blob, server public key f, and signature blob

            SshBuffer kexReplyBuffer = packetReader.readPacket();
            byte kexReplyType = kexReplyBuffer.readByte();
            if (kexReplyType != SshConstants.SSH_MSG_KEXDH_REPLY) {
                throw new IOException("Expected SSH_MSG_KEXDH_REPLY, but got message type: " + kexReplyType);
            }

            byte[] hostKeyBlob = kexReplyBuffer.readByteString();
            byte[] serverF =  kexReplyBuffer.readByteString();
            byte[] signatureBlob = kexReplyBuffer.readByteString();

            logger.info("Received KEXDH_REPLY from server, host key blob length: {}, server F length: {}, signature blob length: {}",
                hostKeyBlob.length, serverF.length, signatureBlob.length);

            // calculate the shared secret 

            BigInteger sharedSecretK = kex.computeSharedSecret(serverF);

            // calculate the exchange hash

            byte[] exchangeHash = null;

            try {

                exchangeHash = KexUtils.calculateExchangeHash(
                    kex.getHashAlgorithm(), 
                    CLIENT_VERSION, serverVersion,
                    clientKexInitPayload, serverKexInitPayload, 
                    hostKeyBlob, clientE, serverF, sharedSecretK,
                    kexAlgo, gexMin, gexPreferred, gexMax,
                    kex.getP(), kex.getG()
                );

            } catch (Exception e) {
                throw new IOException("Failed to compute exchange hash: " + e.getMessage(), e);
            }

            //verify the server's signature on the exchange hash using the host key blob

            boolean signatureValid = KexUtils.verifyServerSignature(hostKeyBlob, signatureBlob, exchangeHash);

            if (!signatureValid) {
                throw new IOException("Server's KEX signature verification failed");
            }

            // save the session ID if this is the first key exchange
            if (SessionId == null) {
                SessionId = exchangeHash;
            }

            // --------- NEWSKEY EXCHANGE PHASE ---------

            // send NEWKEYS message to server
            SshBuffer newKeysMsg = new SshBuffer();
            newKeysMsg.writeByte(SshConstants.SSH_MSG_NEWKEYS);
            
            try {
                sendPacket(newKeysMsg);
            } catch (Exception e) {
                throw new IOException("Failed to send NEWKEYS message: " + e.getMessage(), e);
            }


            // generate the encryption key and MAC keys

            DerivedKeys keys = null;

            try {
                keys = KexUtils.deriveKeys(
                    sharedSecretK, exchangeHash, SessionId,
                    cipherC2S, cipherS2C,
                    macC2S, macS2C,
                    kex.getHashAlgorithm(),
                    false
                );
            } catch (Exception e) {
                throw new IOException("Failed to derive keys: " + e.getMessage(), e);
            }

            currentDecryptor = keys.decryptor();
            currentEncryptor = keys.encryptor();
            inboundMac = keys.inboundMac();
            outboundMac = keys.outboundMac();


            // read server's NEWKEYS message

            SshBuffer serverNewKeysBuffer = null;
            
            try {
                serverNewKeysBuffer = packetReader.readPacket();
            } catch (Exception e) {
                throw new IOException("Failed to read server's NEWKEYS message: " + e.getMessage(), e);
            }


            byte serverNewKeysType = serverNewKeysBuffer.readByte();
            if (serverNewKeysType != SshConstants.SSH_MSG_NEWKEYS) {
                throw new IOException("Expected SSH_MSG_NEWKEYS from server, but got message type: " + serverNewKeysType);
            }

            logger.info("Key exchange complete, secure channel established!");

            // activate the new keys for subsequent communication
            packetReader.setCipher(currentDecryptor);
            packetReader.setMac(inboundMac);
            packetWriter.setCipher(currentEncryptor);
            packetWriter.setMac(outboundMac);

            

            // initiate the user authentication phase

            logger.info("Initiating user authentication phase...");

            SshBuffer authRequest = new SshBuffer();
            authRequest.writeByte(SshConstants.SSH_MSG_SERVICE_REQUEST);
            authRequest.writeString("ssh-userauth");

             try {
                sendPacket(authRequest);
            } catch (Exception e) {
                throw new IOException("Failed to send service request: " + e.getMessage(), e);
            }

            SshBuffer authResponse = null;

            try {
                authResponse = packetReader.readPacket();
            } catch (Exception e) {
                throw new IOException("Failed to read service accept response: " + e.getMessage(), e);
            }

            byte authResponseType = authResponse.readByte();
            if (authResponseType != SshConstants.SSH_MSG_SERVICE_ACCEPT) {
                throw new IOException("Expected SSH_MSG_SERVICE_ACCEPT, but got message type: " + authResponseType);
            }

            logger.info("Server accepted ssh-userauth service request, ready to authenticate!");


        } catch (Exception e) {
            close();
            throw new IOException("Failed to init session: " + e.getMessage(), e);
        }

    }

    public String requestAuthMethods() throws IOException {

        logger.info("Requesting supported authentication methods from server for user '{}'", client.getUsername());

        SshBuffer authRequest = new SshBuffer();
        authRequest.writeByte(SshConstants.SSH_MSG_USERAUTH_REQUEST);
        authRequest.writeString(client.getUsername());
        authRequest.writeString("ssh-connection");
        authRequest.writeString("none");

        try {
            sendPacket(authRequest);
        } catch (Exception e) {
            throw new IOException("Failed to send authentication request: " + e.getMessage(), e);
        }

        SshBuffer responseBuffer = null;

        try {
            responseBuffer = packetReader.readPacket();
        } catch (Exception e) {
            throw new IOException("Failed to read authentication response: " + e.getMessage(), e);
        }

        byte responseType = responseBuffer.readByte();

        if (responseType == SshConstants.SSH_MSG_USERAUTH_FAILURE) {
            String methods = responseBuffer.readString();
            logger.info("supported methods: {}", methods);
            return methods;
        } else if (responseType == SshConstants.SSH_MSG_USERAUTH_SUCCESS) {
            logger.info("Unexpectedly authenticated without credentials");
            return null;
        } else {
            throw new IOException("Unexpected message type during authentication: " + responseType);
        }

    }


    private void sendKexInit() throws IOException {

        SshBuffer payload = KexUtils.buildKexInitPayload();
        this.clientKexInitPayload = payload.getCompactData();

        try {
            sendPacket(payload);
        } catch (Exception e) {
            throw new IOException("Failed to send KEXINIT packet: " + e.getMessage(), e);
        }

    }  

    public void sendPacket(SshBuffer buffer) throws IOException {
        packetWriter.writePacket(buffer);
    }  


    private void close() {
        
        try {

            logger.info("Closing session for {}", serverSocket.getRemoteSocketAddress());
            if (serverSocket != null && !serverSocket.isClosed()) {
                serverSocket.close();
            }

        } catch (IOException e) {
            logger.error("Error closing socket", e);
        }
    }
}
