package com.arima.ssh.client;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Map;

import org.jline.terminal.Terminal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.arima.ssh.client.channel.ClientChannelManager;
import com.arima.ssh.client.channel.SessionChannel;
import com.arima.ssh.common.NegotiationUtils;
import com.arima.ssh.common.PacketReader;
import com.arima.ssh.common.PacketWriter;
import com.arima.ssh.common.SshBuffer;
import com.arima.ssh.common.SshConstants;
import com.arima.ssh.common.SshProtocolUtils;
import com.arima.ssh.common.channel.Session;
import com.arima.ssh.common.crypto.SignatureUtils;
import com.arima.ssh.common.crypto.SshCipher;
import com.arima.ssh.common.crypto.SshKeyDecoder;
import com.arima.ssh.common.crypto.SshMac;
import com.arima.ssh.common.kex.DerivedKeys;
import com.arima.ssh.common.kex.KexInitData;
import com.arima.ssh.common.kex.KexUtils;
import com.arima.ssh.common.kex.KeyExchange;

public class ClientSession implements Session {

    private static final String CLIENT_VERSION = "SSH-2.0-ArimaSSHClient_0.1";

    private static final Logger logger = LoggerFactory.getLogger(ClientSession.class);

    private final String host;
    private final int port;
    private Socket serverSocket;
    private final SshClient client;

    private final Terminal terminal;
   
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

    private ClientChannelManager channelManager;
    private ClientForwardingManager forwardingManager;


    public ClientSession(String host, int port , SshClient client, Terminal terminal) {
        this.host = host;
        this.port = port;
        this.client = client;
        this.terminal = terminal;
        this.channelManager = new ClientChannelManager(this);
        this.forwardingManager = new ClientForwardingManager(this.channelManager);
    }

    public SshClient getClient() {
        return client;
    }

    public Terminal getTerminal() {
        return terminal;
    }

    public boolean isConnected() {
        return serverSocket != null && serverSocket.isConnected() && !serverSocket.isClosed();
    }

    public ClientChannelManager getChannelManager() {
        return channelManager;
    }

    public void init () throws Exception
    {

        logger.info("client session started for {}:{}", host, port);

        try {


            // ---------- CONNECT TO SERVER AND INITIALIZE STREAMS -----------

            
            InetAddress address = InetAddress.getByName(host);
            serverSocket = new Socket(address, port);

            inputStream = serverSocket.getInputStream();
            outputStream = serverSocket.getOutputStream();

            logger.info("Successfully connected to {}", serverSocket.getRemoteSocketAddress());



            // --------- INITIAL PROTOCOL EXCHANGE ---------
            

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
            if (!(
                 (isGroupExchange && kexReplyType == SshConstants.SSH_MSG_KEXDH_GEX_REPLY) ||
                 (!isGroupExchange && kexReplyType == SshConstants.SSH_MSG_KEXDH_REPLY)
            )) {
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

    public void handleIncomingPacket() throws Exception {

        SshBuffer incomingPacket = packetReader.readPacket();
        byte incomingMsgId = incomingPacket.readByte();

        logger.info("Received packet with Msg ID: {}", incomingMsgId);

        if (incomingMsgId == SshConstants.SSH_MSG_DISCONNECT) {
            
            int reasonCode = (int)incomingPacket.readUInt32();
            String description = incomingPacket.readString();
            logger.info("Client sent disconnect: {} - {}", reasonCode, description);
            close();

        }else if (incomingMsgId == SshConstants.SSH_MSG_CHANNEL_SUCCESS || incomingMsgId == SshConstants.SSH_MSG_CHANNEL_FAILURE) {

            channelManager.handleChannelReplay(incomingMsgId, incomingPacket);
        
        }else if(incomingMsgId == SshConstants.SSH_MSG_CHANNEL_DATA) {

            channelManager.handleChannelData(incomingPacket);

        }else if( incomingMsgId == SshConstants.SSH_MSG_CHANNEL_WINDOW_ADJUST){

            channelManager.handleChannelWindowAdjust(incomingPacket);
        
        }else if (incomingMsgId == SshConstants.SSH_MSG_CHANNEL_CLOSE) {
            
            channelManager.handleChannelClose(incomingPacket);
            
        }else if (incomingMsgId == SshConstants.SSH_MSG_CHANNEL_EOF) {

            channelManager.handleChannelEOF(incomingPacket);
        
        }else if (incomingMsgId == SshConstants.SSH_MSG_CHANNEL_REQUEST) {

            byte[] reply = channelManager.handleChannelRequest(incomingPacket);
            if (reply != null) {
                SshBuffer replyBuffer = new SshBuffer();
                replyBuffer.writeBytes(reply, 0, reply.length);
                sendPacket(replyBuffer);
            }

        }else if (incomingMsgId == SshConstants.SSH_MSG_CHANNEL_OPEN_CONFIRMATION) {

            channelManager.handleChannelOpenConfirmation(incomingPacket);
        
        }else if (incomingMsgId == SshConstants.SSH_MSG_CHANNEL_OPEN_FAILURE) {

            channelManager.handleChannelOpenFailure(incomingPacket);
        
        }else if (incomingMsgId == SshConstants.SSH_MSG_CHANNEL_OPEN) {

            byte[] channelOpenResponse = channelManager.handleChannelOpen(incomingPacket);
            if (channelOpenResponse != null) {
                sendPacket(new SshBuffer(channelOpenResponse));
            }
        
        }else if (incomingMsgId == SshConstants.SSH_MSG_GLOBAL_REQUEST) {

            logger.info("Received global request from server");
            String requestName = incomingPacket.readString();
            boolean wantReply = incomingPacket.readBoolean();
            logger.info("Global Request: {}, wantReply={}", requestName, wantReply);

            // Client does not handle any global requests yet
            if (wantReply) {
                SshBuffer reply = new SshBuffer();
                reply.writeByte(SshConstants.SSH_MSG_REQUEST_FAILURE);
                sendPacket(reply);
            }

        }else if (incomingMsgId == SshConstants.SSH_MSG_REQUEST_SUCCESS) {

            logger.info("Global request succeeded (e.g. tcpip-forward accepted by server)");

        }else if (incomingMsgId == SshConstants.SSH_MSG_REQUEST_FAILURE) {

            logger.warn("Global request failed (e.g. tcpip-forward rejected by server)");

        }else{
            logger.warn("Received unhandled message type: {}", incomingMsgId);
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

    public boolean authenticateWithPassword(String password) throws IOException {

        logger.info("Attempting password authentication for user '{}'", client.getUsername());

        SshBuffer authRequest = new SshBuffer();
        authRequest.writeByte(SshConstants.SSH_MSG_USERAUTH_REQUEST);
        authRequest.writeString(client.getUsername());
        authRequest.writeString("ssh-connection");
        authRequest.writeString("password");
        authRequest.writeBoolean(false); // no password change request
        authRequest.writeString(password);

        try {
            sendPacket(authRequest);
        } catch (Exception e) {
            throw new IOException("Failed to send password authentication request: " + e.getMessage(), e);
        }

        SshBuffer responseBuffer = null;

        try {
            responseBuffer = packetReader.readPacket();
        } catch (Exception e) {
            throw new IOException("Failed to read authentication response: " + e.getMessage(), e);
        }

        byte responseType = responseBuffer.readByte();

        if (responseType == SshConstants.SSH_MSG_USERAUTH_SUCCESS) {
            logger.info("Password authentication successful!");
            return true;
        } else if (responseType == SshConstants.SSH_MSG_USERAUTH_FAILURE) {
            String methods = responseBuffer.readString();
            logger.info("Password authentication failed, supported methods are: {}", methods);
            return false;
        } else {
            throw new IOException("Unexpected message type during authentication: " + responseType);
        }

    }

    public boolean authenticateWithPublicKey(KeyPair keyPair) throws Exception{


        //check if the server accepts this key for authentication

        String sshAlgo = SshKeyDecoder.getSshKeyType(keyPair.getPublic());

        byte[] publicKeyBlob = SshKeyDecoder.encodePublicKey(keyPair.getPublic());

        SshBuffer authRequest = buildPublicKeyAuthRequest(sshAlgo, publicKeyBlob, null);

        sendPacket(authRequest);

        // check server's response

        SshBuffer responseBuffer = packetReader.readPacket();
        byte responseType = responseBuffer.readByte();

        if(responseType == SshConstants.SSH_MSG_USERAUTH_FAILURE) {
            String methods = responseBuffer.readString();
            logger.info("Server does not accept this public key for authentication, supported methods are: {}", methods);
            return false;
        } else if (responseType != SshConstants.SSH_MSG_USERAUTH_PK_OK) {
            throw new IOException("Unexpected message type during public key authentication: " + responseType);
        }

        // server accepted the key, now we need to send the signature

        SshBuffer signBuffer = new SshBuffer();
        signBuffer.writeByteString(this.SessionId, 0 , this.SessionId.length); // 1. Session ID (string)
        signBuffer.writeByte(SshConstants.SSH_MSG_USERAUTH_REQUEST); // 2. Msg ID
        signBuffer.writeString(client.getUsername());      // 3. Username
        signBuffer.writeString("ssh-connection");   // 4. Service ("ssh-connection")
        signBuffer.writeString("publickey"); // 5. Method
        signBuffer.writeBoolean(true);     // 6. Has Signature (TRUE)
        signBuffer.writeString(sshAlgo); // 7. Algo Name
        signBuffer.writeByteString(publicKeyBlob, 0, publicKeyBlob.length); // 8. The Key Blob (string)

        byte[] dataToSign = signBuffer.getCompactData();

        // sign the data with the client's private key
        java.security.Signature signature = java.security.Signature.getInstance(SignatureUtils.mapSshAlgoToJava(sshAlgo));
        signature.initSign(keyPair.getPrivate());
        signature.update(dataToSign);
        byte[] rawSignature = signature.sign();

        // build the signature blob according to RFC 8332 (string containing algo name + string containing raw signature)

        SshBuffer signatureBlobBuffer = new SshBuffer();
        signatureBlobBuffer.writeString(sshAlgo);
        signatureBlobBuffer.writeByteString(rawSignature, 0, rawSignature.length);
        byte[] signatureBlob = signatureBlobBuffer.getCompactData();

        // send the authentication request with the signature
        SshBuffer authRequestWithSig = buildPublicKeyAuthRequest(sshAlgo, publicKeyBlob, signatureBlob);
        sendPacket(authRequestWithSig);

        // check server's response
        SshBuffer finalResponseBuffer = packetReader.readPacket();
        byte finalResponseType = finalResponseBuffer.readByte();

        if (finalResponseType == SshConstants.SSH_MSG_USERAUTH_SUCCESS) {
            logger.info("Public key authentication successful!");
            return true;
        } else if (finalResponseType == SshConstants.SSH_MSG_USERAUTH_FAILURE) {
            String methods = finalResponseBuffer.readString();
            logger.info("Public key authentication failed, supported methods are: {}", methods);
            return false;
        } else {
            throw new IOException("Unexpected message type during authentication: " + finalResponseType);
        }

    }

    private SshBuffer buildPublicKeyAuthRequest(String algoName, byte[] publicKeyBlob, byte[] signature) {

        SshBuffer buffer = new SshBuffer();
        buffer.writeByte(SshConstants.SSH_MSG_USERAUTH_REQUEST);
        buffer.writeString(client.getUsername());
        buffer.writeString("ssh-connection");
        buffer.writeString("publickey");
        buffer.writeBoolean(signature != null); // indicate that we are including a signature
        buffer.writeString(algoName);
        buffer.writeByteString(publicKeyBlob, 0, publicKeyBlob.length);

        if (signature != null){
            buffer.writeByteString(signature, 0, signature.length);
        }

        return buffer;
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


    /**
     * Request remote forwarding (-R): asks the server to listen on bindAddr:bindPort.
     * When a connection arrives there, the server sends "forwarded-tcpip" channel-open
     * which our ClientChannelManager handles by creating a RemoteTcpIpChannel.
     */
    public void requestRemoteForwarding(String bindAddr, int bindPort, String targetHost, int targetPort) throws IOException {
        logger.info("Requesting remote forwarding: {}:{} -> {}:{}", bindAddr, bindPort, targetHost, targetPort);
        
        channelManager.registerRemoteTcpIp(bindAddr, bindPort, targetHost, targetPort);

        SshBuffer buffer = new SshBuffer();
        buffer.writeByte(SshConstants.SSH_MSG_GLOBAL_REQUEST);
        buffer.writeString("tcpip-forward");
        buffer.writeBoolean(true); // want reply
        buffer.writeString(bindAddr);
        buffer.writeUInt32(bindPort);
        sendPacket(buffer);
    }

    /**
     * Request local forwarding (-L): binds a local port and tunnels connections
     * to the remote side via "direct-tcpip" channel-open messages.
     */
    public boolean requestLocalForwarding(String bindAddr, int bindPort, String targetHost, int targetPort) {
        logger.info("Requesting local forwarding: {}:{} -> {}:{}", bindAddr, bindPort, targetHost, targetPort);
        return forwardingManager.requestForwarding(bindAddr, bindPort, targetHost, targetPort);
    }

    public ClientForwardingManager getForwardingManager() {
        return forwardingManager;
    }

    public void sendOpenSessionChannel(Map<String, Object> envVariables, String execCommand )throws IOException {
    
        // register the session channel

        SessionChannel channel = new SessionChannel(this, envVariables, execCommand);

        long myId = channelManager.registerChannel(channel);


        // build the channel open request for a session channel
        SshBuffer buffer = new SshBuffer();
        buffer.writeByte(SshConstants.SSH_MSG_CHANNEL_OPEN);
        buffer.writeString("session"); // channel type
        buffer.writeUInt32(myId); // sender channel
        buffer.writeUInt32(1024 * 1024); // initial window size (1MB)
        buffer.writeUInt32(32 * 1024); // max packet size (32KB)

        try {
            sendPacket(buffer);
        } catch (Exception e) {
            throw new IOException("Failed to send channel open request: " + e.getMessage(), e);
        }

    }

    public void sendPacket(SshBuffer buffer) throws IOException {
        packetWriter.writePacket(buffer);
    }  

    private void sendDisconnect(int reasonCode, String description) throws IOException {
        SshBuffer buffer = new SshBuffer();
        buffer.writeByte(SshConstants.SSH_MSG_DISCONNECT);
        buffer.writeUInt32(reasonCode);
        buffer.writeString(description);
        sendPacket(buffer);
    }

    public void close() {
        
        try {

            if (serverSocket != null && !serverSocket.isClosed()) {
                sendDisconnect(SshConstants.SSH_DISCONNECT_BY_APPLICATION, "Client disconnecting");
                logger.info("Closing session for {}", serverSocket.getRemoteSocketAddress());
                serverSocket.close();
            }

            if (channelManager != null){
                channelManager.closeAllChannels();
            }

            if (forwardingManager != null){
                forwardingManager.closeAll();
            }
            
            System.out.println("Hmph! It's not like I wanted to keep this session open anyway. Don't take it personally... bye bye!");

        } catch (IOException e) {
            logger.error("Error closing socket", e);
        }
    }
}
