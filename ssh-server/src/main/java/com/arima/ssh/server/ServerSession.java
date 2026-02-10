
package com.arima.ssh.server;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

import java.security.SecureRandom;
import com.arima.ssh.common.*;

public class ServerSession implements Runnable {

    private static final Logger logger = LoggerFactory.getLogger(ServerSession.class);

    // RFC 4253: The version string MUST begin with "SSH-2.0-"
    private static final String SERVER_VERSION = "SSH-2.0-ArimaSSH_1.0";

    private final Socket clientSocket;
    private InputStream inputStream;
    private OutputStream outputStream;

    private String clientVersion;


    private byte[] serverKexInitPayload; 
    private byte[] clientKexInitPayload;


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

            // send our KEXINIT
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


            // simple negotiation logic (for demonstration, we just check if the client's proposals contain our single supported option)

            if(!clientKexAlgos.contains(SshConstants.PROPOSAL_KEX) || 
               !clientHostKeyAlgos.contains(SshConstants.PROPOSAL_HOST_KEY) ||
                !clientCipherAlgoC2S.contains(SshConstants.PROPOSAL_CIPHER) ||
                !clientCipherAlgoS2C.contains(SshConstants.PROPOSAL_CIPHER) ||
                !clientMacAlgoC2S.contains(SshConstants.PROPOSAL_MAC) ||
                !clientMacAlgoS2C.contains(SshConstants.PROPOSAL_MAC) ||
                !clientCompressionAlgoC2S.contains(SshConstants.PROPOSAL_COMPRESSION) ||
                !clientCompressionAlgoS2C.contains(SshConstants.PROPOSAL_COMPRESSION) ||
                !clientLangC2S.contains(SshConstants.PROPOSAL_LANG) ||
                !clientLangS2C.contains(SshConstants.PROPOSAL_LANG)
            ) {
                logger.error("Client does not support required kex and hostKey algorithms. Closing session.");
                close();
                return;
            }

            logger.info("Client supports required algorithms. Proceeding with key exchange.");


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