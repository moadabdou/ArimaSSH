package com.arima.ssh.server;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

public class ServerSession implements Runnable {

    private static final Logger logger = LoggerFactory.getLogger(ServerSession.class);

    // RFC 4253: The version string MUST begin with "SSH-2.0-"
    private static final String SERVER_VERSION = "SSH-2.0-ArimaSSH_1.0";

    private final Socket clientSocket;
    private InputStream inputStream;
    private OutputStream outputStream;

    private String clientVersion;

    public ServerSession(Socket clientSocket) {
        this.clientSocket = clientSocket;
    }

    @Override
    public void run() {
        
        try {
            
            this.inputStream = clientSocket.getInputStream();
            this.outputStream = clientSocket.getOutputStream();

            logger.info("Session started for {}", clientSocket.getRemoteSocketAddress());

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