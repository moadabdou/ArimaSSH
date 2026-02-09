package com.arima.ssh.server;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

public class ServerSession implements Runnable {

    private static final Logger logger = LoggerFactory.getLogger(ServerSession.class);

    private final Socket clientSocket;
    private InputStream inputStream;
    private OutputStream outputStream;

    public ServerSession(Socket clientSocket) {
        this.clientSocket = clientSocket;
    }

    @Override
    public void run() {
        
        try {
            
            this.inputStream = clientSocket.getInputStream();
            this.outputStream = clientSocket.getOutputStream();

            logger.info("Session started for {}", clientSocket.getRemoteSocketAddress());

            // For now, we just echo back whatever they type (Echo Server)
            // Later, this will be: while (packet = readPacket()) { handle(packet); }
            int data;
            while ((data = inputStream.read()) != -1) {

                if (data == 'q') {
                    logger.info("Client requested disconnect.");
                    break;
                }

                outputStream.write(data);
                outputStream.flush();
            }

        } catch (IOException e) {
            logger.error("Session error: {}", e.getMessage());
        } finally {
            close();
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