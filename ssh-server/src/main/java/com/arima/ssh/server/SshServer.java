package com.arima.ssh.server;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;


public class SshServer
{

    private final Logger logger = LoggerFactory.getLogger(SshServer.class);
    private final int PORT = 2222; //TODO: find another port representing the name of Arima and not used by other applications

    private ServerSocket serverSocket; 
    private boolean running = true;

    private ExecutorService ConnectionPool = Executors.newVirtualThreadPerTaskExecutor();


    public void start(){

        try {
            serverSocket = new ServerSocket(PORT);
            logger.info("ArimaSSH Server started on port " + PORT);

            while (running) {
                Socket clientSocket = serverSocket.accept();
                logger.info("New connection from " + clientSocket.getInetAddress());

                // Handle the connection in a separate thread
                ConnectionPool.submit(() -> handleClient(clientSocket));
            }
        } catch (IOException e) {
            logger.error("Error starting SSH Server: ", e);
        } finally {
            stop();
        }


    }

    private void handleClient(Socket clientSocket) {
        try (clientSocket) {


            clientSocket.getOutputStream().write("Welcome to ArimaSSH Server!\n".getBytes());
            clientSocket.getOutputStream().flush();

            logger.info("Sent welcome message to " + clientSocket.getInetAddress());

            Thread.sleep(5000); // Simulate some work with the client

            logger.info("Closing connection with " + clientSocket.getInetAddress());

        }catch(Exception e){

            logger.error("Error handling client connection: ", e);

        }

    }

    public void stop() {
        running = false;
        try {
            if (serverSocket != null && !serverSocket.isClosed()) {
                serverSocket.close();
            }
            ConnectionPool.shutdown();
            logger.info("ArimaSSH Server stopped.");
        } catch (IOException e) {
            logger.error("Error stopping SSH Server: ", e);
        }
    }


    public static void main( String[] args )
    {
        
        SshServer sshServer = new SshServer();
        sshServer.start();

        Runtime.getRuntime().addShutdownHook(new Thread(sshServer::stop));

    }
}




