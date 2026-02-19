package com.arima.ssh.server;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.arima.ssh.server.auth.FilePublicKeyAuthenticator;
import com.arima.ssh.server.auth.PasswordAuthenticator;
import com.arima.ssh.server.auth.PublicKeyAuthenticator;
import com.arima.ssh.server.auth.StaticPasswordAuthenticator;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Path;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;


public class SshServer
{

    public final Logger logger = LoggerFactory.getLogger(SshServer.class);
    // Port 3003 - Arima Kana's birthday is March 3rd (3/03) ♪
    private final int PORT = 3003;

    private ServerSocket serverSocket; 
    private boolean running = true;

    private ExecutorService ConnectionPool = Executors.newVirtualThreadPerTaskExecutor();


    private PasswordAuthenticator passwordAuthenticator;
    private PublicKeyAuthenticator publicKeyAuthenticator;

    private HostKeyProvider hostKeyProvider;



    private BannerProvider bannerProvider;


    public void setPasswordAuthenticator(PasswordAuthenticator passwordAuthenticator) {
        this.passwordAuthenticator = passwordAuthenticator;
    }

    public PasswordAuthenticator getPasswordAuthenticator() {
        return passwordAuthenticator;
    }

    public PublicKeyAuthenticator getPublicKeyAuthenticator() {
        return publicKeyAuthenticator;
    }

    public void setPublicKeyAuthenticator(PublicKeyAuthenticator publicKeyAuthenticator) {
        this.publicKeyAuthenticator = publicKeyAuthenticator;
    }

    public HostKeyProvider getHostKeyProvider() {
        return hostKeyProvider;
    }

    public void setHostKeyProvider(HostKeyProvider hostKeyProvider) {
        this.hostKeyProvider = hostKeyProvider;
    }

    public BannerProvider getBannerProvider() {
        return bannerProvider;
    }

    public void setBannerProvider(BannerProvider bannerProvider) {
        this.bannerProvider = bannerProvider;
    }

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
            ServerSession session = new ServerSession(clientSocket, this);
            logger.info("Starting session for {}", clientSocket.getRemoteSocketAddress());
            session.run();

        }catch(IOException e){

            logger.error("Error handling client connection: ", e);

        } catch (Throwable t) {
            logger.error("Unexpected error handling client connection: ", t);
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

        Path ArimaSshDir = Path.of(System.getProperty("user.home")).resolve(".arima_ssh");

        if (!ArimaSshDir.toFile().exists()) {
            try {
                java.nio.file.Files.createDirectories(ArimaSshDir);
            } catch (IOException e) {
                sshServer.logger.error("Failed to create ArimaSSH directory: ", e);
                return;
            }
        }

        //ensure authorized_keys file exists
        Path authorizedKeysPath = ArimaSshDir.resolve("authorized_keys");
        if (!authorizedKeysPath.toFile().exists()) {
            try {
                java.nio.file.Files.createFile(authorizedKeysPath);
            } catch (IOException e) {
                sshServer.logger.error("Failed to create authorized_keys file: ", e);
                return;
            }
        }
        
        StaticPasswordAuthenticator authenticator = new StaticPasswordAuthenticator();
        authenticator.addUser("moadabdou", "arima");

        FilePublicKeyAuthenticator filePublicKeyAuthenticator = new FilePublicKeyAuthenticator(authorizedKeysPath);

        HostKeyProvider hostKeyProvider = new HostKeyProvider(ArimaSshDir.resolve("hostkey.pem"));
        //HostKeyProvider hostKeyProvider = new HostKeyProvider(ArimaSshDir.resolve("hostkey_modern.pem"));


        try {
            hostKeyProvider.init();
        } catch (Exception e) {
            sshServer.logger.error("Failed to initialize HostKeyProvider: ", e);
            return;
        }

        sshServer.setPasswordAuthenticator(authenticator);
        sshServer.setPublicKeyAuthenticator(filePublicKeyAuthenticator);
        sshServer.setHostKeyProvider(hostKeyProvider);
        sshServer.setBannerProvider(new BannerProvider());

        sshServer.start();

        Runtime.getRuntime().addShutdownHook(new Thread(sshServer::stop));

    }
}




