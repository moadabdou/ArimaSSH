package com.arima.ssh.client;


import java.net.InetAddress;
import java.net.Socket;

import org.jline.terminal.Terminal;
import org.jline.terminal.TerminalBuilder;
import org.jline.utils.NonBlockingReader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory; 

 
import com.arima.ssh.client.banner.DefaultBanner;

public class SshClient {
  
    private static final Logger logger = LoggerFactory.getLogger(SshClient.class);
    // private Banner banner = new DefaultBanner();

    private ClientSession session;

    private String username;
    private String host;
    private int port;

    public SshClient(String username, String host, int port) {
        this.username = username;
        this.host = host;
        this.port = port;
    }

    public ClientSession getSession() {
        return session;
    }

    public String getUsername() {
        return username;
    }

    public String getHost() {
        return host;
    }

    public void connect() throws Exception {

        InetAddress address = InetAddress.getByName(host);
        Socket socket = new Socket(address, port);
        logger.info("Successfully connected to {}:{}", host, port);
        
        logger.info ("initializing a client session for user '{}' on {}:{}", username, host, port);  
        session = new ClientSession(socket, this);

        session.init();

        logger.info("SSH client setup complete. Ready to authenticate and open channels.");

        String authMethods = session.requestAuthMethods();

        logger.info("Server supports the following authentication methods: {}", authMethods);

        try{ Thread.sleep(5000); }catch(Exception e){}
 
    }

    public static void main(String[] args) {

        System.out.print(new DefaultBanner().loadBanner());

        SshClient client = new SshClient("moadabdou","localhost", 2222);

        try {
            client.connect();
        } catch (Exception e) {
            logger.error("Failed to connect: {}", e.getMessage());
        }


    }
}