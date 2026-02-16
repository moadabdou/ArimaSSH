package com.arima.ssh.client;


import java.net.InetAddress;
import java.net.Socket;

import org.jline.reader.LineReader;
import org.jline.reader.LineReaderBuilder;
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

    private String authMethods;

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

    public int getPort() {
        return port;
    }

    public String getAuthMethods() {
        return authMethods;
    }

    public void connect() throws Exception {

        InetAddress address = InetAddress.getByName(host);
        Socket socket = new Socket(address, port);
        logger.info("Successfully connected to {}:{}", host, port);
        
        logger.info ("initializing a client session for user '{}' on {}:{}", username, host, port);  
        session = new ClientSession(socket, this);

        session.init();

        logger.info("SSH client setup complete. Ready to authenticate and open channels.");

        authMethods = session.requestAuthMethods();

        logger.info("Server supports the following authentication methods: {}", authMethods);
 
    }

    public static void main(String[] args) {

        System.out.print(new DefaultBanner().loadBanner());

        // get username, host, and port from command line arguments :  user@host:port 

        if (args.length < 1) {
            System.err.println("Usage: java SshClient <username@host:port>");
            return;
        }

        String[] parts = args[0].split("@");
        if (parts.length != 2) {
            System.err.println("Invalid format. Expected: username@host:port");
            return;
        }

        String username = parts[0];
        String[] hostParts = parts[1].split(":");
        
        // if port is not specified, default to 2222
        String host = hostParts[0];
        int port = 2222; // default port

        if (hostParts.length > 1) {
            try {
                port = Integer.parseInt(hostParts[1]);
            } catch (NumberFormatException e) {
                System.err.println("Invalid port number. Expected an integer. Using default port 2222.");
            }
        }

        try (Terminal terminal = TerminalBuilder.builder().system(true).build()) {


            SshClient client = new SshClient(username, host, port);
            client.connect();

            boolean authenticated = false;
            LineReader lineReader = LineReaderBuilder.builder().terminal(terminal).build();

            while (!authenticated) {

                String password = lineReader.readLine("password: ", '*');
                
                if (client.getSession().authenticateWithPassword(password)) {
                    authenticated = true;
                } else {
                    System.out.println("Permission denied, please try again.");
                }
                
            }

            System.out.println("Logged in! (Shell coming soon...)");
  
            while(true) Thread.sleep(1000);

        }catch (Exception e) {

            logger.error("An error occurred: {}", e.getMessage(), e);

        }

    }
}