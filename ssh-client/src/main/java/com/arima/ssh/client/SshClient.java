package com.arima.ssh.client;


import java.net.InetAddress;
import java.net.Socket;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.Security;
import java.util.concurrent.Callable;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jline.reader.LineReader;
import org.jline.reader.LineReaderBuilder;
import org.jline.terminal.Terminal;
import org.jline.terminal.TerminalBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory; 

 
import com.arima.ssh.client.banner.DefaultBanner;
import com.arima.ssh.common.crypto.PemUtils;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

@Command(name = "arima-ssh", mixinStandardHelpOptions = true, version = "1.0",
         description = "ArimaSSH Client - A Java SSHv2 Implementation")
public class SshClient implements Callable<Integer> {


    @Option(names = {"-i", "--identity"}, description = "Identity file (private key) for authentication")
    private Path identityFile;

    @Option(names = {"-p", "--port"}, description = "Port to connect to (default: 2222)")
    private int port = 2222;

    @Parameters(index = "0", description = "Destination (user@host)")
    private String destination;
  
    private static final Logger logger = LoggerFactory.getLogger(SshClient.class);
    // private Banner banner = new DefaultBanner();

    private ClientSession session;

    private String username;
    private String host;

    private String authMethods;


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
        Security.addProvider(new BouncyCastleProvider());
        int exitCode = new CommandLine(new SshClient()).execute(args);
        System.exit(exitCode);
    }

    @Override
    public Integer call() throws Exception {

        String[] parts = destination.split("@");
        if (parts.length != 2) {
            System.err.println("Invalid format. Use: user@host");
            return 1;
        }
        
        username = parts[0];
        host = parts[1];

        System.out.print(new DefaultBanner().loadBanner());

        System.out.println("Connecting to " + host + ":" + port + " as " + username + "...");

        KeyPair keyPair = null;

        if (identityFile != null) {

            // load the key pair from the PEM file
            try {
                keyPair = PemUtils.readPemFile(identityFile);
            } catch (Exception e) {
                System.err.println("Failed to load identity file: " + e.getMessage());
                return 1;
            }

            System.out.println("Using identity file: " + identityFile);
        }

        try (Terminal terminal = TerminalBuilder.builder().system(true).build()) {


            // connect and perform SSH handshake
            connect();

            boolean authenticated = false;
            LineReader lineReader = LineReaderBuilder.builder().terminal(terminal).build();

            // test to authenticate with public key if identity file is provided and server supports it

            if (keyPair != null && authMethods.contains("publickey")) {
                try {
                    session.authenticateWithPublicKey(keyPair);
                    authenticated = true;
                } catch (Exception e) {
                    logger.error("Public key authentication failed with identity file: {}", identityFile, e);
                }
            }

            while (!authenticated) {

                String password = lineReader.readLine("password: ", '*');
                
                if (getSession().authenticateWithPassword(password)) {
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

        return 0;
    }
}