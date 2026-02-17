package com.arima.ssh.client;


import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.Security;
import java.util.HashMap;
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
 
    @Option(names = {"-N", "--no-shell"}, description = "Do not request a shell (useful for port forwarding)")
    private boolean noShell = false;

    @Option(names = {"-i", "--identity"}, description = "Identity file (private key) for authentication")
    private Path identityFile;

    @Option(names = {"-p", "--port"}, description = "Port to connect to (default: 2222)")
    private int port = 2222;

    @Parameters(index = "0", description = "Destination (user@host)")
    private String destination;

    @Parameters(index = "1", description = "Command to execute (optional)", arity = "0..*")
    private String[] command;
  
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
            System.out.println("Connecting to " + host + ":" + port + " as " + username + "...");

            session = new ClientSession(host, port, this, terminal);
            session.init();
            authMethods = session.requestAuthMethods();

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

            System.out.println("Logged in! ");

            // look for ~/.arima_ssh/arima_env file for the env variables to set on the server side

            // check if ~/.arima_ssh/arima_env exists

            Path envFile = Path.of(System.getProperty("user.home"), ".arima_ssh", "arima_env");

            HashMap<String, Object> envVariables = new HashMap<>();

            if (envFile.toFile().exists()) {

                System.out.println("Loading environment variables from " + envFile);

                try {
                    String content = Files.readString(envFile);
                    String[] lines = content.split("\\r?\\n");
                    for (String line : lines) {
                        if (line.trim().isEmpty() || line.startsWith("#")) {
                            continue; // skip empty lines and comments
                        }
                        String[] kv = line.split("=", 2);
                        if (kv.length == 2) {
                            String key = kv[0].trim();
                            String value = kv[1].trim();
                            envVariables.put(key, value);
                            System.out.println("Set env variable: " + key + "=" + value);
                        } else {
                            System.out.println("Invalid env variable line: " + line);
                        }
                    }
                } catch (IOException e) {
                    System.err.println("Failed to read env file: " + e.getMessage());
                }

            }
  
            
            if (!noShell) {

                System.out.println("Requesting shell...");

                session.sendOpenSessionChannel(
                    envVariables.isEmpty() ? null : envVariables, 
                    command != null && command.length > 0 ? 
                        String.join(" ", command) : 
                        null
                );

            }


            while (session.isConnected() && session.getChannelManager().hasOpenChannels()){
        
                session.handleIncomingPacket();

            }

            session.close();


        }catch (Exception e) {

            logger.error("An error occurred: {}", e.getMessage(), e);

        }

        return 0;
    }
}