package com.arima.ssh.client;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.Security;

/**
 * Launcher class for ArimaSSH Client.
 * This class sets up logging BEFORE any other classes are loaded,
 * ensuring that the verbose flag works correctly.
 */
public class Main {
    
    public static void main(String[] args) {
        // Check for verbose flag BEFORE any SLF4J class is loaded
        boolean verbose = false;
        for (String arg : args) {
            if (arg.equals("-v") || arg.equals("--verbose")) {
                verbose = true;
                break;
            }
        }
        
        // Configure SimpleLogger via system properties BEFORE LoggerFactory is touched
        if (verbose) {
            System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "debug");
            System.setProperty("org.slf4j.simpleLogger.showDateTime", "true");
            System.setProperty("org.slf4j.simpleLogger.dateTimeFormat", "HH:mm:ss.SSS");
            System.setProperty("org.slf4j.simpleLogger.showThreadName", "true");
            System.setProperty("org.slf4j.simpleLogger.showLogName", "true");
        } else {
            System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "off");
        }
        
        // Add BouncyCastle provider
        Security.addProvider(new BouncyCastleProvider());
        
        // Now load and run SshClient (its loggers will use our configuration)
        SshClient.run(args);
    }
}
