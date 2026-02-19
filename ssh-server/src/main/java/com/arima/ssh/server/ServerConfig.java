package com.arima.ssh.server;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

/**
 * Handles server configuration loaded from a .config file in the ArimaSSH directory.
 * 
 * Configuration file format (key=value pairs):
 * <pre>
 * # Comment lines start with #
 * port=3003
 * </pre>
 */
public class ServerConfig {

    private static final Logger logger = LoggerFactory.getLogger(ServerConfig.class);

    // Default values
    private static final int DEFAULT_PORT = 3003;

    private final Path configPath;
    private final Map<String, String> properties = new HashMap<>();

    // Parsed config values
    private int port = DEFAULT_PORT;

    public ServerConfig(Path configPath) {
        this.configPath = configPath;
    }

    /**
     * Loads configuration from the config file.
     * If the file doesn't exist, creates it with default values.
     * 
     * @throws IOException if there's an error reading or creating the config file
     */
    public void load() throws IOException {
        if (!Files.exists(configPath)) {
            createDefaultConfig();
            return;
        }

        try (BufferedReader reader = Files.newBufferedReader(configPath)) {
            String line;
            int lineNumber = 0;
            
            while ((line = reader.readLine()) != null) {
                lineNumber++;
                line = line.trim();
                
                // Skip empty lines and comments
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }
                
                int equalsIndex = line.indexOf('=');
                if (equalsIndex == -1) {
                    logger.warn("Invalid config line {} (no '=' found): {}", lineNumber, line);
                    continue;
                }
                
                String key = line.substring(0, equalsIndex).trim().toLowerCase();
                String value = line.substring(equalsIndex + 1).trim();
                
                properties.put(key, value);
            }
        }
        
        parseProperties();
        logger.info("Loaded configuration from: {}", configPath);
    }

    private void parseProperties() {
        // Parse port
        String portStr = properties.get("port");
        if (portStr != null) {
            try {
                int parsedPort = Integer.parseInt(portStr);
                if (parsedPort > 0 && parsedPort <= 65535) {
                    this.port = parsedPort;
                } else {
                    logger.warn("Invalid port value: {}. Using default: {}", portStr, DEFAULT_PORT);
                }
            } catch (NumberFormatException e) {
                logger.warn("Invalid port format: {}. Using default: {}", portStr, DEFAULT_PORT);
            }
        }
    }

    private void createDefaultConfig() throws IOException {
        logger.info("Creating default config file at: {}", configPath);
        
        try (BufferedWriter writer = Files.newBufferedWriter(configPath)) {
            writer.write("# ArimaSSH Server Configuration\n");
            writer.write("# Port 3003 - Arima Kana's birthday is March 3rd (3/03) ♪\n");
            writer.write("\n");
            writer.write("# Server port (1-65535)\n");
            writer.write("port=" + DEFAULT_PORT + "\n");
        }
    }

    /**
     * Gets the configured port number.
     * @return the port number (default: 3003)
     */
    public int getPort() {
        return port;
    }

    /**
     * Gets a raw property value by key.
     * @param key the property key
     * @return the property value, or null if not set
     */
    public String getProperty(String key) {
        return properties.get(key.toLowerCase());
    }

    /**
     * Gets a raw property value with a default.
     * @param key the property key
     * @param defaultValue the default value if property is not set
     * @return the property value, or defaultValue if not set
     */
    public String getProperty(String key, String defaultValue) {
        return properties.getOrDefault(key.toLowerCase(), defaultValue);
    }
}
