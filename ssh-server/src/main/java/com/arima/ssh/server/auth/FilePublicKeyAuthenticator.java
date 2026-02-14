package com.arima.ssh.server.auth;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import org.slf4j.Logger;

import com.arima.ssh.common.crypto.SshKeyDecoder;
import com.arima.ssh.server.ServerSession;

public class FilePublicKeyAuthenticator implements PublicKeyAuthenticator {

    private final Path authorizedKeysPath;

    Logger logger = org.slf4j.LoggerFactory.getLogger(FilePublicKeyAuthenticator.class);

    public FilePublicKeyAuthenticator(Path authorizedKeysPath) {
        this.authorizedKeysPath = authorizedKeysPath;
    }

    @Override
    public boolean authenticate(String username, byte[] publicKey, ServerSession session) {

        if (!Files.exists(authorizedKeysPath)) return false;

        PublicKey clientKey;

        try {

            clientKey = SshKeyDecoder.decodePublicKey(publicKey);

        } catch (Exception e) {
            logger.error("Failed to decode client public key", e);
            return false;
        }

        List<PublicKey> allowedKeys = loadKeys();
        for (PublicKey allowed : allowedKeys) {
            if (allowed.equals(clientKey)) {
                return true; 
            }
        }
        
        return false;

    }

    private List<PublicKey> loadKeys() {

        List<PublicKey> keys = new ArrayList<>();

        try {
            List<String> lines = Files.readAllLines(authorizedKeysPath);
            for (String line : lines) {
                if (line.trim().isEmpty() || line.startsWith("#")) continue;
                
                try {
                    // Format: "ssh-rsa AAAAB3... comment"
                    String[] parts = line.split(" ");
                    if (parts.length < 2) continue;

                    String base64 = parts[1];
                    byte[] data = Base64.getDecoder().decode(base64);

                    keys.add(SshKeyDecoder.decodePublicKey(data));
                } catch (Exception e) {
                    logger.warn("Failed to parse public key line: {}", line, e);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return keys;
    }

    

}