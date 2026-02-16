package com.arima.ssh.client;

import java.nio.file.Path;
import java.security.KeyPair;


import com.arima.ssh.common.crypto.PemUtils;

public class KeyLoader {
    public static KeyPair loadKey(Path path) throws Exception {
        
        if (path.getFileName().toString().endsWith(".pem")) {
            return PemUtils.readPemFile(path);
        } else {
            throw new IllegalArgumentException("Unsupported key format: " + path.getFileName());
        }

    }
}