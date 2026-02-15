package com.arima.ssh.server;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

public class BannerProvider {
    
    public String getBanner() {


        try (InputStream inputStream = getClass().getClassLoader().getResourceAsStream("defaultBanner")) {
            if (inputStream == null) {
                return "Welcome to the SSH server!";
            }
            return new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            e.printStackTrace();
            return "Welcome to the SSH server!";
        }
        

    }

}
