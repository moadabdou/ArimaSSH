package com.arima.ssh.server.auth;

import com.arima.ssh.server.ServerSession;
import java.util.HashMap;
import java.util.Map;


// just for testing/demo purposes, not for production use! In production, you would want to implement a more secure and robust authenticator.

public class StaticPasswordAuthenticator implements PasswordAuthenticator {

    private final Map<String, String> users = new HashMap<>();

    public void addUser(String username, String password) {
        users.put(username, password);
    }

    @Override
    public boolean authenticate(String username, String password, ServerSession session) {
        String storedPass = users.get(username);

        return storedPass != null && storedPass.equals(password);
    }
}