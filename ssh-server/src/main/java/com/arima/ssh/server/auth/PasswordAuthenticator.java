package com.arima.ssh.server.auth;

import com.arima.ssh.server.ServerSession;

public interface PasswordAuthenticator {
    
    /**
     * Verifies if the username and password match.
     * * @param username The username sent by the client.
     * @param password The password sent by the client.
     * @param session  The active session (in case you need IP address, etc.)
     * @return true if valid, false otherwise.
     */
    boolean authenticate(String username, String password, ServerSession session);
}