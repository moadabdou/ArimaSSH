package com.arima.ssh.server.auth;

import com.arima.ssh.server.ServerSession;

/**
 * a contract for public key authenticators
*/

public interface PublicKeyAuthenticator {
    /**
     * verifies if the provided public key is authorized for the given username
     * @param username the username sent by the client
     * @param publicKey the public key sent by the client
     * @return true if authorized, false otherwise
     */
    boolean authenticate(String username, byte[] publicKey, ServerSession session);

}
