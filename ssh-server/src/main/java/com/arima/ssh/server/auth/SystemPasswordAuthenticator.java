package com.arima.ssh.server.auth;

import com.arima.ssh.server.ServerSession;
import org.jvnet.libpam.PAM;
import org.jvnet.libpam.PAMException;
import org.jvnet.libpam.UnixUser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Authenticates users against the system's PAM (Pluggable Authentication Modules).
 * This allows SSH users to log in with their system credentials.
 * 
 * Note: Requires libpam4j dependency and proper PAM configuration on the system.
 * The server typically needs to run with appropriate permissions to access PAM.
 */
public class SystemPasswordAuthenticator implements PasswordAuthenticator {

    private static final Logger logger = LoggerFactory.getLogger(SystemPasswordAuthenticator.class);
    
    private final String pamServiceName;

    /**
     * Creates a SystemPasswordAuthenticator with the default PAM service name "sshd".
     */
    public SystemPasswordAuthenticator() {
        this("sshd");
    }

    /**
     * Creates a SystemPasswordAuthenticator with a custom PAM service name.
     * 
     * @param pamServiceName The PAM service name to use (e.g., "sshd", "login", "password-auth")
     */
    public SystemPasswordAuthenticator(String pamServiceName) {
        this.pamServiceName = pamServiceName;
    }

    @Override
    public boolean authenticate(String username, String password, ServerSession session) {
        try {
            PAM pam = new PAM(pamServiceName);
            UnixUser user = pam.authenticate(username, password);
            
            if (user != null) {
                logger.info("PAM authentication successful for user: {}", username);
                return true;
            }
            
            logger.warn("PAM authentication failed for user: {}", username);
            return false;
            
        } catch (PAMException e) {
            logger.warn("PAM authentication error for user {}: {}", username, e.getMessage());
            return false;
        }
    }
}
