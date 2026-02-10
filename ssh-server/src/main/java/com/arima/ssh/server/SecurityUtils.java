package com.arima.ssh.server;

public class SecurityUtils {
    
    /**
     * Finds the first algorithm in the client's list that is also in the server's list.
     * @param clientListStr Comma-separated list from the client (e.g., "curve25519,diffie-hellman-group14-sha1")
     * @param serverListStr Comma-separated list from the server (e.g., "diffie-hellman-group14-sha1")
     * @return The agreed algorithm, or null if no match found.
     */


    public String negotiate(String clientListStr, String serverListStr) {
        String[] clientAlgos = clientListStr.split(",");
        String[] serverAlgos = serverListStr.split(",");

        for (String clientAlgo : clientAlgos) {
            for (String serverAlgo : serverAlgos) {
                if (clientAlgo.trim().equals(serverAlgo.trim())) {
                    return clientAlgo.trim(); // Found a match!
                }
            }
        }
        return null; // No common algorithm
    }

}
