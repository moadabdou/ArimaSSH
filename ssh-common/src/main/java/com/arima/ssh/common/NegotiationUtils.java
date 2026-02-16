package com.arima.ssh.common;

/**
 * SSH algorithm negotiation utilities (RFC 4253 §7.1).
 * Used by both client and server to agree on algorithms.
 */
public final class NegotiationUtils {

    private NegotiationUtils() {} // utility class

    /**
     * Finds the first algorithm in the client's list that is also in the server's list.
     * Per RFC 4253 §7.1 the iteration order is over the client's list so that the
     * client's preference order is respected.
     *
     * @param clientListStr comma-separated list from the client
     * @param serverListStr comma-separated list from the server
     * @return the first common algorithm, or {@code null} if no match
     */
    public static String negotiate(String clientListStr, String serverListStr) {
        String[] clientAlgos = clientListStr.split(",");
        String[] serverAlgos = serverListStr.split(",");

        for (String clientAlgo : clientAlgos) {
            for (String serverAlgo : serverAlgos) {
                if (clientAlgo.trim().equals(serverAlgo.trim())) {
                    return clientAlgo.trim();
                }
            }
        }
        return null;
    }
}
