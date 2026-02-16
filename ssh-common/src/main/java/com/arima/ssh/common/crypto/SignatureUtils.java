package com.arima.ssh.common.crypto;

public class SignatureUtils {

    public static String mapSshAlgoToJava(String sshAlgo) {

        switch (sshAlgo) {
            case "ssh-rsa":
                return "SHA1withRSA";
            case "rsa-sha2-256":
                return "SHA256withRSA";
            case "rsa-sha2-512":
                return "SHA512withRSA";
            case "ssh-ed25519":
                return "Ed25519";
            default:
                throw new IllegalArgumentException("Unknown sig sshAlgo: " + sshAlgo);
        }

    }

}
