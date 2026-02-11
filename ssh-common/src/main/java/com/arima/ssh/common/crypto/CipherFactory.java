package com.arima.ssh.common.crypto;

public class CipherFactory {

    public static class CipherConstants {
        public final int keySize;
        public final int ivSize;
        public final String transformation;

        public CipherConstants(int keySize, int ivSize, String transformation) {
            this.keySize = keySize;
            this.ivSize = ivSize;
            this.transformation = transformation;
        }
    }

    /**
     * Returns the required sizes and Java transformation string for an SSH cipher name.
     */
    public static CipherConstants getConstants(String sshCipherName) {
        switch (sshCipherName) {
            case "aes128-ctr":
                return new CipherConstants(16, 16, "AES/CTR/NoPadding");
            case "aes192-ctr":
                return new CipherConstants(24, 16, "AES/CTR/NoPadding");
            case "aes256-ctr":
                return new CipherConstants(32, 16, "AES/CTR/NoPadding");
            case "3des-cbc":
                return new CipherConstants(24, 8, "DESede/CBC/NoPadding");
            default:
                throw new IllegalArgumentException("Unsupported cipher: " + sshCipherName);
        }
    }
}
