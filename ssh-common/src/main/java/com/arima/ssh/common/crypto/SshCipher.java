package com.arima.ssh.common.crypto;

import javax.crypto.Cipher;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class SshCipher {

    private final Cipher cipher;

    /**
     * Initializes the cipher for encryption or decryption.
      * @param transformation The cipher transformation (e.g., "AES/CBC/PKCS5Padding")
      * @param key The encryption/decryption key
      * @param iv The initialization vector
      * @param mode Cipher.ENCRYPT_MODE or Cipher.DECRYPT_MODE
      * @throws Exception If initialization fails
    */

    public SshCipher(String transformation, byte[] key, byte[] iv, int mode) throws Exception {
        // Mode: Cipher.ENCRYPT_MODE or Cipher.DECRYPT_MODE
        this.cipher = Cipher.getInstance(transformation);
        
        String algorithm = transformation.split("/")[0];
        SecretKeySpec keySpec = new SecretKeySpec(key, algorithm);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        
        cipher.init(mode, keySpec, ivSpec);
    }

    /**
     * Transforms (Encrypts or Decrypts)
     */
    public void transform(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException {
        cipher.update(input, inputOffset, inputLen, output, outputOffset);
    }

    public int getBlockSize() {
        return cipher.getBlockSize();
    }
}