package com.arima.ssh.common.crypto;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class SshMac {

    private final Mac mac;
    private final String algorithm;

    public SshMac(String algorithm, byte[] key) throws Exception {
        this.algorithm = algorithm;
        // Map SSH name to Java name
        String javaName =  macAlgoToJava(algorithm); 
        
        this.mac = Mac.getInstance(javaName);
        this.mac.init(new SecretKeySpec(key, javaName));
    }

    public String getAlgorithm() {
        return algorithm;
    }

    /*
    
    RFC 4253 Section 6.4:

    The message authentication algorithm and key are negotiated during
   key exchange.  Initially, no MAC will be in effect, and its length
   MUST be zero.  After key exchange, the 'mac' for the selected MAC
   algorithm will be computed before encryption from the concatenation
   of packet data:

      mac = MAC(key, sequence_number || unencrypted_packet)

   where unencrypted_packet is the entire packet without 'mac' (the
   length fields, 'payload' and 'random padding'), and sequence_number
   is an implicit packet sequence number represented as uint32.  The
   sequence_number is initialized to zero for the first packet, and is
   incremented after every packet (regardless of whether encryption or
   MAC is in use).  It is never reset, even if keys/algorithms are
   renegotiated later.  It wraps around to zero after every 2^32
   packets.  The packet sequence_number itself is not included in the
   packet sent over the wire.

    */

    public byte[] calculate(long sequenceNumber, byte[] data) {
        // HMAC Input: [Sequence Number (uint32)] + [Packet Data]
        
        byte[] seqBytes = new byte[4];
        seqBytes[0] = (byte) ((sequenceNumber >> 24) & 0xFF);
        seqBytes[1] = (byte) ((sequenceNumber >> 16) & 0xFF);
        seqBytes[2] = (byte) ((sequenceNumber >> 8) & 0xFF);
        seqBytes[3] = (byte) (sequenceNumber & 0xFF);
        
        mac.update(seqBytes);
        
        mac.update(data);
        
        byte[] result = mac.doFinal();
        return result;
    }

    //overloaded to calculate MAC from packet components (for verification in PacketReader)
    public byte[] calculate(long sequenceNumber, byte[] packetLengthBuffer, byte[] paddingLengthByte, byte[] payload, byte[] padding) {
        byte[] seqBytes = new byte[4];
        seqBytes[0] = (byte) ((sequenceNumber >> 24) & 0xFF);
        seqBytes[1] = (byte) ((sequenceNumber >> 16) & 0xFF);
        seqBytes[2] = (byte) ((sequenceNumber >> 8) & 0xFF);
        seqBytes[3] = (byte) (sequenceNumber & 0xFF);
        mac.update(seqBytes);
        mac.update(packetLengthBuffer);
        mac.update(paddingLengthByte);
        mac.update(payload);
        mac.update(padding);
        byte[] result = mac.doFinal();
        return result;
    }

    /*
    RFC 4253 Section 6.4:

     The following MAC algorithms are currently defined:

      hmac-sha1    REQUIRED        HMAC-SHA1 (digest length = key
                                   length = 20)
      hmac-sha1-96 RECOMMENDED     first 96 bits of HMAC-SHA1 (digest
                                   length = 12, key length = 20)
      hmac-md5     OPTIONAL        HMAC-MD5 (digest length = key
                                   length = 16)
      hmac-md5-96  OPTIONAL        first 96 bits of HMAC-MD5 (digest
                                   length = 12, key length = 16)
      none         OPTIONAL        no MAC; NOT RECOMMENDED

    
    */


    public static int getMacSize(String algorithm) {
        switch (algorithm) {
            case "hmac-sha1":
                return 20;
            case "hmac-sha1-96":
                return 12;
            case "hmac-md5":
                return 16;
            case "hmac-md5-96":
                return 12;
            case "none":
                return 0;
            default:
                throw new IllegalArgumentException("Unsupported MAC algorithm: " + algorithm);
        }
    }

    public static String macAlgoToJava(String name) {
        switch (name) {
            case "hmac-sha1":
                return "HmacSHA1";
            case "hmac-sha1-96":
                return "HmacSHA1";
            case "hmac-md5":
                return "HmacMD5";
            case "hmac-md5-96":
                return "HmacMD5";
            case "none":
                return "none";
            default:
                throw new IllegalArgumentException("Unsupported MAC algorithm: " + name);
        }
    }


}