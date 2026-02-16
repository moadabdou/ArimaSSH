package com.arima.ssh.common.kex;

import com.arima.ssh.common.crypto.SshCipher;
import com.arima.ssh.common.crypto.SshMac;

/**
 * Holds the derived cipher and MAC instances after key exchange.
 * "decryptor" decrypts incoming packets, "encryptor" encrypts outgoing packets.
 * "inboundMac" verifies incoming MACs, "outboundMac" computes outgoing MACs.
 */
public record DerivedKeys(
    SshCipher decryptor,
    SshCipher encryptor,
    SshMac inboundMac,
    SshMac outboundMac
) {}
