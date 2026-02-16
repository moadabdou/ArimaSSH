package com.arima.ssh.common.kex;

/**
 * Holds the parsed fields from a SSH_MSG_KEXINIT packet (RFC 4253 §7.1).
 */
public record KexInitData(
    String kexAlgos,
    String hostKeyAlgos,
    String cipherC2S,
    String cipherS2C,
    String macC2S,
    String macS2C,
    String compC2S,
    String compS2C,
    String langC2S,
    String langS2C,
    boolean firstKexPacketFollows,
    long reserved
) {}
