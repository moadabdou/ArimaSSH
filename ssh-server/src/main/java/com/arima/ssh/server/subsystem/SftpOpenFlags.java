package com.arima.ssh.server.subsystem;

import java.util.Set;
import java.nio.file.OpenOption;
import com.arima.ssh.common.SshConstants;

public class SftpOpenFlags {

    public static Set<OpenOption> toOpenOptions(int pflags) {
        Set<OpenOption> options = new java.util.HashSet<>();

        if ((pflags & SshConstants.SSH_FXF_READ) != 0) {
            options.add(java.nio.file.StandardOpenOption.READ);
        }
        if ((pflags & SshConstants.SSH_FXF_WRITE) != 0) {
            options.add(java.nio.file.StandardOpenOption.WRITE);
        }
        if ((pflags & SshConstants.SSH_FXF_APPEND) != 0) {
            options.add(java.nio.file.StandardOpenOption.APPEND);
        }
        if ((pflags & SshConstants.SSH_FXF_CREAT) != 0) {
            options.add(java.nio.file.StandardOpenOption.CREATE);
        }
        if ((pflags & SshConstants.SSH_FXF_TRUNC) != 0) {
            options.add(java.nio.file.StandardOpenOption.TRUNCATE_EXISTING);
        }
        if ((pflags & SshConstants.SSH_FXF_EXCL) != 0) {
            options.add(java.nio.file.StandardOpenOption.CREATE_NEW);
        }

        return options;
    }

}
