package com.arima.ssh.server.subsystem;

import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;

public class FileHandle  implements SftpHandle {

    public final FileChannel channel;

    FileHandle(FileChannel channel) {
        this.channel = channel;
    }

    public byte[] read(long offset, long length) throws Exception {
        ByteBuffer buffer = ByteBuffer.allocate((int)length);
        int bytesRead = channel.read(buffer, offset);
        if (bytesRead <= 0) {
            return new byte[0];
        }
        if (bytesRead < length) {
            byte[] result = new byte[bytesRead];
            System.arraycopy(buffer.array(), 0, result, 0, bytesRead);
            return result;
        }
        return buffer.array();
    }

    public void write(long offset, ByteBuffer data) throws Exception {
        channel.write(data, offset);
    }

    @Override
    public void close() throws Exception {
        channel.close();
    }
    
}
