package com.arima.ssh.server.subsystem;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Iterator;

public class DirectoryHandle implements SftpHandle {

    public final Path path;
    public final Iterator<Path> iterator;

    DirectoryHandle(Path path) throws IOException {
        this.path = path;
        // Files.list returns a Stream, we get its iterator to step through it
        this.iterator = Files.list(path).iterator();
    }

    @Override
    public void close() throws Exception {
        // Nothing to close for now, but we could add cleanup logic here if needed in the future
    }

}