package com.arima.ssh.server.subsystem;



import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.BasicFileAttributes;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.arima.ssh.common.SshBuffer;
import com.arima.ssh.common.SshConstants;
import com.arima.ssh.server.channel.SessionChannel;

public class SftpSubsystem {

    private static class DirectoryHandle {

        @SuppressWarnings("unused")
        public final Path path;
        public final Iterator<Path> iterator;

        DirectoryHandle(Path path) throws IOException {
            this.path = path;
            // Files.list returns a Stream, we get its iterator to step through it
            this.iterator = Files.list(path).iterator();
        }
    }

    private final SessionChannel channel;

    private final Map<String, DirectoryHandle> directoryHandles = new HashMap<>();
    private final Map<String, Object> openHandles = new HashMap<>();
    private int handleCounter = 0;

    private Logger logger = LoggerFactory.getLogger(SftpSubsystem.class.getName());

    private SshBuffer stagingBuffer = new SshBuffer();

    private long expectedPacketLength = -1;

    private static final long SFTP_VERSION_SUPPORTED = 3;

    private Path currentDirectory = Paths.get(System.getProperty("user.home")).getParent();

    
    public SftpSubsystem(SessionChannel channel) {
        this.channel = channel;
    }

    public void handleInput(byte[] data) {

        logger.info("Received data on SFTP subsystem: {} bytes", data.length);

        stagingBuffer.writeBytes(data, 0, data.length);

        while (true){

            if (expectedPacketLength == -1) {
                if (stagingBuffer.available() < 4) {
                    return;
                }
                expectedPacketLength = stagingBuffer.readUInt32();
            }

            if (stagingBuffer.available() < expectedPacketLength) {
                return;
            }

            byte[] packetData = stagingBuffer.readBytes((int) expectedPacketLength);

            processPacket(packetData);

            expectedPacketLength = -1;

            //free the already read data from the buffer if buffer is too big [e.g. 1MB or more]

            if (stagingBuffer.available() > 1024 * 1024) {
                stagingBuffer.compact();
            }


        }


        
    } 

    private void processPacket(byte[] packetData){

        SshBuffer packet = new SshBuffer(packetData);

        //parse the packet 
        byte packetType = packet.readByte();
        long requestId = packet.readUInt32();
        byte[] payload = packet.readBytes((int) (packetData.length - 5)); // packet length is excluded

        logger.info("Processing SFTP packet: type={}, requestId={}, payloadLength={}", packetType, requestId, payload.length);

        if (packetType == SshConstants.SSH_FXP_INIT) { 

            handleInit(requestId, payload);

        } else if (packetType == SshConstants.SSH_FXP_REALPATH){
            
            handleRealPath(requestId, payload);

        }else if (packetType == SshConstants.SSH_FXP_OPENDIR) {

            handleOpenDir(requestId, payload);

        }else if(packetType == SshConstants.SSH_FXP_READDIR) {

            handleReadDir(requestId, payload);

        } else if ( packetType == SshConstants.SSH_FXP_CLOSE) {

            handleClose(requestId, payload);

        }else if ( packetType == SshConstants.SSH_FXP_STAT || packetType == SshConstants.SSH_FXP_LSTAT) {

            SshBuffer buffer = new SshBuffer(payload);
            String pathStr = buffer.readString();
            Path p = resolvePath(pathStr);
            logger.info("Handling SFTP stat request: requestId={}, path={}", requestId, p);
            sendAttrs(requestId, p);

        }else {
            logger.warn("Unsupported SFTP packet type: {}", packetType);
        }

    }

    private void handleInit(long requestId, byte[] payload) {


        // ssh2 packet for SSH_FXP_VERSION response
        SshBuffer response = new SshBuffer();
        response.writeByte(SshConstants.SSH_FXP_VERSION);
        response.writeUInt32(SFTP_VERSION_SUPPORTED);

        try{
            sendPacket(response.getCompactData());
        }catch(Exception e){
            logger.error("Error handling SFTP init packet", e);
        }

        logger.info("Sent SFTP version response: {}", SFTP_VERSION_SUPPORTED);
    }
    
    private void handleRealPath(long requestId, byte[] payload) {

        String absolutePath = Paths.get(System.getProperty("user.home")).toAbsolutePath().toString();

        absolutePath = Paths.get(absolutePath).normalize().toString();
        absolutePath = absolutePath.replace("\\", "/");

        logger.info("Handling SFTP realpath request: requestId={}, absolutePath={}", requestId, absolutePath);

        sendNameResponse(requestId, List.of(Paths.get(absolutePath)));

        logger.info("Handled SFTP realpath request: requestId={}", requestId);

    }

    private void handleOpenDir(long requestId, byte[] payload) {

        SshBuffer request = new SshBuffer(payload);

        String pathString = request.readString();

        Path path = resolvePath(pathString);


        logger.info("Handling SFTP open directory request: requestId={}, path={}", requestId, path);

        try {

            String handle = generateHandle();

            directoryHandles.put(handle, new DirectoryHandle(path));

            sendHandleResponse(requestId, handle);

            logger.info("Sent SFTP open directory response: requestId={}, handle={}", requestId, handle);

        }catch (Exception e) {

            logger.warn("Error opening directory in SFTP request: {}", e.getMessage());

            sendStatus(requestId, SshConstants.SSH_FX_NO_SUCH_FILE, "Directory does not exist");

            return;
        }
    }

    private void handleReadDir(long reqId, byte[] payload) {

        SshBuffer request = new SshBuffer(payload);

        String handle = request.readString();

        logger.info("Handling SFTP read directory request: reqId={}, handle={}", reqId, handle);

        DirectoryHandle dir = directoryHandles.get(handle);

        if (dir == null) {
            logger.warn("Invalid SFTP handle in read directory request: {}", handle);
            sendStatus(reqId, SshConstants.SSH_FX_NO_SUCH_FILE, "Invalid directory handle");
            return;
        }

        if (!dir.iterator.hasNext()) {
            // End of File (EOF) - This tells the client "List is finished"
            sendStatus(reqId, SshConstants.SSH_FX_EOF, "End of directory");
            return;
        }

        List<Path> batch = new ArrayList<>();
        int count = 0;
        while (dir.iterator.hasNext() && count < 50) {
            Path next = dir.iterator.next();
            batch.add(next);
            count++;
        }

        sendNameResponse(reqId, batch);

    }

    private void handleClose(long reqId, byte[] buffer){

        String handleId = new SshBuffer(buffer).readString();

        if (directoryHandles.remove(handleId) != null || openHandles.remove(handleId) != null) {

            sendStatus(reqId, SshConstants.SSH_FX_OK, "Handle closed");
        } else {

            sendStatus(reqId, SshConstants.SSH_FX_FAILURE, "Invalid Handle");
        }
    }

    
    private void sendNameResponse(long reqId, List<Path> files) {

        SshBuffer response = new SshBuffer();
        response.writeByte(SshConstants.SSH_FXP_NAME);
        response.writeUInt32(reqId);
        response.writeUInt32((long)files.size());

        logger.info("Sending SFTP name response: reqId={}, fileCount={}", reqId, files.size());

        for (Path file : files) {
            String fileName = file.getFileName().toString();
            
            String longName = formatLongName(file); 

            response.writeString(fileName);
            response.writeString(longName);

            response.writeUInt32(0); 
        }

        sendPacket(response.getCompactData());
    }

    private void sendStatus(long reqId, int statusCode, String message) {

        logger.info("Sending SFTP status response: reqId={}, statusCode={}, message={}", reqId, statusCode, message);

        SshBuffer response = new SshBuffer();
        response.writeByte(SshConstants.SSH_FXP_STATUS);
        response.writeUInt32(reqId);
        response.writeUInt32(statusCode);
        response.writeString(message);
        response.writeString(""); // Language Tag (empty for now)
        sendPacket(response.getCompactData());
    }

    // Helper to send attributes (for LSTAT, FSTAT, etc.)
    // TODO: This is a simplified implementation. A real implementation would need to handle all the possible attributes and flags properly.
    private void sendAttrs(long reqId, Path path){

        SshBuffer response = new SshBuffer();
        response.writeByte(SshConstants.SSH_FXP_ATTRS); // 105
        response.writeUInt32(reqId);

        try {

            BasicFileAttributes attrs = Files.readAttributes(path, BasicFileAttributes.class);
            
            // Flags: We are sending SIZE (1), UIDGID (2), PERMISSIONS (4), ACMODTIME (8)
            // For simplicity, let's just send SIZE and PERMISSIONS (0x00000005) [ 5 = 1 (size) + 4 (permissions) ]
            int flags = 0x00000005; 
            response.writeUInt32(flags);
            
            response.writeUInt64(attrs.size());
            
            // Permissions (Int)
            // Simple mapping: Directory (040000) or File (0100000) + 755 (rwxr-xr-x)
            int p = attrs.isDirectory() ? 040755 : 0100644;
            response.writeUInt32(p);


        } catch (IOException e) {
            // File not found
            sendStatus(reqId, SshConstants.SSH_FX_FAILURE, "File not found");
            return;
        }

        sendPacket(response.getCompactData());
    }


    // TODO: refactor the long name formatting to be more accurate and detailed, including permissions, owner, group, size, and modification time. The current implementation is simplified for demonstration purposes.
    public String formatLongName(Path path) {
        try {

            BasicFileAttributes attrs = Files.readAttributes(path, BasicFileAttributes.class);
            
            StringBuilder sb = new StringBuilder();
            sb.append(attrs.isDirectory() ? "d" : "-");
            

            sb.append("rwxr-xr-x"); 
            
            sb.append(" 1 ");
            
            sb.append("user group "); 
            
            sb.append(String.format("%8d ", attrs.size()));
            
            Instant lastMod = attrs.lastModifiedTime().toInstant();
            LocalDateTime ldt = LocalDateTime.ofInstant(lastMod, ZoneId.systemDefault());
            DateTimeFormatter dtf = DateTimeFormatter.ofPattern("MMM dd HH:mm", Locale.ENGLISH);
            sb.append(ldt.format(dtf)).append(" ");

            sb.append(path.getFileName().toString());
            
            return sb.toString();
            
        } catch (Exception e) {
            return "?????????? 1 user group 0 Jan 01 00:00 " + path.getFileName();
        }
    }
    private Path resolvePath(String inputPath) {

        if (inputPath == null || inputPath.isEmpty() || ".".equals(inputPath)) {
            return currentDirectory;
        }

        Path p = Paths.get(inputPath);

        if (p.isAbsolute()) {
            return p.normalize();
        }

        return currentDirectory.resolve(p).normalize();

    }

    private void sendPacket(byte[] payload) {

        SshBuffer packet = new SshBuffer();

        packet.writeByte(SshConstants.SSH_MSG_CHANNEL_DATA);
        packet.writeUInt32(channel.getChannelId());

        packet.writeUInt32(payload.length + 4);
        packet.writeUInt32(payload.length);
        packet.writeBytes(payload, 0, payload.length);

        try {
            channel.getSession().sendPacket(packet);
        } catch (Exception e) {
            logger.error("Error sending SFTP packet", e);
        }
        
    }

    private void sendHandleResponse(long requestId, String handle) {

        SshBuffer response = new SshBuffer();
        response.writeByte(SshConstants.SSH_FXP_HANDLE);
        response.writeUInt32(requestId);
        response.writeString(handle);

        try{
            sendPacket(response.getCompactData());
        }catch(Exception e){
            logger.error("Error sending SFTP handle response", e);
        }

        logger.info("Sent SFTP handle response: requestId={}, handle={}", requestId, handle);
    }
    
    public void close() {
        logger.info("Closing SFTP subsystem");
    }

    private synchronized String generateHandle() {
        return "handle_" + (++handleCounter);
    }

    public SessionChannel getChannel() {
        return channel;
    }

}
