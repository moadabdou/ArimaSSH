package com.arima.ssh.server.subsystem;


import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.arima.ssh.common.SshBuffer;
import com.arima.ssh.common.SshConstants;
import com.arima.ssh.server.channel.SessionChannel;

public class SftpSubsystem {


    private final SessionChannel channel;

    private final Map<String, SftpHandle > openHandles = new ConcurrentHashMap<>();
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

        }else if ( packetType == SshConstants.SSH_FXP_OPEN ){

            handleOpen(requestId, payload);

        }else if ( packetType == SshConstants.SSH_FXP_READ) {

            handleRead(requestId, payload);

        }else if ( packetType == SshConstants.SSH_FXP_WRITE) {

            handleWrite(requestId, payload);

        }else if ( packetType == SshConstants.SSH_FXP_CLOSE) {

            handleClose(requestId, payload);

        }else if ( packetType == SshConstants.SSH_FXP_STAT || packetType == SshConstants.SSH_FXP_LSTAT) {

            handleStat(requestId, payload);

        }else if ( packetType == SshConstants.SSH_FXP_REMOVE || packetType == SshConstants.SSH_FXP_RMDIR) {

            handleSimpleCommand(requestId, payload, Files::delete);

        }else if (packetType == SshConstants.SSH_FXP_MKDIR) {

            handleSimpleCommand(requestId, payload, Files::createDirectory);

        }else if(packetType == SshConstants.SSH_FXP_RENAME) {

            handleRename(requestId, payload);

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

            openHandles.put(handle, new DirectoryHandle(path));

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

        SftpHandle dir = openHandles.get(handle);

        if (dir == null || ! (dir instanceof DirectoryHandle)){
            logger.warn("Invalid SFTP handle in read directory request: {}", handle);
            sendStatus(reqId, SshConstants.SSH_FX_NO_SUCH_FILE, "Invalid directory handle");
            return;
        }

        DirectoryHandle directoryHandle = (DirectoryHandle) dir;

        if (!directoryHandle.iterator.hasNext()) {
            // End of File (EOF) - This tells the client "List is finished"
            sendStatus(reqId, SshConstants.SSH_FX_EOF, "End of directory");
            return;
        }

        List<Path> batch = new ArrayList<>();
        int count = 0;
        while (directoryHandle.iterator.hasNext() && count < 50) {
            Path next = directoryHandle.iterator.next();
            batch.add(next);
            count++;
        }

        sendNameResponse(reqId, batch);

    }

    private void handleOpen(long requestId, byte[] payload) {

        SshBuffer request = new SshBuffer(payload);

        String pathString = request.readString();
        int pflags = (int) request.readUInt32();

        Path path = resolvePath(pathString);

        logger.info("Handling SFTP open file request: requestId={}, path={}, pflags={}", requestId, path, pflags);

        try {

            String handle = generateHandle();

            Set<OpenOption> options = SftpOpenFlags.toOpenOptions(pflags);

            FileChannel channel = FileChannel.open(path, options);

            openHandles.put(handle, new FileHandle(channel));

            sendHandleResponse(requestId, handle);

            logger.info("Sent SFTP open file response: requestId={}, handle={}", requestId, handle);

        }catch (Exception e) {

            logger.warn("Error opening file in SFTP request: {}", e.getMessage());

            sendStatus(requestId, SshConstants.SSH_FX_NO_SUCH_FILE, "File does not exist or cannot be opened with the specified flags");

            return;
        }
    }

    private void handleRead(long requestId, byte[] payload) {

        SshBuffer request = new SshBuffer(payload);

        String handle = request.readString();
        long offset = request.readUInt64();
        long length = request.readUInt32();

        // Cap the read length to fit within the channel's max packet size.
        // SFTP framing overhead: 4 (sftp length) + 1 (type) + 4 (reqId) + 4 (data string length) = 13 bytes
        long maxData = channel.getRemoteMaxPacket() - 13;
        if (maxData > 0 && length > maxData) {
            length = maxData;
        }

        logger.info("Handling SFTP read file request: requestId={}, handle={}, offset={}, length={}", requestId, handle, offset, length);

        SftpHandle fileHandle = openHandles.get(handle);

        if (fileHandle == null || ! (fileHandle instanceof FileHandle)){
            logger.warn("Invalid SFTP handle in read file request: {}", handle);
            sendStatus(requestId, SshConstants.SSH_FX_NO_SUCH_FILE, "Invalid file handle");
            return;
        }

        FileHandle fh = (FileHandle) fileHandle;

        try {

            byte[] data = fh.read(offset, length);

            if (data.length == 0) {

                // End of File (EOF) - This tells the client "File is finished"
                sendStatus(requestId, SshConstants.SSH_FX_EOF, "End of file");
                logger.info("Sent SFTP read file EOF response: requestId={}", requestId);
                return;

            }

            sendData(requestId, data);
            logger.info("Sent SFTP read file response: requestId={}, bytesRead={}", requestId, data.length);


        }catch(Exception e){
            logger.error("Error reading from file in SFTP request", e);
            sendStatus(requestId, SshConstants.SSH_FX_FAILURE, "Error reading from file");
        }
    }

    private void handleWrite(long requestId, byte[] payload) {

        SshBuffer request = new SshBuffer(payload);

        String handle = request.readString();
        long offset = request.readUInt64();
        byte[] data = request.readByteString();

        logger.info("Handling SFTP write file request: requestId={}, handle={}, offset={}, dataLength={}", requestId, handle, offset, data.length);

        SftpHandle fileHandle = openHandles.get(handle);

        if (fileHandle == null || ! (fileHandle instanceof FileHandle)){
            logger.warn("Invalid SFTP handle in write file request: {}", handle);
            sendStatus(requestId, SshConstants.SSH_FX_NO_SUCH_FILE, "Invalid file handle");
            return;
        }

        FileHandle fh = (FileHandle) fileHandle;

        try {

            fh.write(offset,  ByteBuffer.wrap(data));

            sendStatus(requestId, SshConstants.SSH_FX_OK, "Write successful");

            logger.info("Sent SFTP write file response: requestId={}, bytesWritten={}", requestId, data.length);

        }catch(Exception e){
            logger.error("Error writing to file in SFTP request", e);
            sendStatus(requestId, SshConstants.SSH_FX_FAILURE, "Error writing to file");
        }
    }

    private void handleClose(long reqId, byte[] buffer){

        String handleId = new SshBuffer(buffer).readString();

        SftpHandle handle = openHandles.remove(handleId);

        if (handle != null) {

            try{
                handle.close();
            }catch(Exception e){
                logger.error("Error closing SFTP handle: ", e);
            }

            sendStatus(reqId, SshConstants.SSH_FX_OK, "Handle closed");

        } else {

            sendStatus(reqId, SshConstants.SSH_FX_FAILURE, "Invalid Handle");
        }
    }

    private void handleStat(long reqId, byte[] buffer) {

        String pathString = new SshBuffer(buffer).readString();

        Path path = resolvePath(pathString);

        logger.info("Handling SFTP stat request: reqId={}, path={}", reqId, path);

        sendAttrs(reqId, path);
    }

    // Functional interface for file operations
    private interface FileOperation {
        void execute(Path path) throws IOException;
    }

    private void handleSimpleCommand(long reqId, byte[] payload, FileOperation op){

        SshBuffer buffer = new SshBuffer(payload);
        String pathStr = buffer.readString();
        Path path = resolvePath(pathStr);

        try {
            op.execute(path);
            sendStatus(reqId, SshConstants.SSH_FX_OK, "Success");
        } catch (IOException e) {
            sendStatus(reqId, SshConstants.SSH_FX_FAILURE,  e.getMessage());
        }

    }

    private void handleRename(long reqId, byte[] payload)  {

        SshBuffer buffer = new SshBuffer(payload);
        String oldPathStr = buffer.readString();
        String newPathStr = buffer.readString();
        
        Path oldPath = resolvePath(oldPathStr);
        Path newPath = resolvePath(newPathStr);

        try {
            // Atomic move is safer
            Files.move(oldPath, newPath, StandardCopyOption.ATOMIC_MOVE);
            sendStatus(reqId, SshConstants.SSH_FX_OK, "Renamed");
        } catch (IOException e) {
            sendStatus(reqId, SshConstants.SSH_FX_FAILURE, e.getMessage());
        }

    }

    // TODO: add attributes support in the future, currently we just send 0 attributes for simplicity. This is needed for some clients to work properly, e.g. FileZilla needs at least the size attribute to be sent in order to display files in the directory.
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

            response.writeUInt32(0); // we dont support attributes for now, so we set it to 0
        }

        sendPacket(response.getCompactData());
    }

    private void sendData(long reqId, byte[] data) {
        
        SshBuffer response = new SshBuffer();
        response.writeByte(SshConstants.SSH_FXP_DATA);
        response.writeUInt32(reqId);
        response.writeByteString(data, 0, data.length);

        try{
            sendPacket(response.getCompactData());
            logger.info("Sent SFTP data response: reqId={}, dataLength={}", reqId, data.length);
        }catch(Exception e){
            logger.error("Error sending SFTP data response", e);
        }

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
            // Simple mapping: Directory (040000) or File (0100000) + standard permissions (0755 for directories, 0644 for files)
            int p = attrs.isDirectory() ? 040755 : 0100644;
            response.writeUInt32(p);


        } catch (IOException e) {
            // File not found
            sendStatus(reqId, SshConstants.SSH_FX_FAILURE, "File not found");
            return;
        }

        sendPacket(response.getCompactData());
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
