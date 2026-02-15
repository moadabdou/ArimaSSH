package com.arima.ssh.client;

import java.io.PrintWriter;

import org.jline.terminal.Terminal;
import org.jline.terminal.TerminalBuilder;
import org.jline.utils.NonBlockingReader;
import org.jline.utils.InfoCmp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.arima.ssh.client.banner.Banner;
import com.arima.ssh.client.banner.DefaultBanner;

public class SshClient {

    private static final Logger logger = LoggerFactory.getLogger(SshClient.class);
    private Banner banner = new DefaultBanner();


    public static void main(String[] args) {

        System.out.print(new DefaultBanner().loadBanner());

        try (Terminal terminal = TerminalBuilder.builder()
                .system(true) // Connect to the real system terminal
                .nativeSignals(true) // Handle signals like Ctrl+C natively
                .build()) {

            // 1. Enter Raw Mode
            // This stops the terminal from echoing characters automatically
            // and buffering lines (waiting for ENTER).
            terminal.enterRawMode();

            // 2. The Input Loop
            NonBlockingReader reader = terminal.reader();
            PrintWriter writer =  terminal.writer();
            
            // This is roughly what our "Shell Loop" will look like later
            while (true) {
                int c = reader.read();
                
                if (c == -1) break; // EOF

                // Ctrl+C is usually 3
                if (c == 3 || c == 'q') {
                    System.out.println("\nExiting...");
                    break;
                }

                // Print the raw key code
                // \r is needed because in raw mode, \n only moves down, not back to start of line
                System.out.print("Pressed: " + c + " ('" + (char)c + "')\r\n");
                
                // Flush to ensure output appears immediately
                terminal.flush();
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}