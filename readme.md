# ArimaSSH

<p align="center">
  <img src="./assets/emotes/arima.png" alt="ArimaSSH Logo" width="80">
</p>

<p align="center">
  <strong>A pure Java implementation of the SSH-2 protocol</strong>
</p>

<p align="center">
  <a href="#features">Features</a> |
  <a href="#architecture">Architecture</a> |
  <a href="#installation">Installation</a> |
  <a href="#usage">Usage</a> |
  <a href="#configuration">Configuration</a> |
  <a href="#demo">Demo</a>
</p>

---

## Overview

ArimaSSH is a modular, pure Java implementation of the SSH-2 protocol (RFC 4253), providing both client and server components. Built with modern Java 21 features including Virtual Threads, it offers a lightweight and educational alternative for secure shell communications.

This project implements the core SSH-2 transport layer, authentication mechanisms, connection protocol, and SFTP subsystem from scratch, utilizing the Bouncy Castle cryptographic library for security primitives.

---

## Features

### Protocol Support

- **SSH-2 Transport Layer** - Full implementation of RFC 4253 including version exchange, algorithm negotiation, and key exchange
- **Key Exchange Algorithms**
  - `diffie-hellman-group14-sha1`
  - `diffie-hellman-group14-sha256`
- **Encryption Ciphers**
  - `aes128-ctr`
  - `aes192-ctr`
  - `aes256-ctr`
  - `3des-cbc`
- **MAC Algorithms** - HMAC-based message authentication

### Authentication

- **Password Authentication** - System-level PAM integration for Unix/Linux systems
- **Public Key Authentication** - RSA, DSA, ECDSA, and Ed25519 key support
- **Authorized Keys** - File-based public key management

### Channels and Subsystems

- **Interactive Shell Sessions** - PTY allocation with terminal emulation via pty4j
- **Command Execution** - Remote command execution without shell allocation
- **SFTP Subsystem** - Full SFTP version 3 implementation for file transfer operations
- **TCP/IP Port Forwarding**
  - Local port forwarding (`-L`)
  - Remote port forwarding (`-R`)

### Server Features

- **Customizable Banner** - Pre-authentication banner support
- **Host Key Management** - Automatic host key generation and persistence
- **Systemd Integration** - User-level systemd service support for Linux
- **Virtual Thread Pool** - Efficient connection handling using Project Loom

### Client Features

- **Interactive Terminal** - JLine-based terminal with full ANSI support
- **Identity File Support** - PEM-formatted private key authentication
- **Verbose Logging** - Debug output for troubleshooting connections

---

## Architecture

ArimaSSH follows a modular Maven multi-project structure:

```
ArimaSSH/
├── ssh-common/          # Shared protocol implementation
│   ├── channel/         # Channel abstractions and TCP/IP tunneling
│   ├── crypto/          # Cipher, MAC, signature utilities
│   └── kex/             # Key exchange implementations
├── ssh-server/          # SSH server implementation
│   ├── auth/            # Password and public key authenticators
│   ├── channel/         # Server-side channel handling
│   └── subsystem/       # SFTP subsystem implementation
└── ssh-client/          # SSH client implementation
    ├── channel/         # Client-side channel handling
    └── banner/          # Client banner display
```

### Dependencies

| Component | Purpose |
|-----------|---------|
| Bouncy Castle | Cryptographic operations (bcprov-jdk18on, bcpkix-jdk18on) |
| pty4j | Pseudo-terminal support for shell sessions |
| JLine | Interactive terminal handling |
| picocli | Command-line argument parsing |
| SLF4J | Logging facade |

---

## Requirements

- **Java 21** or later (required for Virtual Threads)
- **Maven 3.6+** for building
- **Linux/macOS** for full server functionality (PAM authentication)

---

## Installation

### Building from Source

```bash
git clone https://github.com/moadabdou/ArimaSSH.git
cd ArimaSSH
```

### Installing the Client

```bash
./install_client.sh
```

This script:
1. Builds the project using Maven
2. Installs the client JAR to `~/.arima_ssh/`
3. Creates an executable wrapper script in `~/.local/bin/arima-ssh`

### Installing the Server

```bash
./install_server.sh
```

This script:
1. Builds the project using Maven
2. Installs the server JAR to `~/.arima_ssh/`
3. Generates host keys if not present
4. Optionally configures a systemd user service

---

## Usage

### Client

```bash
# Basic connection
arima-ssh user@hostname

# Specify port and identity file
arima-ssh -p 22 -i ~/.ssh/id_rsa user@hostname

# Execute remote command
arima-ssh user@hostname "ls -la"

# Local port forwarding
arima-ssh user@hostname -L 8080:localhost:80 

# Remote port forwarding
arima-ssh user@hostname -R 9000:localhost:3000 

# Port forwarding without shell
arima-ssh -N user@hostname -L 8080:localhost:80 

# Enable verbose output
arima-ssh -v user@hostname
```

#### Client Options

| Option | Description |
|--------|-------------|
| `-p, --port` | SSH server port (default: 3003) |
| `-i, --identity` | Path to private key file for authentication |
| `-L` | Local port forwarding (bindAddr:bindPort:targetHost:targetPort) |
| `-R` | Remote port forwarding (bindAddr:bindPort:targetHost:targetPort) |
| `-N, --no-shell` | Do not request a shell (for port forwarding only) |
| `-v, --verbose` | Enable debug logging output |

### Server

The server can be managed via the installer script or run directly:

```bash
# Start server via systemd (if installed as service)
systemctl --user start arima-ssh-server
# or 
./install_server.sh start 

# Check server status
systemctl --user status arima-ssh-server
# or 
./install_server.sh status 

# View server logs
journalctl --user -u arima-ssh-server -f

# Run server directly (for testing)
java -jar ~/.arima_ssh/arima-ssh-server.jar
```

---

## Configuration

### Server Configuration

Server configuration is stored in `~/.arima_ssh/.config`:

```ini
# ArimaSSH Server Configuration
port=3003
```

### Host Keys

Host keys are automatically generated on first run and stored in:
- `~/.arima_ssh/host_key` (private key)
- `~/.arima_ssh/host_key.pub` (public key)

### Authorized Keys

For public key authentication, add client public keys to:
- `~/.arima_ssh/authorized_keys` (standard OpenSSH format)

---

## Protocol Implementation Details

### Packet Structure

All packets follow the SSH-2 binary packet protocol:
```
uint32    packet_length
byte      padding_length
byte[n1]  payload
byte[n2]  padding
byte[m]   MAC
```

### Key Derivation

Session keys are derived using the shared secret and exchange hash as specified in RFC 4253, supporting the required key material for:
- Initial IV (client to server / server to client)
- Encryption key (client to server / server to client)
- Integrity key (client to server / server to client)

---

## Demo

A demonstration of ArimaSSH in action is available here:

**[View Demo on LinkedIn](https://www.linkedin.com/posts/moad-elabdellaoui-401613248_java-ssh-cryptography-activity-7430731395494297600-zfzz?utm_source=share&utm_medium=member_desktop&rcm=ACoAAD1Qr4EBi4dEscWptj244uLf4dVDbX9EqFI)**

---

## Limitations

- Compression algorithms are not currently implemented
- Certificate-based authentication is not supported
- Only SFTP version 3 is implemented

---

## Acknowledgments

- SSH-2 protocol specifications: RFC 4250, RFC 4251, RFC 4252, RFC 4253, RFC 4254
- SFTP protocol: draft-ietf-secsh-filexfer-02
- Bouncy Castle for cryptographic primitives
- JetBrains pty4j for terminal emulation

