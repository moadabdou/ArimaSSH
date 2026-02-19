#!/bin/bash

# ═══════════════════════════════════════════════════════════════════════════════
#  ArimaSSH Server Installer
#  "I'll become a star that lights up the stage!" - Arima Kana
# ═══════════════════════════════════════════════════════════════════════════════

set -e

# Colors
PINK='\033[1;35m'
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
CYAN='\033[1;36m'
WHITE='\033[1;37m'
RESET='\033[0m'

# Installation paths
JAR_DIR="${HOME}/.arima_ssh"
JAR_NAME="arima-ssh-server.jar"
SERVICE_NAME="arima-ssh-server"
SYSTEMD_USER_DIR="${HOME}/.config/systemd/user"
PID_FILE="${JAR_DIR}/server.pid"
LOG_FILE="${JAR_DIR}/server.log"

# Cute ASCII art
print_banner() {
    echo -e "${PINK}"
    cat << 'EOF'
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║      ___       _                   ____ ____  _   _       ║
    ║     / _ \  _ __(_)_ __ ___   __ _ / ___/ ___|| | | |      ║
    ║    | |_| || '__| | '_ ` _ \ / _` |\___ \___ \| |_| |      ║
    ║    |  _  || |  | | | | | | | (_| | ___) |__) |  _  |      ║
    ║    |_| |_||_|  |_|_| |_| |_|\__,_||____/____/|_| |_|      ║
    ║                                                           ║
    ║           ⭐ SSH Server Installation ⭐                   ║
    ╚═══════════════════════════════════════════════════════════╝
EOF
    echo -e "${RESET}"
}

# Arima-styled messages
arima_say() {
    local msg="$1"
    local color="${2:-$PINK}"
    echo -e "${color}  ✧ ${msg}${RESET}"
}

arima_excited() {
    local msg="$1"
    echo -e "${YELLOW}  ★ ${msg} ★${RESET}"
}

arima_success() {
    local msg="$1"
    echo -e "${GREEN}  ✓ ${msg}${RESET}"
}

arima_error() {
    local msg="$1"
    echo -e "${RED}  ✗ ${msg}${RESET}"
}

arima_step() {
    local step="$1"
    local msg="$2"
    echo -e "${CYAN}  [${step}]${WHITE} ${msg}${RESET}"
}

# Check for Java
check_java() {
    arima_step "1/4" "Checking if Java is installed..."
    if command -v java &> /dev/null; then
        JAVA_VERSION=$(java -version 2>&1 | head -n 1 | cut -d'"' -f2)
        arima_success "Found Java ${JAVA_VERSION}! Nice~"
    else
        arima_error "Java not found! You need Java 21+ to run ArimaSSH!"
        arima_say "Please install Java first, then try again!" "$RED"
        exit 1
    fi
}

# Build the project
build_project() {
    arima_step "2/4" "Building the project... (This might take a moment!)"
    arima_say "Hang in there! I'm compiling everything~" "$YELLOW"
    
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    cd "$SCRIPT_DIR"
    
    if [ ! -f "pom.xml" ]; then
        arima_error "pom.xml not found! Are you in the right directory?"
        exit 1
    fi
    
    if mvn clean package -DskipTests -q; then
        arima_success "Build complete! That was perfect~!"
    else
        arima_error "Build failed... Let's check what went wrong!"
        exit 1
    fi
}

# Install the JAR
install_jar() {
    arima_step "3/4" "Installing the JAR file..."
    
    # Create directory
    mkdir -p "$JAR_DIR"
    
    # Copy JAR
    SOURCE_JAR="ssh-server/target/ssh-server-0.1.0-SNAPSHOT.jar"
    if [ -f "$SOURCE_JAR" ]; then
        cp "$SOURCE_JAR" "$JAR_DIR/$JAR_NAME"
        arima_success "JAR installed to ${JAR_DIR}/${JAR_NAME}"
    else
        arima_error "Could not find the built JAR file!"
        arima_say "Expected: ${SOURCE_JAR}" "$RED"
        exit 1
    fi
}

# Create systemd service
create_systemd_service() {
    arima_step "4/4" "Creating systemd user service..."
    
    # Create systemd user directory
    mkdir -p "$SYSTEMD_USER_DIR"
    
    # Find Java path
    JAVA_PATH=$(which java)
    
    cat > "$SYSTEMD_USER_DIR/${SERVICE_NAME}.service" << SERVICEEOF
[Unit]
Description=ArimaSSH Server - Secure Shell Server
After=network.target

[Service]
Type=simple
WorkingDirectory=${JAR_DIR}
ExecStart=${JAVA_PATH} -jar ${JAR_DIR}/${JAR_NAME}
Restart=on-failure
RestartSec=5
StandardOutput=append:${LOG_FILE}
StandardError=append:${LOG_FILE}

[Install]
WantedBy=default.target
SERVICEEOF
    
    arima_success "Systemd service created!"
    
    # Reload systemd
    systemctl --user daemon-reload
    arima_success "Systemd daemon reloaded!"
}

# Enable and start the service
enable_service() {
    arima_say "Enabling the service to start on boot..." "$CYAN"
    systemctl --user enable "$SERVICE_NAME" 2>/dev/null || true
    arima_success "Service enabled!"
    
    arima_say "Starting the server..." "$CYAN"
    systemctl --user start "$SERVICE_NAME"
    arima_success "Server started!"
}

# Manual background process (fallback if systemd is not available)
start_manual() {
    arima_say "Starting server as background process..." "$CYAN"
    
    # Check if already running
    if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
        arima_say "Server is already running (PID: $(cat "$PID_FILE"))" "$YELLOW"
        return
    fi
    
    cd "$JAR_DIR"
    nohup java -jar "$JAR_DIR/$JAR_NAME" >> "$LOG_FILE" 2>&1 &
    echo $! > "$PID_FILE"
    arima_success "Server started with PID $(cat "$PID_FILE")"
}

# Stop manual background process
stop_manual() {
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if kill -0 "$PID" 2>/dev/null; then
            kill "$PID"
            rm -f "$PID_FILE"
            arima_success "Server stopped"
        else
            arima_say "Server was not running" "$YELLOW"
            rm -f "$PID_FILE"
        fi
    else
        arima_say "No PID file found. Server may not be running." "$YELLOW"
    fi
}

# Check server status
check_status() {
    print_banner
    echo ""
    
    # Try systemd first
    if systemctl --user is-active "$SERVICE_NAME" &>/dev/null; then
        arima_success "Server is running (systemd)!"
        echo ""
        systemctl --user status "$SERVICE_NAME" --no-pager
    elif [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
        arima_success "Server is running (PID: $(cat "$PID_FILE"))"
    else
        arima_say "Server is not running" "$YELLOW"
    fi
    
    echo ""
    if [ -f "$LOG_FILE" ]; then
        arima_say "Last 10 log lines:" "$CYAN"
        tail -10 "$LOG_FILE" 2>/dev/null || true
    fi
}

# Start server
start_server() {
    print_banner
    echo ""
    
    # Check if JAR exists
    if [ ! -f "$JAR_DIR/$JAR_NAME" ]; then
        arima_error "Server JAR not found! Please run the installer first."
        exit 1
    fi
    
    # Try systemd first
    if command -v systemctl &> /dev/null && systemctl --user status &>/dev/null; then
        arima_say "Starting server via systemd..." "$CYAN"
        systemctl --user start "$SERVICE_NAME"
        arima_success "Server started!"
    else
        start_manual
    fi
}

# Stop server
stop_server() {
    print_banner
    echo ""
    
    # Try systemd first
    if command -v systemctl &> /dev/null && systemctl --user is-active "$SERVICE_NAME" &>/dev/null; then
        arima_say "Stopping server via systemd..." "$CYAN"
        systemctl --user stop "$SERVICE_NAME"
        arima_success "Server stopped!"
    else
        stop_manual
    fi
}

# Restart server
restart_server() {
    print_banner
    echo ""
    
    # Try systemd first
    if command -v systemctl &> /dev/null && systemctl --user status &>/dev/null; then
        arima_say "Restarting server via systemd..." "$CYAN"
        systemctl --user restart "$SERVICE_NAME"
        arima_success "Server restarted!"
    else
        stop_manual
        sleep 1
        start_manual
    fi
}

# View logs
view_logs() {
    print_banner
    echo ""
    
    if [ -f "$LOG_FILE" ]; then
        arima_say "Server logs (press Ctrl+C to exit):" "$CYAN"
        echo ""
        tail -f "$LOG_FILE"
    else
        arima_say "No log file found at $LOG_FILE" "$YELLOW"
    fi
}

# Final message
print_success() {
    echo ""
    echo -e "${PINK}  ╔═══════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${PINK}  ║${GREEN}          ✨ Installation Complete! ✨                    ${PINK}║${RESET}"
    echo -e "${PINK}  ╚═══════════════════════════════════════════════════════════╝${RESET}"
    echo ""
    arima_excited "The server is installed and running!"
    echo ""
    arima_say "Commands:" "$WHITE"
    echo -e "    ${CYAN}./install_server.sh start${RESET}   - Start the server"
    echo -e "    ${CYAN}./install_server.sh stop${RESET}    - Stop the server"
    echo -e "    ${CYAN}./install_server.sh restart${RESET} - Restart the server"
    echo -e "    ${CYAN}./install_server.sh status${RESET}  - Check server status"
    echo -e "    ${CYAN}./install_server.sh logs${RESET}    - View server logs"
    echo ""
    arima_say "Log file: ${CYAN}${LOG_FILE}${RESET}" "$WHITE"
    arima_say "JAR file: ${CYAN}${JAR_DIR}/${JAR_NAME}${RESET}" "$WHITE"
    echo ""
    arima_say "Your SSH server is ready to shine! (ﾉ◕ヮ◕)ﾉ*:・゚✧" "$PINK"
    echo ""
}

# Uninstall function
uninstall() {
    print_banner
    arima_say "Uninstalling ArimaSSH Server..." "$YELLOW"
    
    # Stop the service first
    if command -v systemctl &> /dev/null; then
        systemctl --user stop "$SERVICE_NAME" 2>/dev/null || true
        systemctl --user disable "$SERVICE_NAME" 2>/dev/null || true
    fi
    stop_manual 2>/dev/null || true
    
    # Remove files
    if [ -f "$JAR_DIR/$JAR_NAME" ]; then
        rm -f "$JAR_DIR/$JAR_NAME"
        arima_success "Removed JAR file"
    fi
    
    if [ -f "$SYSTEMD_USER_DIR/${SERVICE_NAME}.service" ]; then
        rm -f "$SYSTEMD_USER_DIR/${SERVICE_NAME}.service"
        systemctl --user daemon-reload 2>/dev/null || true
        arima_success "Removed systemd service"
    fi
    
    if [ -f "$PID_FILE" ]; then
        rm -f "$PID_FILE"
    fi
    
    echo ""
    arima_say "ArimaSSH Server has been uninstalled... See you next time! (´;ω;｀)" "$PINK"
    echo ""
}

# Print help
print_help() {
    print_banner
    echo ""
    arima_say "Usage: ./install_server.sh [command]" "$WHITE"
    echo ""
    echo "  Commands:"
    echo -e "    ${CYAN}(no args)${RESET}     Install and start the server"
    echo -e "    ${CYAN}start${RESET}         Start the server"
    echo -e "    ${CYAN}stop${RESET}          Stop the server"
    echo -e "    ${CYAN}restart${RESET}       Restart the server"
    echo -e "    ${CYAN}status${RESET}        Check server status"
    echo -e "    ${CYAN}logs${RESET}          View server logs (tail -f)"
    echo -e "    ${CYAN}--uninstall${RESET}   Uninstall the server"
    echo -e "    ${CYAN}--help${RESET}        Show this help message"
    echo ""
}

# Main installation
install() {
    print_banner
    
    arima_excited "Welcome to the ArimaSSH Server installer!"
    arima_say "I'll set up everything for you~" "$WHITE"
    echo ""
    
    check_java
    build_project
    install_jar
    
    # Check if systemd is available
    if command -v systemctl &> /dev/null && systemctl --user status &>/dev/null; then
        create_systemd_service
        enable_service
    else
        arima_say "Systemd not available, using manual background process..." "$YELLOW"
        start_manual
    fi
    
    print_success
}

# Main
main() {
    case "${1:-}" in
        start)
            start_server
            ;;
        stop)
            stop_server
            ;;
        restart)
            restart_server
            ;;
        status)
            check_status
            ;;
        logs)
            view_logs
            ;;
        --uninstall|-u)
            uninstall
            ;;
        --help|-h)
            print_help
            ;;
        "")
            install
            ;;
        *)
            arima_error "Unknown command: $1"
            print_help
            exit 1
            ;;
    esac
}

main "$@"
