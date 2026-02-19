#!/bin/bash

# ═══════════════════════════════════════════════════════════════════════════════
#  ArimaSSH Client Installer
#  "Let's give it our all!" - Arima Kana
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
INSTALL_DIR="${HOME}/.local/bin"
JAR_DIR="${HOME}/.arima_ssh"
JAR_NAME="arima-ssh-client.jar"
SCRIPT_NAME="arima-ssh"

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
    ║           ⭐ SSH Client Installation ⭐                   ║
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
    
    # Create directories
    mkdir -p "$JAR_DIR"
    mkdir -p "$INSTALL_DIR"
    
    # Copy JAR
    SOURCE_JAR="ssh-client/target/ssh-client-0.1.0-SNAPSHOT.jar"
    if [ -f "$SOURCE_JAR" ]; then
        cp "$SOURCE_JAR" "$JAR_DIR/$JAR_NAME"
        arima_success "JAR installed to ${JAR_DIR}/${JAR_NAME}"
    else
        arima_error "Could not find the built JAR file!"
        arima_say "Expected: ${SOURCE_JAR}" "$RED"
        exit 1
    fi
}

# Create CLI wrapper script
create_wrapper() {
    arima_step "4/4" "Creating CLI wrapper script..."
    
    cat > "$INSTALL_DIR/$SCRIPT_NAME" << 'WRAPPER'
#!/bin/bash
# ArimaSSH Client Wrapper
# "I'll show you a performance you'll never forget!" - Arima Kana

JAR_PATH="${HOME}/.arima_ssh/arima-ssh-client.jar"

if [ ! -f "$JAR_PATH" ]; then
    echo "Error: ArimaSSH client JAR not found at $JAR_PATH"
    echo "Please run the installer again!"
    exit 1
fi

exec java -jar "$JAR_PATH" "$@"
WRAPPER
    
    chmod +x "$INSTALL_DIR/$SCRIPT_NAME"
    arima_success "Wrapper script created at ${INSTALL_DIR}/${SCRIPT_NAME}"
}

# Check PATH
check_path() {
    echo ""
    if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
        arima_say "Almost done! Add this to your shell config (~/.bashrc or ~/.zshrc):" "$YELLOW"
        echo ""
        echo -e "    ${WHITE}export PATH=\"\$PATH:$INSTALL_DIR\"${RESET}"
        echo ""
        arima_say "Then reload your shell or run: source ~/.bashrc" "$YELLOW"
    fi
}

# Final message
print_success() {
    echo ""
    echo -e "${PINK}  ╔═══════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${PINK}  ║${GREEN}          ✨ Installation Complete! ✨                    ${PINK}║${RESET}"
    echo -e "${PINK}  ╚═══════════════════════════════════════════════════════════╝${RESET}"
    echo ""
    arima_excited "You did it! I knew you could!"
    echo ""
    arima_say "Usage: ${CYAN}arima-ssh [options] user@host${RESET}" "$WHITE"
    arima_say "Help:  ${CYAN}arima-ssh --help${RESET}" "$WHITE"
    echo ""
    arima_say "Let's make some secure connections together! (ﾉ◕ヮ◕)ﾉ*:・゚✧" "$PINK"
    echo ""
}

# Uninstall function
uninstall() {
    print_banner
    arima_say "Uninstalling ArimaSSH Client..." "$YELLOW"
    
    if [ -f "$JAR_DIR/$JAR_NAME" ]; then
        rm -f "$JAR_DIR/$JAR_NAME"
        arima_success "Removed JAR file"
    fi
    
    if [ -f "$INSTALL_DIR/$SCRIPT_NAME" ]; then
        rm -f "$INSTALL_DIR/$SCRIPT_NAME"
        arima_success "Removed CLI wrapper"
    fi
    
    echo ""
    arima_say "ArimaSSH has been uninstalled... See you next time! (´;ω;｀)" "$PINK"
    echo ""
}

# Main
main() {
    print_banner
    
    if [ "$1" == "--uninstall" ] || [ "$1" == "-u" ]; then
        uninstall
        exit 0
    fi
    
    arima_excited "Welcome to the ArimaSSH installer!"
    arima_say "I'll guide you through the installation~" "$WHITE"
    echo ""
    
    check_java
    build_project
    install_jar
    create_wrapper
    check_path
    print_success
}

main "$@"
