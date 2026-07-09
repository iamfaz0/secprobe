#!/bin/bash
# SecProbe Installation Script
# Works on Linux and Termux

set -e

echo "=========================================="
echo "    SecProbe Installer"
echo "    Advanced Penetration Testing Toolkit"
echo "=========================================="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running on Termux
if [[ "$PREFIX" == *"com.termux"* ]]; then
    IS_TERMUX=true
    echo -e "${YELLOW}[*] Termux detected${NC}"
    echo -e "${YELLOW}[*] Note: Installing cryptography on Termux requires rust. If install fails, run:${NC}"
    echo -e "      pkg update && pkg install rust python-cryptography${NC}"
else
    IS_TERMUX=false
    echo -e "${YELLOW}[*] Linux system detected${NC}"
fi

# Check Python version
echo "[*] Checking Python version..."
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
    echo -e "${GREEN}[+] Python $PYTHON_VERSION found${NC}"
else
    echo -e "${RED}[!] Python 3 not found. Installing...${NC}"
    if [ "$IS_TERMUX" = true ]; then
        pkg update && pkg install -y python
    else
        apt-get update && apt-get install -y python3 python3-pip
    fi
fi

# Check pip
echo "[*] Checking pip..."
if ! command -v pip3 &> /dev/null; then
    echo -e "${YELLOW}[*] Installing pip...${NC}"
    if [ "$IS_TERMUX" = true ]; then
        pkg install -y python-pip
    else
        apt-get install -y python3-pip
    fi
fi

# Install dependencies
echo "[*] Installing Python dependencies..."

# Use Termux-specific requirements if on Termux
if [ "$IS_TERMUX" = true ]; then
    REQ_FILE="requirements-termux.txt"
    echo "[*] Using Termux-optimized requirements"
else
    REQ_FILE="requirements.txt"
fi

# Try user install first, then system-wide with --break-system-packages for externally managed environments
pip3 install --user -r "$REQ_FILE" 2>/dev/null || \
pip3 install --break-system-packages --user -r "$REQ_FILE" 2>/dev/null || \
pip3 install -r "$REQ_FILE" 2>/dev/null || \
pip3 install --break-system-packages -r "$REQ_FILE" 2>/dev/null || {
    echo -e "${RED}[!] Failed to install dependencies.${NC}"
    if [ "$IS_TERMUX" = true ]; then
        echo "   Try: pkg install rust python-cryptography"
        echo "   Then re-run this installer"
    else
        echo "   Try running with --break-system-packages flag"
        echo "   Or use: python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt"
    fi
}

# Make secprobe executable
echo "[*] Setting up executable..."
chmod +x secprobe.py

# Create symlink
INSTALL_DIR="$HOME/.local/bin"
if [ "$IS_TERMUX" = true ]; then
    INSTALL_DIR="$PREFIX/bin"
fi

mkdir -p "$INSTALL_DIR"

# Get absolute path
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cat > "$INSTALL_DIR/secprobe" << EOF
#!/bin/bash
python3 "$SCRIPT_DIR/secprobe.py" "\$@"
EOF

chmod +x "$INSTALL_DIR/secprobe"

# Add to PATH if needed
if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    echo -e "${YELLOW}[*] Adding $INSTALL_DIR to PATH${NC}"
    if [ "$IS_TERMUX" = true ]; then
        echo "export PATH=\"\$PATH:$INSTALL_DIR\"" >> ~/.bashrc
    else
        echo "export PATH=\"\$PATH:$INSTALL_DIR\"" >> ~/.bashrc
        echo "export PATH=\"\$PATH:$INSTALL_DIR\"" >> ~/.zshrc 2>/dev/null || true
    fi
fi

echo ""
echo "=========================================="
echo -e "${GREEN}    Installation Complete!${NC}"
echo "=========================================="
echo ""
echo "Usage:"
echo "  secprobe jwt --target <token>          # JWT audit"
echo "  secprobe api --target <url>            # API test"
echo "  secprobe recon --target <domain>       # Reconnaissance"
echo "  secprobe full --target <url>           # Full assessment"
echo ""
echo "Or run directly:"
echo "  python3 secprobe.py --help"
echo ""

# Test installation
echo "[*] Testing installation..."
python3 secprobe.py --version 2>/dev/null || echo -e "${YELLOW}[!] Restart your terminal or run: source ~/.bashrc${NC}"

echo ""
echo -e "${GREEN}[+] Done!${NC}"