#!/bin/bash
# SecProbe Installer for Kali Linux
# Uses virtual environment to avoid system conflicts

set -e

echo "=========================================="
echo "    SecProbe Installer for Kali"
echo "    Advanced Penetration Testing Toolkit"
echo "=========================================="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Check if running on Kali
if [ -f /etc/os-release ] && grep -q "Kali" /etc/os-release; then
    IS_KALI=true
    echo -e "${YELLOW}[*] Kali Linux detected${NC}"
else
    IS_KALI=false
    echo -e "${YELLOW}[*] Standard Linux detected${NC}"
fi

# Check Python version
echo "[*] Checking Python version..."
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
    echo -e "${GREEN}[+] Python $PYTHON_VERSION found${NC}"
else
    echo -e "${RED}[!] Python 3 not found. Please install it first.${NC}"
    exit 1
fi

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Create virtual environment
echo "[*] Creating virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi

# Activate virtual environment
echo "[*] Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo "[*] Upgrading pip..."
pip install --upgrade pip

# Install dependencies
echo "[*] Installing Python dependencies..."
pip install -r requirements.txt

# Make secprobe executable
echo "[*] Setting up executable..."
chmod +x secprobe.py

# Create wrapper script
cat > secprobe << 'EOF'
#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
source venv/bin/activate
python3 secprobe.py "$@"
EOF

chmod +x secprobe

# Also create a system-wide link
INSTALL_DIR="$HOME/.local/bin"
mkdir -p "$INSTALL_DIR"

cat > "$INSTALL_DIR/secprobe" << EOF
#!/bin/bash
cd "$SCRIPT_DIR"
source venv/bin/activate
python3 secprobe.py "\$@"
EOF

chmod +x "$INSTALL_DIR/secprobe"

# Add to PATH if needed
if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    echo -e "${YELLOW}[*] Adding $INSTALL_DIR to PATH${NC}"
    echo "export PATH=\"\$PATH:$INSTALL_DIR\"" >> ~/.bashrc
    echo "export PATH=\"\$PATH:$INSTALL_DIR\"" >> ~/.zshrc 2>/dev/null || true
fi

echo ""
echo "=========================================="
echo -e "${GREEN}    Installation Complete!${NC}"
echo "=========================================="
echo ""
echo "Usage:"
echo "  ./secprobe --help              # Run from this directory"
echo "  secprobe --help                # Run from anywhere (after restarting terminal)"
echo ""
echo "Available commands:"
echo "  secprobe jwt --target <token>          # JWT audit"
echo "  secprobe api --target <url>            # API security test"
echo "  secprobe recon --target <domain>       # Reconnaissance"
echo "  secprobe full --target <url>           # Full assessment"
echo ""

# Test installation
echo "[*] Testing installation..."
python3 secprobe.py --version 2>/dev/null && echo -e "${GREEN}[+] SecProbe is ready!${NC}" || echo -e "${YELLOW}[!] Restart your terminal or run: source ~/.bashrc${NC}"

echo ""
echo -e "${GREEN}[+] Done!${NC}"
