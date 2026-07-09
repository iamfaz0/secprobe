#!/bin/bash
# Demo script for SecProbe
# Run this to generate screenshots

echo "=========================================="
echo "     SecProbe v2.0.0 - Demo"
echo "=========================================="
echo ""

# JWT Demo
echo "[*] Running JWT Security Audit..."
echo "Command: python3 secprobe.py jwt --target 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4K3ACPv5y6v5cV9x6cV9x6cV9x'"
echo ""
python3 secprobe.py jwt --target "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4K3ACPv5y6v5cV9x6cV9x6cV9x" --quiet || echo ""

echo ""
echo "=========================================="
echo "[*] Demo complete!"
echo "=========================================="