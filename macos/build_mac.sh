#!/bin/bash
# HenkerDPI V2 macOS - Build Script
# Requires: Python 3.10+, pip

set -e

echo "=== HenkerDPI V2 macOS Build ==="

# Install dependencies
pip3 install -r requirements.txt pyinstaller

# Build with PyInstaller
python3 -m PyInstaller \
    --name "HenkerDPI_V2" \
    --onefile \
    --windowed \
    --add-data "icon.png:." \
    --hidden-import pystray._darwin \
    --hidden-import customtkinter \
    --icon icon.icns \
    --osx-bundle-identifier com.henkerr.henkerdpi.v2 \
    gui.py

echo ""
echo "=== Build complete ==="
echo "Output: dist/HenkerDPI_V2.app"
echo ""
echo "To run: sudo ./dist/HenkerDPI_V2"
echo "Note: Root privileges required for raw sockets and pf rules."
