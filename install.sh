#!/bin/bash
set -e

# Configuration
REPO="hiro-o918/drydock"
BINARY_NAME="drydock"
# Use provided INSTALL_DIR or default to /usr/local/bin
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

# Detect OS and Architecture
OS=$(uname -s)
ARCH=$(uname -m)

# Determine OS
case $OS in
  Linux)  OS_SUFFIX="Linux" ;;
  Darwin) OS_SUFFIX="Darwin" ;;
  *) echo "Error: Unsupported OS: $OS"; exit 1 ;;
esac

# Determine Architecture
case $ARCH in
  x86_64) ARCH_SUFFIX="x86_64" ;;
  arm64|aarch64) ARCH_SUFFIX="arm64" ;;
  *) echo "Error: Unsupported Architecture: $ARCH"; exit 1 ;;
esac

# Construct Download URL (Latest release)
FILE_NAME="${BINARY_NAME}_${OS_SUFFIX}_${ARCH_SUFFIX}.tar.gz"
DOWNLOAD_URL="https://github.com/${REPO}/releases/latest/download/${FILE_NAME}"

echo "Downloading $BINARY_NAME for $OS_SUFFIX/$ARCH_SUFFIX..."

# Create a temporary directory
TMP_DIR=$(mktemp -d)

# Download the archive
if ! curl -sL "$DOWNLOAD_URL" -o "$TMP_DIR/$FILE_NAME"; then
    echo "Error: Failed to download release from $DOWNLOAD_URL"
    rm -rf "$TMP_DIR"
    exit 1
fi

# Extract the binary
tar -xzf "$TMP_DIR/$FILE_NAME" -C "$TMP_DIR"
chmod +x "$TMP_DIR/$BINARY_NAME"

# Check write permissions for INSTALL_DIR
if [ ! -d "$INSTALL_DIR" ]; then
    echo "Directory $INSTALL_DIR does not exist. Creating it..."
    if ! mkdir -p "$INSTALL_DIR"; then
        echo "Error: Failed to create directory $INSTALL_DIR (permission denied?)"
        rm -rf "$TMP_DIR"
        exit 1
    fi
fi

echo "Installing to $INSTALL_DIR..."

# Move binary (use sudo if not writable)
if [ -w "$INSTALL_DIR" ]; then
    mv "$TMP_DIR/$BINARY_NAME" "$INSTALL_DIR/"
else
    echo "Requires sudo permissions to write to $INSTALL_DIR..."
    sudo mv "$TMP_DIR/$BINARY_NAME" "$INSTALL_DIR/"
fi

# Cleanup
rm -rf "$TMP_DIR"

echo "Successfully installed $BINARY_NAME to $INSTALL_DIR!"
