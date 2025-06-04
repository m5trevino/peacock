#!/bin/bash

# Log file
LOG_FILE="obrida.log"

# Function to log messages
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Get the architecture of the connected Android device
get_device_architecture() {
    adb shell getprop ro.product.cpu.abi | tr -d '\r'
}

# Download the latest Frida server
download_frida_server() {
    local arch=$1
    local frida_version="16.1.3" # Update to latest version as needed
    local url="https://github.com/frida/frida/releases/download/${frida_version}/frida-server-${frida_version}-android-${arch}.xz"

    log "Downloading Frida server for architecture: $arch"
    curl -L -o "frida-server-${arch}.xz" "$url"
    if [ $? -ne 0 ]; then
        log "[ERROR] Failed to download Frida server from $url"
        exit 1
    fi

    # Unpack the xz file
    log "Unpacking Frida server..."
    xz -d "frida-server-${arch}.xz"
    chmod +x "frida-server-${arch}"
    mv "frida-server-${arch}" "frida-server"
}

# Push the Frida server to the device
push_frida_to_device() {
    log "Pushing Frida server to device..."
    adb push frida-server /data/local/tmp/frida-server
    adb shell chmod 755 /data/local/tmp/frida-server
}

# Start the Frida server on the device
start_frida_server() {
    log "Starting Frida server on device..."
    adb shell /data/local/tmp/frida-server &
}

# Main function
main() {
    log "Detecting device architecture..."
    local arch=$(get_device_architecture)

    if [ -z "$arch" ]; then
        log "[ERROR] Could not detect device architecture. Ensure the device is connected and adb is working."
        exit 1
    fi

    log "Device architecture detected: $arch"

    if [ ! -f "frida-server" ]; then
        download_frida_server "$arch"
    else
        log "Frida server binary already exists locally. Skipping download."
    fi

    push_frida_to_device
    start_frida_server

    log "[SUCCESS] Frida server has been pushed and started successfully!"
}

main
