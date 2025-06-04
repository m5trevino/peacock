#!/bin/bash

# Function to start the Frida server
start_frida_server() {
    echo "Checking ADB connection..."
    adb devices | grep -w "device" > /dev/null
    if [ $? -ne 0 ]; then
        echo "[ERROR] No connected devices found. Ensure the device is connected and ADB is running."
        exit 1
    fi

    echo "Starting Frida server on the device..."
    adb shell /data/local/tmp/frida-server &
    if [ $? -eq 0 ]; then
        echo "[SUCCESS] Frida server started successfully."
    else
        echo "[ERROR] Failed to start Frida server."
    fi
}

# Run the function
start_frida_server
