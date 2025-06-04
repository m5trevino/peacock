#!/bin/bash

# Start Frida server
adb shell /data/local/tmp/frida-server &

# Verify if Frida server started
if adb shell pgrep -f "frida-server"; then
    echo "[SUCCESS] Frida server started."
else
    echo "[ERROR] Failed to start Frida server."
fi