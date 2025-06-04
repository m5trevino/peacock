#!/bin/bash

# Kill Frida server if running
adb shell pkill frida-server

# Confirm if it was killed successfully
if adb shell pgrep -f "frida-server"; then
    echo "[ERROR] Failed to kill Frida server."
else
    echo "[SUCCESS] Frida server killed."
fi