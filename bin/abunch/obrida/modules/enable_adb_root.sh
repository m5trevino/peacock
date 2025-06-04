#!/bin/bash

# Enable adb root
adb root

# Verify root access
if adb shell whoami | grep -q "root"; then
    echo "[SUCCESS] ADB root enabled."
else
    echo "[ERROR] Failed to enable ADB root. Ensure the device supports root."
fi