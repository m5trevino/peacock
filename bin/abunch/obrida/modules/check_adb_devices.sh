#!/bin/bash

# Check connected devices using adb
adb devices

# Ensure at least one device is listed
if adb devices | grep -q "device$"; then
    echo "[SUCCESS] Emulator/Device connected."
else
    echo "[ERROR] No devices found. Ensure the emulator is running."
fi