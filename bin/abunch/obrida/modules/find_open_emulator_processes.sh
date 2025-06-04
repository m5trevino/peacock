#!/bin/bash

# Fetch open processes on the emulator
echo "Fetching open processes on the emulator..."
adb shell ps -A | grep "emulator"

# Ensure the command ran successfully
if [ $? -ne 0 ]; then
    echo "[ERROR] Failed to fetch open processes. Ensure the emulator is running."
else
    echo "[SUCCESS] Open processes fetched successfully."
fi