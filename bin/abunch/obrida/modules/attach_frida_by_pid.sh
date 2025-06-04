#!/bin/bash

# Fetch running processes
echo "Fetching running processes..."
frida-ps -Uia

# Prompt for PID
read -p "Enter the PID of the process to attach Frida: " pid

# Attach Frida to the process by PID
frida -U -p "$pid"

# Verify attachment
if [ $? -ne 0 ]; then
    echo "[ERROR] Failed to attach Frida to PID $pid. Ensure the PID is valid."
else
    echo "[SUCCESS] Frida attached to PID $pid."
fi