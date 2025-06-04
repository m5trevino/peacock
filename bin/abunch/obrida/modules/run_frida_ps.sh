#!/bin/bash

# Run frida-ps to list processes
echo "Fetching running processes with Frida..."
frida-ps -Uia

# Ensure the command ran successfully
if [ $? -ne 0 ]; then
    echo "[ERROR] Failed to list processes. Ensure Frida server is running and device is connected."
else
    echo "[SUCCESS] Processes fetched successfully."
fi