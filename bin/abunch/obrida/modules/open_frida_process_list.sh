#!/bin/bash

# Open a new terminal window to display frida-ps output
gnome-terminal -- bash -c "frida-ps -Uia; exec bash"

if [ $? -ne 0 ]; then
    echo "[ERROR] Failed to open Frida process list in a new terminal window."
else
    echo "[SUCCESS] Opened Frida process list in a new terminal."
fi