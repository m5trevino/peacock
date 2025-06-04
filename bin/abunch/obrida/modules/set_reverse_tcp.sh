#!/bin/bash

# Prompt for port details
read -p "Enter local port: " local_port
read -p "Enter emulator port: " emulator_port

# Set reverse TCP port
adb reverse tcp:$local_port tcp:$emulator_port

# Verify port forwarding
adb reverse --list