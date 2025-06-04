#!/bin/bash

# Fetch running processes
echo "Fetching running processes..."
frida-ps -Uia
read -p "Enter the app package name to explore with Objection: " package_name

# Launch Objection
objection -g "$package_name" explore

# Verify success
if [ $? -ne 0 ]; then
    echo "[ERROR] Failed to launch Objection for package $package_name."
else
    echo "[SUCCESS] Objection launched for package $package_name."
fi