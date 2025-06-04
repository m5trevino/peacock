#!/bin/bash

# Fetch available Frida scripts
echo "Fetching available Frida scripts..."
scripts_dir="/home/flintx/APKs/frida/"
scripts=$(ls "$scripts_dir"*.js 2>/dev/null)

if [ -z "$scripts" ]; then
    echo "[ERROR] No Frida scripts found in $scripts_dir"
    exit 1
fi

echo "Available Frida scripts:"
select script in $scripts; do
    if [ -n "$script" ]; then
        echo "Selected script: $script"
        break
    else
        echo "[ERROR] Invalid selection. Try again."
    fi
done

# Fetch running processes
echo "Fetching running processes..."
frida-ps -Uia
read -p "Enter the process name or package name to attach the script: " process_name

# Launch the Frida script
frida -U -n "$process_name" -s "$script"