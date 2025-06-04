#!/bin/bash

# Prompt for app package and activity
read -p "Enter the app package name: " package_name
read -p "Enter the app activity name: " activity_name

# Start the app
adb shell am start -n "$package_name/$activity_name"

# Prompt for Frida script
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

# Attach Frida script
frida -U -n "$package_name" -s "$script"