#!/bin/bash
echo "Starting app and running Frida script..."
read -p "Enter the package name: " package_name
read -p "Enter the activity name: " activity_name
read -p "Enter the script path: " script_path
adb shell am start -n "$package_name/$activity_name"
frida -U -n "$package_name" -s "$script_path"

