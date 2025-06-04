#!/bin/bash
echo "Starting Logcat for app..."
read -p "Enter the package name: " package_name
adb logcat | grep "$package_name"

