#!/bin/bash

# Check SELinux mode
selinux_mode=$(adb shell getenforce)

echo "Current SELinux mode: $selinux_mode"

# Set SELinux to permissive if needed
if [[ "$selinux_mode" != "Permissive" ]]; then
    adb shell setenforce 0
    echo "[INFO] SELinux set to permissive mode."
else
    echo "[INFO] SELinux is already in permissive mode."
fi