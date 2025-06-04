#!/bin/bash

# Function to kill any process using a specific port
kill_port() {
    local PORT=$1
    echo "Checking for processes using port $PORT..."
    fuser -k "$PORT"/tcp
    echo "Killed processes using port $PORT (if any)."
}

# Kill processes using port 8080 to free it for mitmproxy or MobSF
kill_port 8080

# Activate the main environment
echo "Activating main environment..."
source /home/flintx/main-env/bin/activate

# Start the emulator without loading any saved state
echo "Starting emulator without saved state..."
/home/flintx/Android/Sdk/emulator/emulator -avd Nexus28 -writable-system -no-snapshot-load &

# Wait for the emulator to boot completely
echo "Waiting for emulator to fully boot..."
adb wait-for-device

# Wait for manual unlock and confirmation
read -p "Please unlock the emulator (enter pattern) and press Enter to continue..."

# Set SELinux to permissive mode
echo "Attempting to set SELinux to permissive mode..."
adb root
adb shell setenforce 0

# Setup Frida
echo "Setting permissions for Frida Server on the emulator..."
adb shell "chmod 755 /data/local/tmp/frida-server-16.5.1-android-x86_64"
echo "Starting Frida Server..."
adb shell "/data/local/tmp/frida-server-16.5.1-android-x86_64 &"
echo "Setting up ADB port forwarding for Frida..."
adb forward tcp:27042 tcp:27042

# Push the Burp certificate to the emulator
echo "Pushing Burp CA certificate to emulator..."
adb push /home/flintx/main-env/burp-ca-cert.crt /sdcard/burp-ca-cert.crt
echo "Moving certificate to system trust store..."
adb root
adb remount
adb shell mv /sdcard/burp-ca-cert.crt /system/etc/security/cacerts/
adb shell chmod 644 /system/etc/security/cacerts/burp-ca-cert.crt
adb reboot

# Wait for emulator to reboot and confirm
adb wait-for-device
read -p "Please unlock the emulator after reboot and press Enter to continue..."

# Prompt user for MobSF or mitmproxy
echo "Choose an option to run:"
echo "1) MobSF"
echo "2) mitmproxy"
read -p "Enter 1 or 2: " choice

if [ "$choice" == "1" ]; then
    echo "Setting up ADB port forwarding for MobSF..."
    adb forward tcp:5000 tcp:5000
    echo "Starting MobSF..."
    source /root/Mobile-Security-Framework-MobSF/mobsf-env/bin/activate
    /root/Mobile-Security-Framework-MobSF/run.sh
elif [ "$choice" == "2" ]; then
    echo "Starting mitmproxy on port 8080..."
    mitmproxy
else
    echo "Invalid option selected. Exiting..."
    exit 1
fi
