#!/bin/bash

# Initial Setup
echo "Welcome to the guided setup process."
echo "Please ensure the emulator is already running before proceeding."
echo "Are you setting up MobSF or mitmproxy? (Type 'MobSF' or 'mitmproxy')"
read program

# Step 1: Check ADB Connection
echo "Checking ADB connection..."
adb devices
echo "Ensure the emulator is listed. Is the emulator listed? (y/n)"
read emulator_ready

if [[ "$emulator_ready" == "n" ]]; then
    echo "Please make sure the emulator is running and connected via ADB."
    exit 1
fi

# Step 2: Set ADB Root
echo "Switching ADB to root mode..."
adb root
echo "Did the ADB root succeed? (y/n)"
read adb_root

if [[ "$adb_root" == "n" ]]; then
    echo "ADB root failed. Please check the emulator and ADB."
    exit 1
fi

# Step 3: Set up ADB TCP and Proxy
echo "Setting up ADB TCP forwarding for Frida and proxy."
adb tcpip 5555
echo "TCP mode set. Is it configured correctly? (y/n)"
read tcp_correct

if [[ "$tcp_correct" == "n" ]]; then
    echo "Retry the TCP setup manually or check your settings."
    exit 1
fi

echo "Configuring proxy settings on the emulator..."
adb shell settings put global http_proxy "$HOST_IP:8080"
echo "Did the proxy configuration succeed? (y/n)"
read proxy_success

if [[ "$proxy_success" == "n" ]]; then
    echo "Proxy setup failed. Please recheck the emulator connection."
    exit 1
fi

# Step 4: Start Frida
echo "Starting Frida on the emulator..."
adb shell "chmod +x /data/local/tmp/frida-server-16.5.1-android-x86_64"
adb shell "/data/local/tmp/frida-server-16.5.1-android-x86_64 &"
echo "Verify Frida is running with 'frida-ps -U'. Is Frida running? (y/n)"
read frida_running

if [[ "$frida_running" == "n" ]]; then
    echo "Frida did not start correctly. Please troubleshoot."
    exit 1
fi

# Step 5: Install Burp Certificate
echo "Pushing Burp CA certificate to emulator..."
adb push /home/flintx/main-env/burp-ca-cert.crt /sdcard/burp-ca-cert.crt
adb root
adb remount
adb shell "mv /sdcard/burp-ca-cert.crt /system/etc/security/cacerts/"
adb shell "chmod 644 /system/etc/security/cacerts/burp-ca-cert.crt"
adb reboot
echo "Burp certificate has been installed."

# Step 6: Confirm the program to launch
if [[ "$program" == "MobSF" ]]; then
    echo "Launching MobSF environment..."
    source /root/Mobile-Security-Framework-MobSF/mobsf-env/bin/activate
    cd /root/Mobile-Security-Framework-MobSF/
    ./run.sh
else
    echo "Launching mitmproxy..."
    mitmproxy
fi
