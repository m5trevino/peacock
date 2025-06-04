#!/bin/bash

# Check and kill processes using port 8080
echo "Checking for processes using port 8080..."
sudo fuser -k 8080/tcp
echo "Killed processes using port 8080 (if any)."

# Get host IP address
HOST_IP=$(hostname -I | awk '{print $1}')
echo "Host IP address is $HOST_IP"

# Ask which program to run
echo "Choose an option to run:"
echo "1) MobSF"
echo "2) mitmproxy"
read -p "Enter 1 or 2: " choice

if [ "$choice" == "1" ]; then
    # Activate MobSF environment
    echo "Main environment activated."
    source /root/Mobile-Security-Framework-MobSF/mobsf-env/bin/activate

    # Start the emulator with full path
    echo "Starting emulator..."
    sudo /home/flintx/Android/Sdk/emulator/emulator -avd Nexus28 -writable-system -no-snapshot-load &

    # Wait for user input to confirm the emulator is fully booted
    read -p "Please unlock the emulator and press Enter to continue..."

    # Run adb devices to confirm emulator connection
    echo "Checking connected devices..."
    adb devices

    # Setup ADB TCP forwarding for Frida
    echo "Setting up ADB TCP forwarding for Frida..."
    adb tcpip 5555
    adb connect $HOST_IP:5555

    # Retry ADB connection if failed
    for i in {1..5}; do
        adb connect $HOST_IP:5555 && break || echo "Retrying ADB connection ($i/5)..."
        sleep 2
    done

    # Configure proxy settings on the emulator
    echo "Configuring proxy settings on the emulator..."
    adb shell settings put global http_proxy "$HOST_IP:8080"

    # Push Burp CA certificate to the emulator
    echo "Pushing Burp CA certificate to the emulator..."
    adb push /home/flintx/main-env/burp-ca-cert.crt /sdcard/burp-ca-cert.crt
    adb root
    adb remount
    adb shell mv /sdcard/burp-ca-cert.crt /system/etc/security/cacerts/
    adb shell chmod 644 /system/etc/security/cacerts/burp-ca-cert.crt
    adb reboot

    # Start MobSF
    echo "Activating MobSF environment..."
    source /root/Mobile-Security-Framework-MobSF/mobsf-env/bin/activate
    echo "MobSF environment activated."
    cd /root/Mobile-Security-Framework-MobSF/
    ./run.sh

elif [ "$choice" == "2" ]; then
    # Mitmproxy setup
    echo "Main environment activated."
    
    # Start the emulator with full path
    echo "Starting emulator..."
    sudo /home/flintx/Android/Sdk/emulator/emulator -avd Nexus28 -writable-system -no-snapshot-load &

    # Wait for user input to confirm the emulator is fully booted
    read -p "Please unlock the emulator and press Enter to continue..."

    # Run adb devices to confirm emulator connection
    echo "Checking connected devices..."
    adb devices

    # Setup ADB TCP forwarding for Frida
    echo "Setting up ADB TCP forwarding for Frida..."
    adb tcpip 5555
    adb connect $HOST_IP:5555

    # Retry ADB connection if failed
    for i in {1..5}; do
        adb connect $HOST_IP:5555 && break || echo "Retrying ADB connection ($i/5)..."
        sleep 2
    done

    # Configure proxy settings on the emulator
    echo "Configuring proxy settings on the emulator..."
    adb shell settings put global http_proxy "$HOST_IP:8080"

    # Start mitmproxy
    echo "Starting mitmproxy..."
    mitmproxy
fi
