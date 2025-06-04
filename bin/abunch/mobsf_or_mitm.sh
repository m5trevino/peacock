#!/bin/bash

# Function to handle proxy setup for mitmproxy and MobSF emulator preparation
setup_mitmproxy() {
    echo "Setting up mitmproxy..."
    
    # Ensure ADB is running in root mode
    adb root
    
    # Start the emulator if it's not already running
    /home/flintx/main-env/mobsf_emulator_setup.sh
    
    # Wait for emulator to boot completely
    adb wait-for-device
    echo "Emulator booted!"
    
    # Pause and ask you to unlock the device (enter pattern or password)
    echo "Please unlock the emulator (enter pattern) and press Enter to continue..."
    read -p ""

    # Forward necessary ports for mitmproxy
    adb reverse tcp:8080 tcp:8080
    
    # Push and install mitmproxy certificate on the emulator
    echo "Pushing mitmproxy certificate to the emulator..."
    adb push /sdcard/Download/mitmproxy-ca-cert.pem /sdcard/
    adb shell "su -c 'mount -o rw,remount /system'"
    adb shell "su -c 'cp /sdcard/mitmproxy-ca-cert.pem /system/etc/security/cacerts/'"
    adb shell "su -c 'chmod 644 /system/etc/security/cacerts/mitmproxy-ca-cert.pem'"
    adb shell "su -c 'mount -o ro,remount /system'"
    adb reboot
    
    echo "Emulator rebooted to apply the certificate."
    
    # Start mitmproxy
    echo "Launching mitmproxy on port 8080..."
    mitmproxy --listen-port 8080
    
    echo "mitmproxy is running. You can start capturing traffic."
}

# Function to handle MobSF startup
setup_mobsf() {
    echo "Setting up MobSF..."
    
    # Activate MobSF environment
    echo "Activating MobSF environment..."
    source /root/Mobile-Security-Framework-MobSF/mobsf-env/bin/activate
    
    # Start the emulator if it's not already running
    /home/flintx/main-env/mobsf_emulator_setup.sh
    
    # Wait for emulator to boot completely
    adb wait-for-device
    echo "Emulator booted!"

    # Start MobSF
    echo "Launching MobSF..."
    /root/Mobile-Security-Framework-MobSF/run.sh
}

# Main script prompt
echo "1) MobSF 2) mitmproxy (Enter 1 or 2): "
read choice

case $choice in
    1)
        setup_mobsf
        ;;
    2)
        setup_mitmproxy
        ;;
    *)
        echo "Invalid option. Exiting."
        exit 1
        ;;
esac
