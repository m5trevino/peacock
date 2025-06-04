#!/bin/bash

# Step 1: Activate the main Python environment
echo "Activating Python environment..."
source /home/flintx/main-env/bin/activate

# Step 2: Launch the emulator with writable system and no snapshot
echo "Launching Nexus28 emulator with writable system..."
/home/flintx/main-env/mobsf_emulator_setup.sh &

# Wait for the emulator to fully boot up
echo "Waiting for emulator to fully boot..."
adb wait-for-device

# Set up ADB in root mode
echo "Enabling ADB root mode..."
adb root

# Step 3: Start Frida Server on the emulator
echo "Starting Frida Server..."
adb shell "chmod +x /data/local/tmp/frida-server-16.5.1-android-x86_64"
adb shell "/data/local/tmp/frida-server-16.5.1-android-x86_64 &"

# Set up Frida port forwarding
echo "Setting up ADB port forwarding for Frida..."
adb forward tcp:27042 tcp:27042

# Step 4: Reverse proxy setup for MobSF
echo "Setting up reverse proxy for MobSF..."
adb forward tcp:5000 tcp:5000

# Step 5: Prompt to choose between MobSF or mitmproxy
read -p "Choose dynamic analysis tool: 1) MobSF 2) mitmproxy (Enter 1 or 2): " choice

if [ "$choice" -eq 1 ]; then
    echo "Activating MobSF environment..."
    source /root/Mobile-Security-Framework-MobSF/mobsf-env/bin/activate
    
    echo "Starting MobSF..."
    /root/Mobile-Security-Framework-MobSF/run.sh
elif [ "$choice" -eq 2 ]; then
    echo "Starting mitmproxy..."
    mitmproxy
else
    echo "Invalid choice. Exiting."
    exit 1
fi
