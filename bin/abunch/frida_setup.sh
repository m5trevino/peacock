#!/bin/bash

# Step 1: Launch the emulator with writable system and no snapshot
echo "Launching Nexus28 emulator with writable system..."
emulator -avd Nexus28 -writable-system -no-snapshot &

# Wait for the emulator to boot up
echo "Waiting for emulator to fully boot..."
adb wait-for-device

# Step 2: Set up Frida Server on the emulator
echo "Setting permissions for Frida Server on the emulator..."
adb shell "chmod +x /data/local/tmp/frida-server-16.5.1-android-x86_64"

echo "Starting Frida Server..."
adb shell "/data/local/tmp/frida-server-16.5.1-android-x86_64 &"

# Step 3: Forward Frida port (27042) for MobSF to use
echo "Setting up ADB port forwarding for Frida..."
adb forward tcp:27042 tcp:27042

# Step 4: Forward MobSF proxy port (5000)
echo "Setting up ADB port forwarding for MobSF..."
adb forward tcp:5000 tcp:5000

# Confirm Frida is running
echo "Verifying Frida is running on the emulator..."
frida-ps -U

echo "Emulator, Frida, and MobSF port forwarding are ready for dynamic analysis."
