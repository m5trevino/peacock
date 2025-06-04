#!/bin/bash

# Step 1: Launch the emulator with writable system and no snapshot
echo "Launching Nexus28 emulator with writable system..."
emulator -avd Nexus28 -writable-system -no-snapshot &

# Wait for the emulator to boot up
echo "Waiting for emulator to fully boot..."
adb wait-for-device

# Step 2: Ensure the emulator is fully booted before proceeding
echo "Waiting for the Android system to be fully booted..."
boot_completed=$(adb shell getprop sys.boot_completed | tr -d '\r')
while [[ "$boot_completed" != "1" ]]; do
    sleep 5
    boot_completed=$(adb shell getprop sys.boot_completed | tr -d '\r')
    echo "Emulator is still booting, waiting..."
done
echo "Emulator booted!"

# Step 3: Set SELinux to permissive mode using root privileges
echo "Attempting to set SELinux to permissive mode..."
adb root
adb shell setenforce 0 || echo "SELinux permissive failed, continuing anyway..."

# Step 4: Set up Frida Server on the emulator
echo "Setting permissions for Frida Server on the emulator..."
adb shell "chmod +x /data/local/tmp/frida-server-16.5.1-android-x86_64"

echo "Starting Frida Server..."
adb shell "/data/local/tmp/frida-server-16.5.1-android-x86_64 &"

# Step 5: Forward Frida port (27042) for MobSF to use
echo "Setting up ADB port forwarding for Frida..."
adb forward tcp:27042 tcp:27042

# Step 6: Push Burp CA certificate to emulator
echo "Pushing Burp CA certificate to emulator..."
adb push /home/flintx/Documents/burp-ca-cert.crt /sdcard/burp-ca-cert.crt

# Move it to the trusted system certificate store
echo "Moving certificate to system trust store..."
adb root
adb remount
adb shell "mv /sdcard/burp-ca-cert.crt /system/etc/security/cacerts/"
adb shell "chmod 644 /system/etc/security/cacerts/burp-ca-cert.crt"

# Step 7: Forward MobSF port (5000) for dynamic analysis
echo "Setting up ADB port forwarding for MobSF..."
adb forward tcp:5000 tcp:5000

# Step 8: Confirm Frida is running
echo "Verifying Frida is running on the emulator..."
frida-ps -U

echo "Emulator and Frida are ready for MobSF dynamic analysis."
