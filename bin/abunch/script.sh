#!/bin/bash

# Initial Setup
echo "Welcome to the guided setup process."
echo "Please ensure the emulator is already running before proceeding."
echo "Are you setting up MobSF or mitmproxy? (Type 'MobSF' or 'mitmproxy')"
read program

# Step 1: Check ADB Connection
echo "Step 1: Check ADB connection."
echo "Run the following command:"
echo "adb devices"
read -p "Press Enter after you've manually run the above command."

# Step 2: Set ADB Root
echo "Step 2: Switch ADB to root mode."
echo "Run the following command:"
echo "adb root"
read -p "Press Enter after you've manually run the above command."

# Step 3: Set ADB TCP and Proxy
echo "Step 3: Set ADB TCP forwarding and configure proxy."
echo "First, run:"
echo "adb tcpip 5555"
read -p "Press Enter after you've run the above command."
echo "Next, connect ADB to the emulator. Run this command:"
echo "adb connect <your_ip>:5555"
read -p "Press Enter after you've run the above command, replacing <your_ip> with the host IP."

# Step 4: Set Proxy
echo "Step 4: Configure proxy settings on the emulator."
echo "Run the following command (replace <your_ip> with your IP):"
echo "adb shell settings put global http_proxy <your_ip>:8080"
read -p "Press Enter after you've run the above command."

# Step 5: Push Burp Certificate
echo "Step 5: Push Burp CA certificate to the emulator."
echo "Run the following command:"
echo "adb push /home/flintx/main-env/burp-ca-cert.crt /sdcard/burp-ca-cert.crt"
read -p "Press Enter after you've run the above command."

# Step 6: Move Certificate to Trust Store
echo "Step 6: Move the certificate to the system trust store."
echo "Run the following commands one by one:"
echo "adb shell mv /sdcard/burp-ca-cert.crt /system/etc/security/cacerts/"
echo "adb shell chmod 644 /system/etc/security/cacerts/burp-ca-cert.crt"
read -p "Press Enter after you've run both commands."

# Step 7: Restart Emulator
echo "Step 7: Reboot the emulator."
echo "Run the following command:"
echo "adb reboot"
read -p "Press Enter after you've manually rebooted the emulator."

# Step 8: Start Frida
echo "Step 8: Start the Frida server on the emulator."
echo "Run the following command:"
echo "adb shell /data/local/tmp/frida-server-16.5.1-android-x86_64 &"
read -p "Press Enter after you've run the above command."

# Step 9: Verify Frida
echo "Step 9: Verify if Frida is running. Run the following command:"
echo "frida-ps -U"
read -p "Press Enter after you've verified if Frida is running."

# Step 10: MobSF or mitmproxy
if [ "$program" == "MobSF" ]; then
    echo "Step 10: Starting MobSF. Run the following command:"
    echo "source /root/Mobile-Security-Framework-MobSF/mobsf-env/bin/activate"
    echo "cd /root/Mobile-Security-Framework-MobSF/"
    echo "./run.sh"
elif [ "$program" == "mitmproxy" ]; then
    echo "Step 10: Starting mitmproxy. Run the following command:"
    echo "mitmproxy"
fi

echo "All steps are complete."
