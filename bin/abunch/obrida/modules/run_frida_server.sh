#!/bin/bash

# Start Frida server
adb shell /data/local/tmp/frida-server &

# Confirm Frida server is running
adb shell pgrep -f "frida-server"