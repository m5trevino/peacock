#!/bin/bash

# Prompt for APK file path
read -p "Enter the path to the APK file to patch: " apk_path

# Patch the APK
objection patchapk -s "$apk_path"

# Verify success
if [ $? -ne 0 ]; then
    echo "[ERROR] Failed to patch APK at $apk_path."
else
    echo "[SUCCESS] APK patched successfully: $apk_path.objection.apk"
fi