#!/bin/bash
echo "Patching APK with Objection..."
read -p "Enter the APK path: " apk_path
objection patchapk -s "$apk_path"

