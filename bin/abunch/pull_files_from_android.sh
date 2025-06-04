#!/bin/bash

# Android source directory (from where files will be pulled)
ANDROID_DIR="/storage/emulated/0/bcks"

# Local destination directory (where files will be copied)
LOCAL_DIR="/media/flintx/7eb08ac4-d6a0-d01d-500f-4f15b41813c2/samsungbackup/bcks"

# Temporary directory to hold pulled files
TEMP_DIR="/tmp/android_bcks"

# Create the temporary folder if it doesn't exist
mkdir -p "$TEMP_DIR"

# Pull files from Android device to the temporary folder
echo "Pulling files from Android to temporary folder..."
adb pull "$ANDROID_DIR" "$TEMP_DIR"

# Sync files from the temporary folder to the local folder without overwriting existing files
echo "Syncing files to the destination folder..."
rsync -avz --ignore-existing "$TEMP_DIR/" "$LOCAL_DIR/"

# Clean up the temporary folder
rm -rf "$TEMP_DIR"

echo "File sync complete. New files have been copied to: $LOCAL_DIR"
