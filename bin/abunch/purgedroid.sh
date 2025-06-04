#!/bin/bash

# Step 1: Remove installed Android packages via apt
echo "Removing Android related packages..."
sudo apt-get remove --purge -y google-android-build-tools-34.0.0-installer \
    google-android-cmdline-tools-9.0-installer \
    google-android-emulator-installer \
    google-android-platform-tools-installer \
    google-android-licenses

# Step 2: Clean up remaining dependencies and files
echo "Removing unused dependencies..."
sudo apt-get autoremove -y
sudo apt-get clean

# Step 3: Remove any leftover files from system directories
echo "Cleaning up leftover system files..."
sudo rm -rf /usr/share/google-android*
sudo rm -rf /opt/google/android*
sudo rm -rf /usr/local/google/android*
sudo rm -rf /home/$USER/Android
sudo rm -rf /home/$USER/android-studio

# Step 4: Optionally remove any leftover files from Android SDK manager
echo "Removing any leftover SDK Manager configurations..."
rm -rf ~/.android
rm -rf ~/.gradle

# Step 5: Verify the removal
echo "Verifying removal of Android packages..."
dpkg -l | grep android

echo "Android software removal complete."
