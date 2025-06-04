#!/bin/bash

# START ### CONFIGURATION ###
# Path to the downloaded Android Studio archive
ARCHIVE_PATH="/home/flintx/Downloads/android-studio-2024.3.1.15-linux.tar.gz"
# Where we gon' stash the goods - /opt is standard procedure
INSTALL_DIR="/opt/android-studio"
# The name of the extracted folder inside the tarball (usually 'android-studio')
# Check inside your tar.gz if this script fails, might change between versions
EXTRACTED_FOLDER_NAME="android-studio"
# User's bash config file for PATH setup
BASH_CONFIG_FILE="$HOME/.bashrc"
# FINISH ### CONFIGURATION ###

# START ### SANITY CHECKS ###
echo "[*] Whats good? Let's get this Android Studio hustle goin'..."

# Check if the archive file is really there, no funny business
if [ ! -f "$ARCHIVE_PATH" ]; then
  echo "[!] Yo, hold up! Archive not found at $ARCHIVE_PATH"
  echo "[!] Make sure that path is 100, my boy. Fix it in the script if needed."
  exit 1
fi

# Check if we got root access, needed for /opt
if [ "$(id -u)" -ne 0 ]; then
  echo "[!] Heads up, G. We need root privileges (sudo) to install into $INSTALL_DIR."
  echo "[!] Run this script again using 'sudo bash install_android_studio.sh'"
  exit 1
fi
# FINISH ### SANITY CHECKS ###

# START ### INSTALLATION ###
echo "[*] Archive found. Let's crack this shit open..."

# Temporary spot for extraction
TEMP_EXTRACT_DIR="/tmp/android-studio-extract-$$" # $$ adds process ID for uniqueness
mkdir -p "$TEMP_EXTRACT_DIR"

# Extract the tarball
echo "[*] Extracting $ARCHIVE_PATH to $TEMP_EXTRACT_DIR..."
tar -xzf "$ARCHIVE_PATH" -C "$TEMP_EXTRACT_DIR"
EXTRACT_STATUS=$?

if [ $EXTRACT_STATUS -ne 0 ]; then
  echo "[!] Fuck! Extraction failed. Maybe the archive is corrupted or disk space low?"
  rm -rf "$TEMP_EXTRACT_DIR" # Clean up the mess
  exit 1
fi

# Check if the expected folder name exists after extraction
if [ ! -d "$TEMP_EXTRACT_DIR/$EXTRACTED_FOLDER_NAME" ]; then
    echo "[!] Hold up! After extraction, couldn't find the folder '$EXTRACTED_FOLDER_NAME' inside $TEMP_EXTRACT_DIR."
    echo "[!] Check the archive content, maybe the folder name inside is different? Update EXTRACTED_FOLDER_NAME variable."
    rm -rf "$TEMP_EXTRACT_DIR" # Clean up the mess
    exit 1
fi


echo "[*] Extraction smooth. Now movin' the operation to $INSTALL_DIR..."

# Remove any old installation first, keepin' it clean
if [ -d "$INSTALL_DIR" ]; then
  echo "[*] Found an old install at $INSTALL_DIR. Movin' it out the way..."
  rm -rf "$INSTALL_DIR"
fi

# Move the extracted folder to the final destination
mv "$TEMP_EXTRACT_DIR/$EXTRACTED_FOLDER_NAME" "$INSTALL_DIR"
MV_STATUS=$?

# Clean up temporary directory regardless of move status
rm -rf "$TEMP_EXTRACT_DIR"

if [ $MV_STATUS -ne 0 ]; then
  echo "[!] Shit! Failed to move the folder to $INSTALL_DIR. Check permissions or if something went wrong."
  exit 1
fi

echo "[*] Copacetic. Android Studio files are now sittin' pretty in $INSTALL_DIR."
# FINISH ### INSTALLATION ###

# START ### PATH SETUP ###
# Add the bin directory to the user's PATH in .bashrc if it ain't already there
STUDIO_BIN_PATH="$INSTALL_DIR/bin"
PATH_EXPORT_LINE="export PATH=\$PATH:$STUDIO_BIN_PATH"

echo "[*] Setting up the PATH in $BASH_CONFIG_FILE so you can run 'studio.sh' from anywhere..."

# Check if the line already exists to avoid duplicate entries
if grep -q "export PATH=.*$STUDIO_BIN_PATH" "$BASH_CONFIG_FILE"; then
  echo "[*] Looks like the PATH is already set up in $BASH_CONFIG_FILE. We good."
else
  echo "[*] Adding PATH to $BASH_CONFIG_FILE..."
  # Append the export line to the .bashrc file
  echo "" >> "$BASH_CONFIG_FILE" # Add a newline for separation
  echo "# Android Studio PATH setup" >> "$BASH_CONFIG_FILE"
  echo "$PATH_EXPORT_LINE" >> "$BASH_CONFIG_FILE"
  echo "[*] PATH added. You'll need to reload your shell or run 'source $BASH_CONFIG_FILE'."
fi
# FINISH ### PATH SETUP ###

# START ### POST-INSTALL INSTRUCTIONS ###
echo ""
echo "[*]==============================================================[*]"
echo "[*]                 ANDROID STUDIO INSTALL DONE                  [*]"
echo "[*]==============================================================[*]"
echo ""
echo "[>] What's next, big dawg?"
echo "    1. Reload your shell config: Run 'source $BASH_CONFIG_FILE' or just open a new terminal window."
echo "    2. Launch Android Studio: Just type 'studio.sh' in your terminal."
echo "    3. First Launch Setup: Studio will guide you through downloading the SDKs and other components. Make sure you got internet."
echo "    4. Emulator Performance (IMPORTANT!): For the emulator to not run like bootise, make sure KVM acceleration is set up."
echo "       Check KVM status: 'sudo kvm-ok'"
echo "       If it ain't enabled, you might need to enable virtualization (VT-x/AMD-V) in your BIOS/UEFI and install KVM packages:"
echo "       'sudo apt update && sudo apt install qemu-kvm libvirt-daemon-system libvirt-clients bridge-utils'"
echo "       Then add your user to the kvm and libvirt groups:"
echo "       'sudo adduser $(whoami) libvirt'"
echo "       'sudo adduser $(whoami) kvm'"
echo "       You'll need to LOG OUT and LOG BACK IN for group changes to take effect."
echo ""
echo "[*] Alright, you set. Go make some moves!"
# FINISH ### POST-INSTALL INSTRUCTIONS ###

exit 0
