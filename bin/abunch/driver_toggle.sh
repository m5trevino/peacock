#!/bin/bash

# START ### CONFIGURATION ###
# Define the key files we need to manage
# Note: We operate on the symlink names in /etc/modprobe.d/ usually
NVIDIA_INSTALL_CONF="/etc/modprobe.d/nvidia.conf"
NOUVEAU_BLACKLIST_CONF="/etc/modprobe.d/blacklist-nvidia-nouveau.conf"
NVIDIA_MANUAL_BLACKLIST="/etc/modprobe.d/blacklist-nvidia-MANUAL.conf" # The one we added
# Add other specific Nvidia blacklist files here if needed:
# OTHER_NVIDIA_BLACKLIST="/etc/modprobe.d/some-other-nvidia-blacklist.conf"
# FINISH ### CONFIGURATION ###

# START ### HELPER FUNCTIONS ###
# Function to rename .conf to .conf.disabled or vice-versa
# Arg 1: Full path to the file (either .conf or .conf.disabled)
# Arg 2: "enable" or "disable"
rename_conf() {
    local filepath="$1"
    local action="$2"
    local conf_path=""
    local disabled_path=""

    if [[ "$filepath" == *.disabled ]]; then
        conf_path="${filepath%.disabled}"
        disabled_path="$filepath"
    else
        conf_path="$filepath"
        disabled_path="${filepath}.disabled"
    fi

    if [[ "$action" == "enable" ]]; then
        # Want .conf to exist, .conf.disabled to NOT exist
        if [[ -f "$disabled_path" ]]; then
            echo "  Enabling $conf_path..."
            mv -v "$disabled_path" "$conf_path" || echo "  ERROR: Failed to enable $conf_path" >&2
        elif [[ -f "$conf_path" ]]; then
            echo "  $conf_path is already enabled."
        else
             echo "  WARN: Cannot enable $conf_path, neither file found." >&2
        fi
    elif [[ "$action" == "disable" ]]; then
        # Want .conf.disabled to exist, .conf to NOT exist
        if [[ -f "$conf_path" ]]; then
            echo "  Disabling $conf_path..."
            mv -v "$conf_path" "$disabled_path" || echo "  ERROR: Failed to disable $conf_path" >&2
        elif [[ -f "$disabled_path" ]]; then
            echo "  $conf_path is already disabled."
        else
            echo "  WARN: Cannot disable $conf_path, neither file found." >&2
        fi
    else
        echo "  ERROR: Invalid action '$action' for rename_conf." >&2
    fi
}
# FINISH ### HELPER FUNCTIONS ###

# START ### ROOT CHECK ###
if [[ "$EUID" -ne 0 ]]; then
  echo "Error: This script must be run as root (sudo ./driver_toggle.sh)"
  exit 1
fi
# FINISH ### ROOT CHECK ###

# START ### MAIN MENU ###
echo "-------------------------------------"
echo " Select Driver to Enable:"
echo "-------------------------------------"
echo " 1) NVIDIA (Proprietary)"
echo " 2) Nouveau (Open Source)"
echo " 3) Exit"
echo "-------------------------------------"
read -p "Enter choice [1-3]: " choice
# FINISH ### MAIN MENU ###

# START ### SCRIPT LOGIC ###
case "$choice" in
  1)
    echo ">>> Enabling NVIDIA driver..."
    # Enable Nvidia install hooks
    rename_conf "$NVIDIA_INSTALL_CONF" "enable"
    # Disable Nouveau blacklist
    rename_conf "$NOUVEAU_BLACKLIST_CONF" "disable"
    # Disable manual Nvidia blacklist (we want Nvidia *enabled*)
    rename_conf "$NVIDIA_MANUAL_BLACKLIST" "disable"
    # Add lines here to disable OTHER_NVIDIA_BLACKLIST if defined

    echo ">>> Running update-initramfs..."
    update-initramfs -u -k all
    echo "-------------------------------------"
    echo "NVIDIA configuration potentially enabled."
    echo "IMPORTANT: REMEMBER TO CHECK/SET GRUB KERNEL PARAMETERS!"
    echo "           You likely need 'nvidia-drm.modeset=1' and NO 'nomodeset'."
    echo "           Run 'sudo update-grub' after checking/editing /etc/default/grub."
    echo "           Reboot required to apply changes."
    echo "-------------------------------------"
    ;;
  2)
    echo ">>> Enabling Nouveau driver..."
    # Disable Nvidia install hooks
    rename_conf "$NVIDIA_INSTALL_CONF" "disable"
    # Enable Nouveau blacklist (if it exists as .disabled) OR ensure it's not active if we want Nouveau
    # ACTUALLY: To enable Nouveau, we need its blacklist DISABLED.
    rename_conf "$NOUVEAU_BLACKLIST_CONF" "disable"
    # Enable manual Nvidia blacklist (we want Nvidia *disabled*)
    rename_conf "$NVIDIA_MANUAL_BLACKLIST" "enable"
    # Add lines here to enable OTHER_NVIDIA_BLACKLIST if defined

    echo ">>> Running update-initramfs..."
    update-initramfs -u -k all
    echo "-------------------------------------"
    echo "Nouveau configuration potentially enabled."
    echo "IMPORTANT: REMEMBER TO CHECK/SET GRUB KERNEL PARAMETERS!"
    echo "           Ensure NO 'nomodeset' and NO 'nvidia-drm.modeset=1'."
    echo "           Run 'sudo update-grub' after checking/editing /etc/default/grub."
    echo "           Reboot required to apply changes."
    echo "-------------------------------------"
    ;;
  3)
    echo "Exiting."
    ;;
  *)
    echo "Invalid choice. Exiting."
    exit 1
    ;;
esac
# FINISH ### SCRIPT LOGIC ###

exit 0
