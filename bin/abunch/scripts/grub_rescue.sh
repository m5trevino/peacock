#!/usr/bin/env bash

# START ### CONFIGURATION & HELPERS ###
# --- Script to automate GRUB/Initramfs repair from a Live OS ---

# Function to print colored messages
print_color() {
    local color_code="$1"
    local message="$2"
    local reset_code="\e[0m"
    echo -e "${color_code}${message}${reset_code}"
}

# Colors
INFO_COLOR="\e[36m"    # Cyan
CMD_COLOR="\e[33m"     # Yellow
DESC_COLOR="\e[32m"    # Green
PROMPT_COLOR="\e[35m"   # Magenta
ERROR_COLOR="\e[31m"    # Red
SUCCESS_COLOR="\e[32m"  # Green
WARN_COLOR="\e[31m"     # Red (using Red for warnings too for visibility)

# Function for error handling
handle_error() {
    local error_message="$1"
    local exit_code="${2:-1}" # Default exit code 1
    print_color "$ERROR_COLOR" "ERROR: $error_message"
    print_color "$ERROR_COLOR" "Aborting script."
    # Attempt cleanup before exiting
    print_color "$INFO_COLOR" "Attempting to unmount partitions..."
    unmount_system &> /dev/null # Suppress errors during cleanup attempt
    exit "$exit_code"
}

# Mount point
MOUNT_POINT="/mnt/system"

# Bind mount paths
BIND_MOUNTS=( "/dev" "/dev/pts" "/proc" "/sys" )

# --- Core Functions ---

get_partitions() {
    print_color "$INFO_COLOR" "We need to know where your installed system lives."
    print_color "$INFO_COLOR" "Use 'lsblk -f' or 'sudo fdisk -l' in another terminal to find them."
    
    while true; do
        read -p "$(print_color "$PROMPT_COLOR" "Enter the ROOT partition device (e.g., /dev/nvme0n1p3, /dev/sda2): ")" ROOT_PART
        if [[ -b "$ROOT_PART" ]]; then
            break
        else
            print_color "$ERROR_COLOR" "Device '$ROOT_PART' not found or not a block device. Check the path."
        fi
    done

    while true; do
        read -p "$(print_color "$PROMPT_COLOR" "Enter the EFI System Partition (ESP) device (e.g., /dev/nvme0n1p1, /dev/sda1): ")" EFI_PART
        if [[ -b "$EFI_PART" ]]; then
            break
        else
             print_color "$ERROR_COLOR" "Device '$EFI_PART' not found or not a block device. Check the path."
        fi
    done
     print_color "$INFO_COLOR" "Target Root: $ROOT_PART"
     print_color "$INFO_COLOR" "Target EFI:  $EFI_PART"
     echo ""
}

mount_system() {
    print_color "$INFO_COLOR" "Creating mount points..."
    sudo mkdir -p "$MOUNT_POINT/boot/efi" || handle_error "Failed to create mount points."

    print_color "$INFO_COLOR" "Mounting Root partition ($ROOT_PART) to $MOUNT_POINT..."
    sudo mount "$ROOT_PART" "$MOUNT_POINT" || handle_error "Failed to mount root partition $ROOT_PART."

    print_color "$INFO_COLOR" "Mounting EFI partition ($EFI_PART) to $MOUNT_POINT/boot/efi..."
    sudo mount "$EFI_PART" "$MOUNT_POINT/boot/efi" || handle_error "Failed to mount EFI partition $EFI_PART."

    print_color "$INFO_COLOR" "Setting up bind mounts..."
    for path in "${BIND_MOUNTS[@]}"; do
        sudo mount --bind "$path" "$MOUNT_POINT$path" || handle_error "Failed to bind mount $path."
        print_color "$DESC_COLOR" "  - $path mounted."
    done

    print_color "$INFO_COLOR" "Copying DNS info..."
    sudo cp /etc/resolv.conf "$MOUNT_POINT/etc/resolv.conf" || print_color "$WARN_COLOR" "Warning: Failed to copy resolv.conf. Network might not work in chroot."
}

run_chroot_commands() {
    print_color "$INFO_COLOR" "Entering chroot environment to run repair commands..."
    
    # Commands to run inside chroot - use heredoc
    sudo chroot "$MOUNT_POINT" /bin/bash << CHROOT_EOF
set -e # Exit immediately if any command fails inside chroot

echo "--- Inside chroot ---"

# Verify EFI mount inside chroot
echo "Verifying EFI mount..."
mount | grep /boot/efi || (echo "ERROR: EFI partition not mounted inside chroot!" && exit 1)
echo "EFI mount confirmed."

# Rebuild initramfs
echo "Rebuilding initramfs for all kernels..."
update-initramfs -u -k all
echo "Initramfs rebuild complete."

# Update GRUB config
echo "Updating GRUB configuration..."
update-grub
echo "GRUB configuration update complete."

# Reinstall GRUB bootloader
echo "Reinstalling GRUB to EFI partition..."
# Using 'ubuntu' as default bootloader ID, common for Ubuntu/Mint. Might need adjustment for other distros.
grub-install --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id=ubuntu --recheck
echo "GRUB reinstallation complete."

echo "--- Exiting chroot ---"
exit 0 # Explicitly exit with success
CHROOT_EOF

    # Check the exit status of the chroot command itself
    local chroot_status=$?
    if [[ $chroot_status -ne 0 ]]; then
        handle_error "Chroot command execution failed with status $chroot_status."
    else
        print_color "$SUCCESS_COLOR" "Chroot commands completed successfully."
    fi
}

unmount_system() {
    print_color "$INFO_COLOR" "Unmounting filesystems..."
    local failed_unmounts=0

    # Unmount bind mounts first, reverse order implicitly handled by individual umounts
    for path in "${BIND_MOUNTS[@]}"; do
        if mountpoint -q "$MOUNT_POINT$path"; then
            sudo umount "$MOUNT_POINT$path"
            if [[ $? -ne 0 ]]; then
                print_color "$ERROR_COLOR" "  - Failed to unmount $MOUNT_POINT$path. Target might be busy."
                failed_unmounts=$((failed_unmounts + 1))
            else
                 print_color "$DESC_COLOR" "  - $MOUNT_POINT$path unmounted."
            fi
         else
              print_color "$INFO_COLOR" "  - $MOUNT_POINT$path already unmounted."
         fi
    done

    # Unmount EFI
    if mountpoint -q "$MOUNT_POINT/boot/efi"; then
        sudo umount "$MOUNT_POINT/boot/efi"
        if [[ $? -ne 0 ]]; then
            print_color "$ERROR_COLOR" "  - Failed to unmount EFI partition. Target might be busy."
             failed_unmounts=$((failed_unmounts + 1))
        else
             print_color "$DESC_COLOR" "  - EFI partition unmounted."
        fi
    else
         print_color "$INFO_COLOR" "  - EFI partition already unmounted."
    fi


    # Unmount root
     if mountpoint -q "$MOUNT_POINT"; then
        sudo umount "$MOUNT_POINT"
         if [[ $? -ne 0 ]]; then
            print_color "$ERROR_COLOR" "  - Failed to unmount Root partition. Target might be busy."
             failed_unmounts=$((failed_unmounts + 1))
        else
             print_color "$DESC_COLOR" "  - Root partition unmounted."
        fi
    else
         print_color "$INFO_COLOR" "  - Root partition already unmounted."
    fi

    if [[ $failed_unmounts -gt 0 ]]; then
        print_color "$WARN_COLOR" "Some partitions failed to unmount automatically. You might need to close file managers or terminals accessing '$MOUNT_POINT' and run 'sudo umount -R $MOUNT_POINT' manually."
        return 1
    else
        print_color "$SUCCESS_COLOR" "All target filesystems unmounted cleanly."
        # Optional: Remove mount point directory if desired
        # sudo rmdir "$MOUNT_POINT/boot/efi" "$MOUNT_POINT/boot" "$MOUNT_POINT"
        return 0
    fi
}
# FINISH ### CONFIGURATION & HELPERS ###


# START ### SCRIPT EXECUTION ###
print_color "$INFO_COLOR" "--- GRUB & Initramfs Rescue Script ---"
print_color "$WARN_COLOR" "WARNING: This script modifies boot components. Run ONLY from a Live OS."
print_color "$WARN_COLOR" "Ensure you know your ROOT ('/') and EFI partition device names."
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   print_color "$ERROR_COLOR" "This script needs root privileges for mount/chroot. Run with 'sudo'."
   exit 1
fi

# Get partition info
get_partitions

# Confirmation
print_color "$PROMPT_COLOR" "Ready to proceed with mounting and repairs on:"
print_color "$CMD_COLOR" "  Root: $ROOT_PART"
print_color "$CMD_COLOR" "  EFI:  $EFI_PART"
read -p "$(print_color "$PROMPT_COLOR" "Continue? (y/N): ")" confirm
if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    print_color "$ERROR_COLOR" "Operation cancelled by user."
    exit 0
fi

# --- Execute Steps ---
mount_system
run_chroot_commands
unmount_system

if [[ $? -eq 0 ]]; then
    print_color "$SUCCESS_COLOR" "--- Rescue operations completed successfully! ---"
    print_color "$INFO_COLOR" "You can now try rebooting your system."
    print_color "$INFO_COLOR" "Run 'sudo reboot' when ready."
else
     print_color "$ERROR_COLOR" "--- Rescue operations finished with errors (failed unmounts). ---"
     print_color "$WARN_COLOR" "Please check messages above and unmount manually if needed before rebooting."
fi

exit 0
# FINISH ### SCRIPT EXECUTION ###

