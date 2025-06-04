#!/usr/bin/env bash

# GPU & System Rescue Manager
# Built for the streets, respects the hustle.

# --- Configuration ---
SCRIPT_VERSION="1.0"
LOG_DIR="$HOME/gpu_manager_logs"
MAIN_LOG_FILE="$LOG_DIR/gpu_manager_main_$(date +%Y%m%d_%H%M%S).log"

# --- Color Palette (Cyberpunk Neon) ---
GREEN='\e[92m'    # Bright Green (Success, Info)
PURPLE='\e[95m'   # Bright Purple (Section Headers, Highlights)
CYAN='\e[96m'     # Bright Cyan (Commands, Explanations)
YELLOW='\e[93m'   # Bright Yellow (Prompts, Warnings)
RED='\e[91m'      # Bright Red (ERRORS, Critical Warnings - Use Sparingly!)
NC='\e[0m'       # No Color (Reset)

# --- Helper Functions ---
print_color() {
    echo -e "${1}${2}${NC}"
}

log_msg() {
    local level="$1"
    local message="$2"
    local log_line
    log_line="$(date +'%Y-%m-%d %H:%M:%S') [$level] - $message"
    echo "$log_line" >> "$MAIN_LOG_FILE"
    # Optionally echo to screen based on level if needed later
}

prompt_confirm() {
    local message="$1"
    local default_choice="${2:-N}" # Default to No
    local prompt_suffix="[y/N]"
    [[ "$default_choice" =~ ^[Yy]$ ]] && prompt_suffix="[Y/n]"

    while true; do
        read -p "$(print_color "$YELLOW" "$message $prompt_suffix: ")" choice
        choice="${choice:-$default_choice}" # Use default if user presses Enter
        case "$choice" in
            [Yy]* ) log_msg "USER" "Confirmed: '$message'"; return 0;;
            [Nn]* ) log_msg "USER" "Cancelled: '$message'"; return 1;;
            * ) print_color "$RED" "Invalid input. Please enter 'y' or 'n'.";;
        esac
    done
}

# Function to simulate human typing
type_effect() {
    local text="$1"
    local delay="${2:-0.03}" # Default delay between characters
    local current_char
    for (( i=0; i<${#text}; i++ )); do
        current_char="${text:$i:1}"
        echo -n "$current_char"
        # Add slight random variation to delay if desired
        sleep "$(awk -v min=0.01 -v max="$delay" 'BEGIN{srand(); print min+rand()*(max-min)}')"
    done
    echo # Newline at the end
}

# Check sudo upfront
check_sudo() {
    if [[ $EUID -ne 0 ]]; then
        print_color "$RED" "Error: This script requires root privileges for most operations."
        print_color "$YELLOW" "Please run using 'sudo ./gpu_manager.sh'"
        log_msg "ERROR" "Script not run as root. Aborting."
        exit 1
    fi
    log_msg "INFO" "Sudo check passed."
}

# Check TTY for critical sections
check_tty() {
    if ! tty -s || [[ -n "$DISPLAY" ]]; then
        print_color "$YELLOW" "Warning: This operation is best performed from a text TTY (Ctrl+Alt+F3-F6)."
        log_msg "WARN" "Operation started outside TTY."
        if ! prompt_confirm "Continue anyway?"; then
            log_msg "USER" "User aborted due to not being in TTY."
            return 1
        fi
    fi
    return 0
}

get_display_manager() {
  if systemctl status gdm3.service &> /dev/null; then echo "gdm3.service"; return 0; fi
  if systemctl status gdm.service &> /dev/null; then echo "gdm.service"; return 0; fi # Some systems link gdm
  if systemctl status sddm.service &> /dev/null; then echo "sddm.service"; return 0; fi
  if systemctl status lightdm.service &> /dev/null; then echo "lightdm.service"; return 0; fi
  log_msg "WARN" "Could not automatically detect display manager (gdm3/sddm/lightdm)."
  echo "" # Return empty string on failure
  return 1
}

# --- Module: NVIDIA Cleanup ---
run_nvidia_cleanup() {
    print_color "$PURPLE" "\n--- Module: NVIDIA Deep Clean ---"
    log_msg "INFO" "Starting NVIDIA Deep Clean module."

    if ! prompt_confirm "This will attempt to COMPLETELY remove Nvidia drivers/CUDA via DKMS and APT. Continue?"; then
        return 1
    fi

    if ! check_tty; then return 1; fi

    local dm_service
    dm_service=$(get_display_manager)
    if [[ -n "$dm_service" ]]; then
        print_color "$CYAN" "Attempting to stop display manager ($dm_service)..."
        log_msg "EXEC" "systemctl stop $dm_service"
        systemctl stop "$dm_service" || print_color "$YELLOW" "Warning: Failed to stop $dm_service. It might already be stopped."
    else
        print_color "$YELLOW" "Could not detect display manager. Skipping stop command. Ensure graphical server is not running!"
        sleep 3
    fi

    print_color "$CYAN" "Step 1: Removing existing DKMS modules..."
    log_msg "INFO" "Attempting DKMS module removal."
    local dkms_modules
    dkms_modules=$(dkms status | grep -E 'nvidia|nvidia-fs' | awk -F',|/' '{print $1"/"$2}' | uniq)

    if [[ -n "$dkms_modules" ]]; then
        for module in $dkms_modules; do
            print_color "$YELLOW" "  Removing DKMS module: $module"
            log_msg "EXEC" "dkms remove $module --all"
            dkms remove "$module" --all || print_color "$YELLOW" "  Warning: dkms remove for $module might have failed or module was partially removed."
        done
        print_color "$CYAN" "  Verifying DKMS status..."
        if dkms status | grep -qE 'nvidia|nvidia-fs'; then
            print_color "$RED" "  ERROR: DKMS still shows Nvidia modules after removal attempt! Manual check needed."
            log_msg "ERROR" "DKMS modules still present after removal attempt."
            return 1
        else
            print_color "$GREEN" "  DKMS clean."
            log_msg "INFO" "DKMS modules removed successfully."
        fi
    else
        print_color "$GREEN" "  No Nvidia DKMS modules found."
        log_msg "INFO" "No Nvidia DKMS modules found to remove."
    fi

    print_color "$CYAN" "Step 2: Finding installed Nvidia/CUDA packages via dpkg..."
    log_msg "INFO" "Finding Nvidia/CUDA packages via dpkg."
    local packages_to_purge
    packages_to_purge=$(dpkg -l | grep -E 'nvidia|cuda|libnvidia|cublas|cufft|cufile|curand|cusolver|cusparse|npp|nvjpeg' | grep -E '^ii' | awk '{print $2}' | tr '\n' ' ')

    if [[ -z "$packages_to_purge" ]]; then
        print_color "$GREEN" "  No relevant installed packages found via dpkg."
        log_msg "INFO" "No installed Nvidia/CUDA packages found via dpkg."
    else
        print_color "$YELLOW" "  Found packages scheduled for purge:"
        echo "$packages_to_purge" | fold -s -w 80 | sed 's/^/    /' # Indent list
        log_msg "INFO" "Packages found for purge: $packages_to_purge"
        if ! prompt_confirm "Proceed with purging these packages?"; then
            log_msg "USER" "User cancelled package purge."
            return 1
        fi
        print_color "$CYAN" "  Purging packages using apt-get..."
        log_msg "EXEC" "apt-get purge --autoremove -y $packages_to_purge"
        apt-get purge --autoremove -y $packages_to_purge
        local purge_status=$?
        if [[ $purge_status -ne 0 ]]; then
             print_color "$RED" "  ERROR: apt purge failed with status $purge_status!"
             log_msg "ERROR" "apt purge failed with status $purge_status."
             print_color "$YELLOW" "  Attempting package fix commands..."
             dpkg --configure -a
             apt-get update --fix-missing
             apt-get install -f
             return 1
        else
            print_color "$GREEN" "  APT purge completed."
            log_msg "INFO" "APT purge completed successfully."
        fi
    fi

    print_color "$CYAN" "Step 3: Cleaning common config files..."
    log_msg "INFO" "Removing common config files."
    log_msg "EXEC" "rm -f /etc/modprobe.d/blacklist-nvidia*.conf /etc/modprobe.d/nvidia*.conf /etc/X11/xorg.conf"
    rm -f /etc/modprobe.d/blacklist-nvidia*.conf /etc/modprobe.d/nvidia*.conf /etc/X11/xorg.conf
    print_color "$GREEN" "  Config files removed (if they existed)."

    print_color "$CYAN" "Step 4: Cleaning APT caches..."
    log_msg "INFO" "Cleaning APT caches."
    log_msg "EXEC" "rm -rf /var/lib/apt/lists/* && apt clean"
    rm -rf /var/lib/apt/lists/* && apt clean
    print_color "$GREEN" "  APT caches cleaned."

    print_color "$CYAN" "Step 5: Rebuilding initramfs..."
    log_msg "INFO" "Updating initramfs."
    log_msg "EXEC" "update-initramfs -u -k all"
    if update-initramfs -u -k all; then
         print_color "$GREEN" "  Initramfs updated."
         log_msg "INFO" "Initramfs updated successfully."
    else
        print_color "$RED" "  ERROR: update-initramfs failed!"
        log_msg "ERROR" "update-initramfs failed."
        return 1
    fi

    print_color "$GREEN" "\n--- NVIDIA Deep Clean Complete ---"
    print_color "$YELLOW" "A reboot is recommended."
    log_msg "INFO" "NVIDIA Deep Clean module finished."
    return 0
}

# --- Module: NVIDIA Install ---
run_nvidia_install() {
    print_color "$PURPLE" "\n--- Module: NVIDIA Driver Install ---"
    log_msg "INFO" "Starting NVIDIA Driver Install module."

    local driver_version=""
    local install_method=""

    # Select Driver Version
    while true; do
         print_color "$YELLOW" "Select driver version to install:"
         echo "  1) 535 (Stable Production Branch)"
         echo "  2) 550 (Newer Production Branch - Check compatibility)" # Updated example
         # Add 570 if desired, but maybe discourage?
         # echo "  3) 570 (Feature Branch - May be less stable)"
         read -p "$(print_color "$YELLOW" "Enter choice (e.g., 1): ")" v_choice
         case "$v_choice" in
            1) driver_version="535"; break;;
            2) driver_version="550"; break;; # Updated example
            # 3) driver_version="570"; break;;
            *) print_color "$RED" "Invalid choice.";;
         esac
    done
    log_msg "USER" "Selected driver version: $driver_version"

    # Select Install Method
    while true; do
         print_color "$YELLOW" "Select installation method:"
         echo "  1) APT (Recommended - Uses system package manager)"
         echo "  2) Runfile (Official Nvidia installer - Bypasses APT for install step)"
         read -p "$(print_color "$YELLOW" "Enter choice (1 or 2): ")" m_choice
         case "$m_choice" in
             1) install_method="apt"; break;;
             2) install_method="runfile"; break;;
             *) print_color "$RED" "Invalid choice.";;
         esac
    done
     log_msg "USER" "Selected install method: $install_method"

    # --- Execute Install ---
    if [[ "$install_method" == "apt" ]]; then
        install_nvidia_apt "$driver_version"
    elif [[ "$install_method" == "runfile" ]]; then
        install_nvidia_runfile "$driver_version"
    else
        print_color "$RED" "Internal error: Invalid install method."
        log_msg "ERROR" "Invalid install_method variable: $install_method"
        return 1
    fi

    local install_status=$?
    if [[ $install_status -eq 0 ]]; then
        print_color "$GREEN" "\n--- NVIDIA Driver Install Module Complete ---"
        print_color "$YELLOW" "Reboot required to load the new driver."
        log_msg "INFO" "NVIDIA Driver Install module finished successfully."
    else
        print_color "$RED" "\n--- NVIDIA Driver Install Module Failed ---"
        log_msg "ERROR" "NVIDIA Driver Install module failed."
    fi
    return $install_status
}

install_nvidia_apt() {
    local version="$1"
    local package_name="nvidia-driver-${version}"

    print_color "$CYAN" "\nStarting APT installation for driver $version..."
    log_msg "INFO" "Starting APT install for $package_name."

    if ! check_tty; then return 1; fi

    local dm_service
    dm_service=$(get_display_manager)
     if [[ -n "$dm_service" ]]; then
        print_color "$CYAN" "Attempting to stop display manager ($dm_service)..."
        log_msg "EXEC" "systemctl stop $dm_service"
        systemctl stop "$dm_service" || print_color "$YELLOW" "Warning: Failed to stop $dm_service."
    else
        print_color "$YELLOW" "Could not detect display manager. Skipping stop command. Ensure graphical server is not running!"
        sleep 3
    fi

    print_color "$CYAN" "Running apt update..."
    log_msg "EXEC" "apt update"
    if ! apt update; then
        print_color "$RED" "ERROR: apt update failed. Check network and repositories."
        log_msg "ERROR" "apt update failed."
        return 1
    fi

    print_color "$CYAN" "Attempting to install $package_name..."
    log_msg "EXEC" "apt install $package_name -y"
    if apt install "$package_name" -y; then
        print_color "$GREEN" "APT installation command finished."
        log_msg "INFO" "APT installation command finished successfully."
        # Verify DKMS status maybe?
        print_color "$CYAN" "Checking DKMS status..."
        log_msg "INFO" "Checking DKMS status post-install."
        if dkms status | grep -q "nvidia/${version}"; then
             print_color "$GREEN" "DKMS module appears installed for $version."
             log_msg "INFO" "DKMS module found for nvidia/$version."
             return 0 # Success
        else
            print_color "$RED" "ERROR: DKMS module for nvidia/$version not found after install!"
            log_msg "ERROR" "DKMS module for nvidia/$version not found after APT install."
            return 1 # Failure
        fi
    else
        print_color "$RED" "ERROR: apt install $package_name failed!"
        log_msg "ERROR" "apt install $package_name failed."
        print_color "$YELLOW" "  Attempting package fix commands..."
        dpkg --configure -a
        apt-get install -f
        return 1 # Failure
    fi
}

install_nvidia_runfile() {
    local version="$1"
    # Note: Need to map version number (535) to specific runfile name (535.xxx.yy)
    # This requires either hardcoding or a lookup mechanism
    local runfile_name=""
    local runfile_url="" # Add URL if attempting download

    # --- Determine Runfile Name/URL ---
    # Example: This needs updating with actual filenames/URLs from Nvidia site
    case "$version" in
        "535")
            runfile_name="NVIDIA-Linux-x86_64-535.183.01.run" # Example, CHECK NVIDIA FOR LATEST 535
            runfile_url="https://us.download.nvidia.com/XFree86/Linux-x86_64/535.183.01/NVIDIA-Linux-x86_64-535.183.01.run"
            ;;
         "550")
            runfile_name="NVIDIA-Linux-x86_64-550.120.00.run" # EXAMPLE ONLY - CHECK NVIDIA
            runfile_url="URL_FOR_550_RUNFILE" # EXAMPLE ONLY - FIND ACTUAL URL
             ;;
        *)
            print_color "$RED" "ERROR: No runfile defined for driver version $version in script."
            log_msg "ERROR" "Runfile name/URL not defined for version $version."
            return 1
            ;;
    esac
    # --- ---

    local runfile_path="$HOME/$runfile_name" # Assume download to home dir

    print_color "$CYAN" "\nStarting Runfile installation for $runfile_name..."
    log_msg "INFO" "Starting Runfile install for $runfile_name."

    # Check if runfile exists, offer download?
    if [[ ! -f "$runfile_path" ]]; then
        print_color "$YELLOW" "Runfile '$runfile_path' not found."
        log_msg "WARN" "Runfile $runfile_path not found."
        if [[ -n "$runfile_url" && "$runfile_url" != "URL_"* ]]; then
             if prompt_confirm "Attempt to download from $runfile_url?"; then
                 print_color "$CYAN" "Downloading $runfile_name to $HOME..."
                 log_msg "EXEC" "wget -P $HOME $runfile_url"
                 wget -P "$HOME" "$runfile_url"
                 if [[ $? -ne 0 ]]; then
                      print_color "$RED" "ERROR: Download failed!"
                      log_msg "ERROR" "Runfile download failed."
                      return 1
                 fi
                 chmod +x "$runfile_path"
             else
                print_color "$RED" "Aborting. Please download '$runfile_name' manually to $HOME."
                return 1
             fi
        else
             print_color "$RED" "No download URL configured. Aborting. Please download '$runfile_name' manually to $HOME."
             return 1
        fi
    fi

    if ! check_tty; then return 1; fi

     local dm_service
     dm_service=$(get_display_manager)
     if [[ -n "$dm_service" ]]; then
        print_color "$CYAN" "Attempting to stop display manager ($dm_service)..."
        log_msg "EXEC" "systemctl stop $dm_service"
        systemctl stop "$dm_service" || print_color "$YELLOW" "Warning: Failed to stop $dm_service."
    else
        print_color "$YELLOW" "Could not detect display manager. Skipping stop command. Ensure graphical server is not running!"
        sleep 3
    fi

    print_color "$CYAN" "Running Nvidia installer ($runfile_name)..."
    print_color "$YELLOW" "Using flags: --dkms --ui=none --no-questions (Accepts defaults)"
    log_msg "EXEC" "$runfile_path --dkms --ui=none --no-questions"

    # --- PRE-INSTALL STEPS (Runfile often needs these) ---
    print_color "$CYAN" "Ensuring build tools & headers are installed..."
    log_msg "EXEC" "apt install build-essential linux-headers-$(uname -r) -y"
    apt install build-essential "linux-headers-$(uname -r)" -y

    print_color "$CYAN" "Blacklisting Nouveau..."
    log_msg "EXEC" "echo blacklist | tee /etc/modprobe.d/blacklist-nvidia-runfile.conf" # Simple blacklist
    echo "blacklist nouveau" > /etc/modprobe.d/blacklist-nvidia-runfile.conf
    log_msg "EXEC" "update-initramfs -u"
    update-initramfs -u
    # --- ---

    if "$runfile_path" --dkms --ui=none --no-questions; then
        print_color "$GREEN" "Nvidia Runfile installer finished."
        log_msg "INFO" "Nvidia Runfile installer finished successfully."
        # Consider removing blacklist file if successful?
        # rm -f /etc/modprobe.d/blacklist-nvidia-runfile.conf
        # update-initramfs -u
        return 0 # Success
    else
        print_color "$RED" "ERROR: Nvidia Runfile installer failed!"
        log_msg "ERROR" "Nvidia Runfile installer failed."
        print_color "$YELLOW" "Check the log: /var/log/nvidia-installer.log"
        # Attempt to restart display manager on failure
        if [[ -n "$dm_service" ]]; then
            print_color "$CYAN" "Attempting to restart display manager..."
            log_msg "EXEC" "systemctl start $dm_service"
            systemctl start "$dm_service" || print_color "$YELLOW" "Failed to restart display manager."
        fi
        return 1 # Failure
    fi
}


# --- Module: GRUB Fix ---
run_grub_fix() {
    print_color "$PURPLE" "\n--- Module: GRUB Configuration Fix ---"
    log_msg "INFO" "Starting GRUB Fix module."

    local grub_default="/etc/default/grub"
    local grub_backup="/etc/default/grub.backup.$(date +%Y%m%d_%H%M%S)"
    local selected_config=""

    # Present Options
    print_color "$YELLOW" "Select a GRUB configuration preset:"
    echo "  1) Standard Ubuntu Default (Quiet Splash)"
    echo "  2) Verbose Boot (No quiet splash)"
    echo "  3) Basic Failsafe (nomodeset - for graphics issues)"
    echo "  4) Reinstall GRUB Bootloader (EFI)"
    echo "  5) Cancel"
    read -p "$(print_color "$YELLOW" "Enter choice: ")" g_choice

    case "$g_choice" in
        1) # Standard
            config_name="Standard Ubuntu Default"
            selected_config=$(cat <<'GRUBEOF'
GRUB_DEFAULT=0
GRUB_TIMEOUT_STYLE=menu
GRUB_TIMEOUT=5
GRUB_DISTRIBUTOR=`lsb_release -i -s 2> /dev/null || echo Debian`
GRUB_CMDLINE_LINUX_DEFAULT="quiet splash"
GRUB_CMDLINE_LINUX=""
GRUB_GFXMODE=auto # Let grub detect
GRUB_TERMINAL=console # Sometimes needed if gfx fails early
GRUBEOF
)
            ;;
        2) # Verbose
            config_name="Verbose Boot"
             selected_config=$(cat <<'GRUBEOF'
GRUB_DEFAULT=0
GRUB_TIMEOUT_STYLE=menu
GRUB_TIMEOUT=10 # Longer timeout
GRUB_DISTRIBUTOR=`lsb_release -i -s 2> /dev/null || echo Debian`
GRUB_CMDLINE_LINUX_DEFAULT="" # No quiet splash
GRUB_CMDLINE_LINUX=""
GRUB_GFXMODE=auto
GRUB_TERMINAL=console
GRUBEOF
)
            ;;
        3) # Nomodeset
            config_name="Basic Failsafe (nomodeset)"
             selected_config=$(cat <<'GRUBEOF'
GRUB_DEFAULT=0
GRUB_TIMEOUT_STYLE=menu
GRUB_TIMEOUT=10
GRUB_DISTRIBUTOR=`lsb_release -i -s 2> /dev/null || echo Debian`
GRUB_CMDLINE_LINUX_DEFAULT="nomodeset" # Add nomodeset
GRUB_CMDLINE_LINUX=""
# GRUB_GFXMODE= # Comment out GFXMODE with nomodeset
GRUB_TERMINAL=console
GRUBEOF
)
            ;;
        4) # Reinstall GRUB
             print_color "$CYAN" "Selected: Reinstall GRUB Bootloader (EFI)."
             log_msg "USER" "Selected GRUB Fix: Reinstall GRUB."
             if prompt_confirm "This will run 'grub-install --recheck'. Continue?"; then
                 print_color "$CYAN" "Running grub-install..."
                 log_msg "EXEC" "grub-install --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id=ubuntu --recheck"
                 if grub-install --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id=ubuntu --recheck; then
                     print_color "$GREEN" "grub-install completed successfully."
                     log_msg "INFO" "grub-install completed successfully."
                     print_color "$CYAN" "Running update-grub..."
                     log_msg "EXEC" "update-grub"
                     if update-grub; then
                         print_color "$GREEN" "update-grub completed successfully."
                         log_msg "INFO" "update-grub completed successfully."
                     else
                         print_color "$RED" "ERROR: update-grub failed!"
                         log_msg "ERROR" "update-grub failed after grub-install."
                         return 1
                     fi
                 else
                    print_color "$RED" "ERROR: grub-install failed!"
                    log_msg "ERROR" "grub-install failed."
                    return 1
                 fi
             else
                log_msg "USER" "User cancelled grub-install."
                return 1
             fi
             return 0 # Finished reinstall task
             ;;
        *)
            print_color "$YELLOW" "GRUB fix cancelled."
            log_msg "USER" "Cancelled GRUB fix selection."
            return 1
            ;;
    esac

    # Apply Config Change (Options 1, 2, 3)
    print_color "$CYAN" "\nSelected Config: $config_name"
    print_color "$PURPLE" "--- Configuration to Apply ---"
    # Simulate typing
    print_color "$CYAN" "$(type_effect "$selected_config")"
    print_color "$PURPLE" "------------------------------"
    log_msg "INFO" "Applying GRUB config: $config_name"

    if prompt_confirm "Apply this configuration to $grub_default?"; then
        print_color "$YELLOW" "Backing up current config to $grub_backup..."
        log_msg "EXEC" "cp $grub_default $grub_backup"
        cp "$grub_default" "$grub_backup" || { print_color "$RED" "ERROR: Failed to backup GRUB config!"; log_msg "ERROR" "Failed to backup GRUB config."; return 1; }

        print_color "$CYAN" "Writing new configuration..."
        log_msg "EXEC" "echo \"$selected_config\" | tee $grub_default" # Needs sudo implicitly from script start
        # Use echo and tee to write config - avoids heredoc issues with sudo
        if echo "$selected_config" | tee "$grub_default" > /dev/null; then
             print_color "$CYAN" "Running update-grub..."
             log_msg "EXEC" "update-grub"
             if update-grub; then
                 print_color "$GREEN" "GRUB updated successfully with '$config_name' config."
                 log_msg "INFO" "GRUB updated successfully with '$config_name' config."
                 return 0 # Success
             else
                print_color "$RED" "ERROR: update-grub failed after applying config!"
                log_msg "ERROR" "update-grub failed after applying config."
                print_color "$YELLOW" "Consider restoring backup: sudo cp $grub_backup $grub_default && sudo update-grub"
                return 1 # Failure
             fi
        else
             print_color "$RED" "ERROR: Failed to write to $grub_default!"
             log_msg "ERROR" "Failed to write GRUB config."
             return 1 # Failure
        fi
    else
        print_color "$YELLOW" "GRUB configuration change cancelled."
        log_msg "USER" "User cancelled GRUB config application."
        return 1
    fi
}

# --- Module: Kernel Fix ---
run_kernel_fix() {
    print_color "$PURPLE" "\n--- Module: Kernel Reset ---"
    log_msg "INFO" "Starting Kernel Reset module."

    print_color "$YELLOW" "This attempts to fix boot issues by removing and reinstalling a specific kernel version."
    print_color "$YELLOW" "It assumes you are currently booted into a DIFFERENT, WORKING kernel (like an older version or recovery)."

    local current_kernel
    current_kernel=$(uname -r)
    log_msg "INFO" "Currently running kernel: $current_kernel"
    print_color "$CYAN" "Currently running kernel: $current_kernel"

    print_color "$CYAN" "Identifying installed kernels..."
    dpkg -l | grep -E '^ii.*linux-(image|headers)-[0-9]' | awk '{print $2}' | sort -V > /tmp/installed_kernels.txt
    log_msg "INFO" "Installed kernels listed in /tmp/installed_kernels.txt"

    print_color "$YELLOW" "Installed kernels found:"
    cat /tmp/installed_kernels.txt | sed 's/^/  /'
    echo ""

    local kernel_to_fix=""
    while true; do
        read -p "$(print_color "$YELLOW" "Enter the FULL version string of the kernel to remove/reinstall (e.g., 6.8.0-57-generic): ")" kernel_version
        if grep -q "linux-image-${kernel_version}" /tmp/installed_kernels.txt; then
            if [[ "$kernel_version" == "$current_kernel" ]]; then
                 print_color "$RED" "Cannot remove the currently running kernel ($current_kernel)!"
                 log_msg "WARN" "User attempted to remove the running kernel."
            else
                 kernel_to_fix="$kernel_version"
                 break
            fi
        else
             print_color "$RED" "Kernel version '$kernel_version' not found in installed list."
        fi
    done
    rm /tmp/installed_kernels.txt # Clean up temp file
    log_msg "USER" "Selected kernel to fix: $kernel_to_fix"

    print_color "$RED" "\nWARNING: This will PURGE kernel $kernel_to_fix and then reinstall it."
    if ! prompt_confirm "Are you absolutely sure? Booted into a working kernel: $current_kernel?"; then
        log_msg "USER" "User cancelled kernel fix."
        return 1
    fi

    print_color "$CYAN" "Step 1: Purging kernel $kernel_to_fix..."
    local purge_cmd="apt-get purge --autoremove -y linux-image-${kernel_to_fix} linux-headers-${kernel_to_fix} linux-modules-${kernel_to_fix} linux-modules-extra-${kernel_to_fix}"
    print_color "$CMD_COLOR" "$purge_cmd"
    log_msg "EXEC" "$purge_cmd"
    if eval "$purge_cmd"; then
        print_color "$GREEN" "Kernel $kernel_to_fix purged successfully."
        log_msg "INFO" "Kernel $kernel_to_fix purged successfully."
        # DKMS removal should happen automatically here, log file will show details if run with sudo
    else
         print_color "$RED" "ERROR: Failed to purge kernel $kernel_to_fix!"
         log_msg "ERROR" "Failed to purge kernel $kernel_to_fix."
         print_color "$YELLOW" "Attempting package fix commands..."
         dpkg --configure -a
         apt-get install -f
         return 1
    fi

    # Optional: Verify removal from /boot and /lib/modules?

    print_color "$CYAN" "Step 2: Updating GRUB..."
    log_msg "EXEC" "update-grub"
    if ! update-grub; then
         print_color "$RED" "ERROR: update-grub failed after purge!"
         log_msg "ERROR" "update-grub failed after purge."
         # Continue anyway, reinstall might fix it
    fi

    print_color "$CYAN" "Step 3: Reinstalling kernel $kernel_to_fix..."
    # Determine HWE package name if applicable (adjust based on base OS version if needed)
    local base_kernel_series="${kernel_to_fix%%-generic}" # e.g., 6.8.0-57
    local hwe_package="linux-generic-hwe-22.04" # Assuming 22.04 base

    local install_cmd="apt install -y linux-image-${kernel_to_fix} linux-headers-${kernel_to_fix} ${hwe_package}"
    print_color "$CMD_COLOR" "$install_cmd"
    log_msg "EXEC" "$install_cmd"
    if eval "$install_cmd"; then
         print_color "$GREEN" "Kernel $kernel_to_fix reinstalled successfully."
         log_msg "INFO" "Kernel $kernel_to_fix reinstalled successfully."
    else
        print_color "$RED" "ERROR: Failed to reinstall kernel $kernel_to_fix!"
        log_msg "ERROR" "Failed to reinstall kernel $kernel_to_fix."
        return 1
    fi

    print_color "$GREEN" "\n--- Kernel Reset Complete ---"
    print_color "$YELLOW" "A reboot is required to test the reinstalled kernel."
    print_color "$YELLOW" "Boot into '$kernel_to_fix' (it should be default). If it fails again, the issue is deeper."
    log_msg "INFO" "Kernel Reset module finished."
    return 0
}


# --- Module: Chroot Helper ---
run_chroot_helper() {
    print_color "$PURPLE" "\n--- Module: Chroot Helper ---"
    log_msg "INFO" "Starting Chroot Helper module."
    print_color "$YELLOW" "This helps mount your system partitions and enter a chroot environment from the Live OS."

    local root_part=""
    local efi_part=""
    local mount_point="/mnt/system" # Hardcoded standard mount point
    local bind_mounts=( "/dev" "/dev/pts" "/proc" "/sys" )

    # Get Partitions
    print_color "$CYAN" "Need your installed system's partitions."
    lsblk -f # Show available partitions
    while true; do read -p "$(print_color "$YELLOW" "Enter ROOT partition: ")" root_part; if [[ -b "$root_part" ]]; then break; else print_color "$RED" "Invalid device."; fi; done
    while true; do read -p "$(print_color "$YELLOW" "Enter EFI partition: ")" efi_part; if [[ -b "$efi_part" ]]; then break; else print_color "$RED" "Invalid device."; fi; done
    log_msg "USER" "Selected Root: $root_part, EFI: $efi_part for chroot."

    # Mount
    print_color "$CYAN" "Mounting partitions..."
    log_msg "EXEC" "mkdir -p $mount_point/boot/efi"
    mkdir -p "$mount_point/boot/efi" || { log_msg "ERROR" "Failed mkdir"; return 1; }
    log_msg "EXEC" "mount $root_part $mount_point"
    mount "$root_part" "$mount_point" || { log_msg "ERROR" "Failed mount root"; return 1; }
    log_msg "EXEC" "mount $efi_part $mount_point/boot/efi"
    mount "$efi_part" "$mount_point/boot/efi" || { log_msg "ERROR" "Failed mount efi"; umount "$mount_point"; return 1; }

    # Bind Mounts
    print_color "$CYAN" "Setting up bind mounts..."
    for path in "${bind_mounts[@]}"; do
        log_msg "EXEC" "mount --bind $path $mount_point$path"
        mount --bind "$path" "$mount_point$path" || { log_msg "ERROR" "Failed bind $path"; umount -R "$mount_point" &>/dev/null; return 1; }
    done

    # DNS
    print_color "$CYAN" "Copying DNS info..."
    log_msg "EXEC" "cp /etc/resolv.conf $mount_point/etc/resolv.conf"
    cp /etc/resolv.conf "$mount_point/etc/resolv.conf" || log_msg "WARN" "Failed to copy DNS info."

    print_color "$GREEN" "System mounted and prepped."
    print_color "$YELLOW" "Entering chroot environment. Type 'exit' when done."
    read -p "$(print_color "$YELLOW" "Press Enter to chroot...")"

    log_msg "EXEC" "chroot $mount_point /bin/bash"
    chroot "$mount_point" /bin/bash
    local chroot_exit_status=$?
    log_msg "INFO" "Exited chroot with status $chroot_exit_status."

    print_color "$PURPLE" "\n--- Exited Chroot ---"
    print_color "$YELLOW" "Remember to UNMOUNT MANUALLY:"
    print_color "$CYAN"   "sudo umount -R $mount_point"
    return 0
}

# --- Main Menu ---
main_menu() {
    print_color "$PURPLE" "\n=== GPU & System Rescue Manager v$SCRIPT_VERSION ==="
    print_color "$GREEN" "Select an operation:"
    echo "  1) NVIDIA Deep Clean (Purge drivers/CUDA)"
    echo "  2) NVIDIA Driver Install (APT or Runfile)"
    echo "  3) GRUB Fix / Reinstall"
    echo "  4) Kernel Reset (Remove & Reinstall)"
    echo "  5) Chroot Helper (Live OS Only)"
    echo "  6) Exit"

    local choice
    read -p "$(print_color "$YELLOW" "Enter choice [1-6]: ")" choice

    case "$choice" in
        1) run_nvidia_cleanup ;;
        2) run_nvidia_install ;;
        3) run_grub_fix ;;
        4) run_kernel_fix ;;
        5) run_chroot_helper ;;
        6) print_color "$GREEN" "Exiting manager."; log_msg "INFO" "Exiting script."; exit 0 ;;
        *) print_color "$RED" "Invalid selection." ;;
    esac

    read -p "$(print_color "$YELLOW" "\nPress Enter to return to menu...")"
}

# --- Script Start ---
check_sudo # Ensure script is run with sudo

# Create log directory if it doesn't exist
mkdir -p "$LOG_DIR"
log_msg "INFO" "GPU Manager Started. Version $SCRIPT_VERSION. Logging to $MAIN_LOG_FILE"

# Main loop
while true; do
    main_menu
done

