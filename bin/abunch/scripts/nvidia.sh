#!/usr/bin/env bash

# NVIDIA Management Script - "nvidia-mybitch.sh" v1.7
# Built for the streets, respects the hustle. No more bullshit placeholders.

# --- Configuration ---
SCRIPT_VERSION="1.7" # Menu restructure, Log viewer, Log/Path fixes, Nvidia APT method, GRUB params
USER_HOME="" # Determined by check_sudo()
LOG_DIR=""   # Determined by check_sudo()
MAIN_LOG_FILE="" # Determined by check_sudo()

# --- Color Palette (Cyberpunk Neon) ---
GREEN='\e[92m'    # Bright Green (Success, Info)
PURPLE='\e[95m'   # Bright Purple (Section Headers, Highlights)
CYAN='\e[96m'     # Bright Cyan (Commands, Explanations)
YELLOW='\e[93m'   # Bright Yellow (Prompts, Warnings)
RED='\e[91m'      # Bright Red (ERRORS, Critical Warnings)
NC='\e[0m'       # No Color (Reset)

# --- Helper Functions ---
print_color() { echo -e "${1}${2}${NC}" >&2; }

log_msg() {
    if [[ -z "$MAIN_LOG_FILE" ]]; then echo "FATAL: Log file not initialized!" >&2; exit 1; fi
    local level="$1"; local message="$2"; local log_line;
    log_line="$(date +'%Y-%m-%d %H:%M:%S') [$level] - $message"
    echo "$log_line" >> "$MAIN_LOG_FILE" # Always log to file
    if [[ "$level" == "ERROR" || "$level" == "WARN" ]]; then
        local color="$YELLOW"; [[ "$level" == "ERROR" ]] && color="$RED"
        print_color "$color" "[$level] $message" # Also print errors/warnings to screen
    fi
}

prompt_confirm() {
    local message="$1"; local default_choice="${2:-N}"; local psfx="[y/N]";
    [[ "$default_choice" =~ ^[Yy]$ ]] && psfx="[Y/n]"
    while true; do
        echo -en "$(print_color "$YELLOW" "$message $psfx: ")" >&2
        read -r choice < /dev/tty
        choice="${choice:-$default_choice}";
        case "$choice" in
            [Yy]*) log_msg "USER" "Confirmed: '$message'"; return 0;;
            [Nn]*) log_msg "USER" "Cancelled: '$message'"; return 1;;
            *) print_color "$RED" "Invalid input.";;
        esac
    done
}

type_effect() {
    local text="$1"; local delay="${2:-0.03}";
    if [[ -z "$NO_TYPE_EFFECT" ]]; then
        for (( i=0; i<${#text}; i++ )); do printf "%c" "${text:$i:1}" >&2; sleep "$(awk -v M=0.01 -v x="$delay" 'BEGIN{srand(); print M+rand()*(x-M)}')"; done
    else printf "%s" "$text" >&2; fi;
    echo >&2;
}

check_sudo() {
    if [[ -z "$SUDO_USER" || "$EUID" -ne 0 ]]; then print_color "$RED" "Error: Run with sudo."; exit 1; fi
    USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
    if [[ -z "$USER_HOME" || ! -d "$USER_HOME" ]]; then print_color "$YELLOW" "Warn: Could not get user home via getent. Fallback..."; USER_HOME=$(eval echo ~"$SUDO_USER"); if [[ -z "$USER_HOME" || ! -d "$USER_HOME" ]]; then print_color "$RED" "Fallback failed. Exiting."; exit 1; fi; fi
    LOG_DIR="$USER_HOME/gpu_manager_logs"; MAIN_LOG_FILE="$LOG_DIR/nvidia-mybitch_main_$(date +%Y%m%d_%H%M%S).log"; mkdir -p "$LOG_DIR" || { print_color "$RED" "FATAL: Could not create log dir $LOG_DIR"; exit 1; }; touch "$MAIN_LOG_FILE" || { print_color "$RED" "FATAL: Could not create log file $MAIN_LOG_FILE"; exit 1; }; chown "$SUDO_USER:$SUDO_USER" "$LOG_DIR" "$MAIN_LOG_FILE" || print_color "$YELLOW" "Warn: Could not chown log dir/file."
    log_msg "INFO" "Sudo check passed. User: $SUDO_USER. Home: $USER_HOME. Logging: $MAIN_LOG_FILE."
}

check_tty() { if ! tty -s || [[ -n "$DISPLAY" ]]; then log_msg "WARN" "Op started outside TTY."; print_color "$YELLOW" "Warning: Best run from TTY."; if ! prompt_confirm "Continue anyway?"; then log_msg "USER" "Aborted: Not TTY."; return 1; fi; fi; return 0; }

get_display_manager() {
  local detected_dm=""; local final_dm=""; local user_input; log_msg "INFO" "Detecting DM...";
  if systemctl list-units --type=service --state=active | grep -q -E 'gdm[0-9]*\.service|gdm\.service'; then detected_dm="gdm3.service"; elif systemctl list-units --type=service --state=active | grep -q 'sddm\.service'; then detected_dm="sddm.service"; elif systemctl list-units --type=service --state=active | grep -q 'lightdm\.service'; then detected_dm="lightdm.service"; fi;
  if [[ -n "$detected_dm" ]]; then log_msg "INFO" "Detected: $detected_dm"; read -r -p "$(print_color "$YELLOW" "Detected '$detected_dm'. Correct? [Y/n]: ")" confirm < /dev/tty; confirm="${confirm:-Y}"; if [[ "$confirm" =~ ^[Yy]$ ]]; then final_dm="$detected_dm"; log_msg "USER" "Confirmed DM: $final_dm"; else log_msg "USER" "Rejected detected DM."; detected_dm=""; fi; fi;
  if [[ -z "$final_dm" ]]; then print_color "$YELLOW" "Could not detect/confirm."; read -r -p "$(print_color "$YELLOW" "Enter DM service (or blank to skip): ")" user_input < /dev/tty; if [[ -n "$user_input" ]]; then if [[ ! "$user_input" == *".service" ]]; then final_dm="${user_input}.service"; else final_dm="$user_input"; fi; log_msg "USER" "Manual DM: $final_dm"; else print_color "$YELLOW" "Skipping DM."; log_msg "USER" "Skipped DM."; final_dm=""; fi; fi;
  echo "$final_dm"; if [[ -n "$final_dm" ]]; then return 0; else return 1; fi;
}

# --- >>> UPDATED run_command with LIVE screen output + MAIN log file logging <<< ---
run_command() {
    local cmd_string="$1"
    local log_output_to_file="${2:-false}" # Controls logging to SEPARATE file (true/false)
    local cmd_desc="${3:-Command}"

    log_msg "EXEC" "($cmd_desc): $cmd_string"
    print_color "$CYAN" "Running: $cmd_string"

    local output_log_file="${LOG_DIR}/cmd_output_$(date +%s)_$(echo "$cmd_desc" | sed 's/[^a-zA-Z0-9]/-/g' | cut -c -50).log"
    local status
    local tee_cmd="tee -a \"$MAIN_LOG_FILE\"" # Append to main log file

    # Ensure the output log file exists if requested
    if [[ "$log_output_to_file" == true ]]; then
        touch "$output_log_file" && chown "$SUDO_USER:$SUDO_USER" "$output_log_file" || log_msg "WARN" "Could not touch/chown output log $output_log_file"
        # Add tee for the separate file as well
        tee_cmd+=" | tee \"$output_log_file\""
        print_color "$CYAN" "(Logging output to $output_log_file AND main log)"
    else
         print_color "$CYAN" "(Command output will appear below and in main log)"
    fi

    # Execute command, pipe stdout and stderr through tee to main log file AND redirect to /dev/tty
    # Need bash -c to handle complex commands and pipes correctly with process substitution
    bash -c "eval $cmd_string" > >(eval "$tee_cmd" > /dev/tty) 2> >(eval "$tee_cmd" > /dev/tty)
    status=${PIPESTATUS[0]} # Status of the 'eval' command

    log_msg "INFO" "($cmd_desc) finished status: $status"

    if [[ $status -ne 0 ]]; then
        print_color "$RED" "Command ($cmd_desc) failed! Status: $status"
        print_color "$YELLOW" "Check output above and main log file: $MAIN_LOG_FILE"
        if [[ "$log_output_to_file" == true ]]; then print_color "$YELLOW" "Also check separate log: $output_log_file"; fi
        return $status
    fi
    # Clean up empty separate log file if not needed
    if [[ "$log_output_to_file" == false && -f "$output_log_file" && ! -s "$output_log_file" ]]; then
        rm "$output_log_file" &> /dev/null
    fi
    return 0
}

view_log_file() {
    local log_path="$1"; local log_desc="$2";
    print_color "$CYAN" "Viewing: $log_desc ($log_path)"; log_msg "INFO" "Viewing log: $log_desc ($log_path)"
    if [[ ! -f "$log_path" ]]; then print_color "$YELLOW" "Not found: $log_path"; log_msg "WARN" "Log not found: $log_path"; read -r -p "$(print_color "$YELLOW" "Enter...")" < /dev/tty; return 1; fi
    if [[ ! -r "$log_path" ]]; then print_color "$RED" "Cannot read: $log_path"; log_msg "ERROR" "Cannot read log: $log_path"; read -r -p "$(print_color "$YELLOW" "Enter...")" < /dev/tty; return 1; fi
    less "$log_path" < /dev/tty # Ensure less reads from TTY
}

# --- Modules (Implementations below Main Menu for readability) ---
run_manage_display_manager() {
    print_color "$PURPLE" "\n--- Module: Display Manager Control ---"; log_msg "INFO" "Starting DM Control.";
    local dm; dm=$(get_display_manager); if [[ $? -ne 0 || -z "$dm" ]]; then print_color "$YELLOW" "Cannot manage DM."; return 1; fi;
    print_color "$YELLOW" "Action for '$dm':"; echo " 1) Stop"; echo " 2) Start"; echo " 3) Status"; echo " 4) Cancel"; local choice;
    read -r -p "$(print_color "$YELLOW" "Choice [1-4]: ")" choice < /dev/tty;
    case "$choice" in
        1) run_command "systemctl stop $dm" false "Stop DM";;
        2) run_command "systemctl start $dm" false "Start DM";;
        3) run_command "systemctl status $dm" false "DM Status";; # Output is now logged+screen via run_command
        4) log_msg "USER" "Cancelled DM action."; return 1;; *) print_color "$RED" "Invalid."; return 1;;
    esac; return $?;
}

run_prepare_build_env() {
    print_color "$PURPLE" "\n--- Module: Prepare Build Environment ---"; log_msg "INFO" "Starting Build Env Prep.";
    print_color "$CYAN" "Installs/reinstalls DKMS, build-essential, current kernel headers.";
    local k; k=$(uname -r); local hdr="linux-headers-${k}"; local req="dkms build-essential ${hdr}";
    print_color "$CYAN" "Checking required pkgs ($req)..."; log_msg "INFO" "Checking: $req"; local missing="";
    for pkg in dkms build-essential "$hdr"; do if ! dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "ok installed"; then missing+="$pkg "; fi; done;
    if [[ -n "$missing" ]]; then log_msg "WARN" "Missing: ${missing% }"; print_color "$YELLOW" "Missing: ${missing% }"; if ! prompt_confirm "Install/reinstall?"; then log_msg "USER" "Skipped pkg install."; return 1; fi;
        print_color "$CYAN" "Running apt update & install..."; if ! run_command "apt update" false "Update build env"; then log_msg "WARN" "apt update failed."; fi; if ! run_command "apt install --reinstall -y $req" false "Install build env"; then log_msg "ERROR" "Install failed."; return 1; fi; log_msg "INFO" "Pkgs installed/reinstalled."; print_color "$GREEN" "Pkgs installed/reinstalled.";
    else log_msg "INFO" "Pkgs already present."; print_color "$GREEN" "Required pkgs seem installed."; if prompt_confirm "Reinstall anyway?"; then print_color "$CYAN" "Running apt update & reinstall..."; if ! run_command "apt update && apt install --reinstall -y $req" true "Reinstall build env"; then log_msg "ERROR" "Reinstall failed."; return 1; fi; log_msg "INFO" "Pkgs reinstalled."; print_color "$GREEN" "Pkgs reinstalled."; fi; fi;
    print_color "$CYAN" "Checking DKMS status..."; run_command "dkms status" false "DKMS Status Check"; print_color "$GREEN" "\n--- Build Env Prep Finished ---"; log_msg "INFO" "Build Env Prep finished."; return 0;
}

run_manage_gcc() {
    print_color "$PURPLE" "\n--- Module: Manage GCC Version ---"; log_msg "INFO" "Starting GCC Mgmt.";
    local gcc; gcc=$(gcc --version | head -n1); local gpp; gpp=$(g++ --version | head -n1); print_color "$CYAN" "Current GCC: $gcc"; print_color "$CYAN" "Current G++: $gpp"; log_msg "INFO" "Current GCC: $gcc / G++: $gpp";
    print_color "$YELLOW" "\nNote: Default GCC 11 on Ubuntu 22.04 OK for recent Nvidia. Switch only if build fails.";
    echo "\nOptions:"; echo " 1) Check alternatives"; echo " 2) Install GCC/G++ 12"; echo " 3) Show manual switch cmds"; echo " 4) Back"; local choice;
    read -r -p "$(print_color "$YELLOW" "Choice [1-4]: ")" choice < /dev/tty;
    case "$choice" in
        1) print_color "$CYAN" "Checking gcc alternatives..."; run_command "update-alternatives --display gcc" false "GCC Alts"; print_color "$CYAN" "Checking g++ alternatives..."; run_command "update-alternatives --display g++" false "G++ Alts";;
        2) print_color "$CYAN" "Checking gcc-12/g++-12..."; if dpkg-query -W -f='${Status}' gcc-12 2>/dev/null | grep -q "ok installed" && dpkg-query -W -f='${Status}' g++-12 2>/dev/null | grep -q "ok installed"; then print_color "$GREEN" "gcc-12/g++-12 already installed."; log_msg "INFO" "gcc-12 installed."; else print_color "$YELLOW" "gcc-12/g++-12 not found."; if prompt_confirm "Install gcc-12 and g++-12?"; then if run_command "apt update && apt install -y gcc-12 g++-12" true "Install GCC 12"; then log_msg "INFO" "Installed gcc-12."; print_color "$YELLOW" "Run opt 1 & 3 for switching."; else log_msg "ERROR" "Install GCC 12 failed."; fi; fi; fi;;
        3) print_color "$YELLOW" "MANUAL switch commands:"; print_color "$CYAN" "# 1. Add alternatives (if needed):"; print_color "$CYAN" "sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-11 110 --slave /usr/bin/g++ g++ /usr/bin/g++-11"; print_color "$CYAN" "sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-12 120 --slave /usr/bin/g++ g++ /usr/bin/g++-12"; print_color "$CYAN" "# 2. Choose default:"; print_color "$CYAN" "sudo update-alternatives --config gcc"; log_msg "INFO" "Showed manual GCC cmds.";;
        4) return 0;; *) print_color "$RED" "Invalid."; return 1;;
    esac; return 0;
}

run_nouveau_blacklist() {
    print_color "$PURPLE" "\n--- Module: Blacklist Nouveau Driver ---"; log_msg "INFO" "Starting Nouveau Blacklist.";
    if ! prompt_confirm "Create modprobe config to blacklist Nouveau?"; then log_msg "USER" "Cancelled blacklist."; return 1; fi;
    local conf="/etc/modprobe.d/blacklist-nvidia-nouveau-manual.conf"; local content="blacklist nouveau\noptions nouveau modeset=0";
    print_color "$CYAN" "Creating/Overwriting $conf..."; if run_command "echo -e \"$content\" | tee \"$conf\" > /dev/null" false "Write blacklist"; then
        print_color "$CYAN" "Running update-initramfs..."; if run_command "update-initramfs -u" true "Update initramfs black"; then
            print_color "$GREEN" "Nouveau blacklisted."; print_color "$YELLOW" "Reboot required."; log_msg "INFO" "Nouveau blacklisted ok."; return 0;
        else log_msg "ERROR" "update-initramfs failed."; return 1; fi
    else log_msg "ERROR" "Write blacklist failed."; return 1; fi
}

run_nvidia_cleanup() {
    print_color "$PURPLE" "\n--- Module: NVIDIA Deep Clean ---"; log_msg "INFO" "Starting Deep Clean.";
    if ! prompt_confirm "COMPLETELY remove Nvidia drivers/CUDA via DKMS & APT?"; then return 1; fi; if ! check_tty; then return 1; fi;
    local dm; dm=$(get_display_manager); if [[ -n "$dm" ]]; then print_color "$CYAN" "Stopping DM ($dm)..."; run_command "systemctl stop $dm" false "Stop DM Clean" || print_color "$YELLOW" "Warn: Stop DM failed."; fi

    print_color "$CYAN" "Step 1: Removing DKMS modules..."; local dkms_mods; dkms_mods=$(dkms status | grep -E 'nvidia|nvidia-fs' | awk -F',|/' '{print $1"/"$2}' | sort -u); if [[ -n "$dkms_mods" ]]; then local fail=0; for mod in $dkms_mods; do print_color "$YELLOW" " Removing: $mod"; run_command "dkms remove $mod --all" false "Remove DKMS $mod" || fail=1; done; print_color "$CYAN" " Verifying DKMS..."; sleep 1; if dkms status | grep -qE 'nvidia|nvidia-fs'; then log_msg "ERROR" "DKMS modules remain!"; return 1; else print_color "$GREEN" " DKMS clean."; log_msg "INFO" "DKMS removed."; fi; else print_color "$GREEN" " No Nvidia DKMS modules."; log_msg "INFO" "No Nvidia DKMS modules."; fi

    print_color "$CYAN" "Step 2: Finding & Purging packages..."; local pkgs; pkgs=$(dpkg -l | grep -E 'nvidia|cuda|libnvidia|cublas|cufft|cufile|curand|cusolver|cusparse|npp|nvjpeg' | grep -E '^ii' | awk '{print $2}' | tr '\n' ' '); if [[ -z "$pkgs" ]]; then print_color "$GREEN" " No packages found."; log_msg "INFO" "No packages found."; else print_color "$YELLOW" " Found:"; echo "$pkgs" | fold -s -w 80 | sed 's/^/    /' >&2; log_msg "INFO" "Purge list: $pkgs"; if ! prompt_confirm "Purge these packages?"; then log_msg "USER" "Cancelled purge."; return 1; fi; print_color "$CYAN" " Purging..."; if ! run_command "apt-get purge --autoremove -y $pkgs" false "APT Purge"; then log_msg "ERROR" "apt purge failed."; print_color "$YELLOW" " Attempting fix..."; run_command "dpkg --configure -a" false "dpkg configure"; run_command "apt-get install -f -y" true "apt fix"; return 1; else print_color "$GREEN" " Purge done."; log_msg "INFO" "APT purge done."; fi; fi

    print_color "$CYAN" "Step 3: Cleaning configs..."; run_command "rm -f /etc/modprobe.d/blacklist-nvidia*.conf /etc/modprobe.d/nvidia*.conf /etc/X11/xorg.conf" false "Remove Configs"; print_color "$GREEN" " Configs removed."
    print_color "$CYAN" "Step 4: Cleaning APT caches..."; run_command "rm -rf /var/lib/apt/lists/* && apt clean" false "Clean APT Cache"; print_color "$GREEN" " Caches cleaned."
    print_color "$CYAN" "Step 5: Rebuilding initramfs..."; if run_command "update-initramfs -u -k all" true "Update Initramfs Clean"; then print_color "$GREEN" " Initramfs updated."; else log_msg "ERROR" "initramfs failed!"; fi
    print_color "$GREEN" "\n--- NVIDIA Deep Clean Complete ---"; print_color "$YELLOW" "Reboot recommended."; log_msg "INFO" "Clean module finished."; return 0
}

run_nvidia_install() {
    print_color "$PURPLE" "\n--- Module: NVIDIA Driver Install ---"; log_msg "INFO" "Starting Driver Install.";
    print_color "$CYAN" "Pre-flight checks..."; if ! run_prepare_build_env; then log_msg "ERROR" "Aborting: Build env prep failed."; return 1; fi;
    local sb_stat; sb_stat=$(mokutil --sb-state 2>/dev/null || echo "Unknown"); log_msg "INFO" "Secure Boot: $sb_stat"; print_color "$CYAN" " Secure Boot: $sb_stat"; if [[ "$sb_stat" == "SecureBoot enabled" ]]; then print_color "$RED" " ERROR: Secure Boot ENABLED."; log_msg "ERROR" "Secure Boot enabled."; if ! prompt_confirm "Disable in BIOS? (Y=Exit / n=Continue - FAIL LIKELY)"; then log_msg "WARN" "Continuing with SB enabled."; else return 1; fi; fi

    local driver_ver=""; local method=""
    while true; do print_color "$YELLOW" "\nSelect driver version:"; echo " 1) 535 (Stable)"; echo " 2) 550 (Newer)"; echo " 3) 570 (Latest, maybe)"; read -r -p "$(print_color "$YELLOW" "Choice: ")" choice < /dev/tty; case "$choice" in 1) driver_ver="535"; break;; 2) driver_ver="550"; break;; 3) driver_ver="570"; break;; *) print_color "$RED" "Invalid.";; esac; done; log_msg "USER" "Selected driver: $driver_ver"
    while true; do print_color "$YELLOW" "\nSelect method:"; echo " 1) APT (Recommended)"; echo " 2) Runfile ($USER_HOME)"; echo " 3) APT - Nvidia Repo Only"; read -r -p "$(print_color "$YELLOW" "Choice: ")" choice < /dev/tty; case "$choice" in 1) method="apt_ubuntu"; break;; 2) method="runfile"; break;; 3) method="apt_nvidia"; break;; *) print_color "$RED" "Invalid.";; esac; done; log_msg "USER" "Selected method: $method"

    local status=1; if [[ "$method" == "apt_ubuntu" ]]; then install_nvidia_apt "$driver_ver"; status=$?; elif [[ "$method" == "apt_nvidia" ]]; then install_nvidia_apt_official_repo "$driver_ver"; status=$?; elif [[ "$method" == "runfile" ]]; then install_nvidia_runfile; status=$?; else log_msg "ERROR" "Invalid method: $method"; fi
    if [[ $status -eq 0 ]]; then print_color "$GREEN" "\n--- Driver Install Complete ---"; print_color "$YELLOW" "Reboot REQUIRED."; print_color "$CYAN" "Verify with 'nvidia-smi' after reboot."; log_msg "INFO" "Driver install success."; else print_color "$RED" "\n--- Driver Install Failed ---"; log_msg "ERROR" "Driver install failed."; fi
    return $status
}

install_nvidia_apt() {
    local ver="$1"; local pkg="nvidia-driver-$ver"
    print_color "$CYAN" "\nStarting Standard APT install: $pkg"; log_msg "INFO" "Starting APT install: $pkg"
    if ! check_tty; then return 1; fi
    local dm; dm=$(get_display_manager); if [[ -n "$dm" ]]; then run_command "systemctl stop $dm" false "Stop DM" || print_color "$YELLOW" "Warn: Stop DM failed."; fi
    run_command "apt update" false "Update before driver" || print_color "$YELLOW" "Warn: apt update failed."
    print_color "$CYAN" "Installing $pkg...";
    if run_command "apt install $pkg -y" false "Install $pkg"; then # Log only status, not full output here
        log_msg "INFO" "APT install cmd finished ok."; print_color "$CYAN" "Verifying DKMS..."; log_msg "INFO" "Verifying DKMS..."; sleep 2; local dkms_out; dkms_out=$(dkms status); log_msg "INFO" "DKMS Status: $dkms_out";
        if echo "$dkms_out" | grep -q "nvidia/${ver}" || echo "$dkms_out" | grep -q "nvidia/" | grep -q "${ver}\."; then print_color "$GREEN" "DKMS built ok."; log_msg "INFO" "DKMS PASSED."; return 0;
        else print_color "$RED" "ERROR: DKMS module NOT found!"; log_msg "ERROR" "DKMS FAILED."; print_color "$YELLOW" "Check logs (Option 11 -> 2)."; return 1; fi
    else log_msg "ERROR" "apt install $pkg failed."; print_color "$YELLOW" "Attempting fix..."; run_command "dpkg --configure -a" false "dpkg cfg"; run_command "apt-get install -f -y" true "apt fix"; return 1; fi
}

install_nvidia_apt_official_repo() {
    local ver="$1" # Version might be handled by cuda-drivers, or nvidia-driver-XXX needed? Let's use cuda-drivers as per docs.
    print_color "$CYAN" "\nStarting Nvidia Repo APT install (using 'cuda-drivers')..."; log_msg "INFO" "Starting Nvidia Repo APT install."
    if ! check_tty; then return 1; fi
    local dm; dm=$(get_display_manager); if [[ -n "$dm" ]]; then run_command "systemctl stop $dm" false "Stop DM" || print_color "$YELLOW" "Warn: Stop DM failed."; fi

    print_color "$CYAN" "Ensuring Nvidia repo keyring is installed..."; log_msg "INFO" "Checking/Installing cuda-keyring."
    if ! dpkg-query -W -f='${Status}' cuda-keyring 2>/dev/null | grep -q "ok installed"; then
        if prompt_confirm "'cuda-keyring' not found. Attempt to download and install?"; then
             if ! run_command "wget https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2204/x86_64/cuda-keyring_1.1-1_all.deb -O /tmp/cuda-keyring.deb" false "Download Keyring"; then log_msg "ERROR" "Keyring download failed."; return 1; fi
             if ! run_command "dpkg -i /tmp/cuda-keyring.deb" true "Install Keyring"; then log_msg "ERROR" "Keyring install failed."; rm -f /tmp/cuda-keyring.deb; return 1; fi
             rm -f /tmp/cuda-keyring.deb
        else log_msg "USER" "Skipped keyring install."; return 1; fi
    else log_msg "INFO" "cuda-keyring already installed."; fi

    run_command "apt update" false "Update after keyring" || print_color "$YELLOW" "Warn: apt update failed."
    print_color "$CYAN" "Installing 'cuda-drivers' meta-package..."; log_msg "EXEC" "apt install cuda-drivers -y"
    if run_command "apt install cuda-drivers -y" true "Install cuda-drivers"; then
        log_msg "INFO" "APT cuda-drivers install cmd finished ok."; print_color "$CYAN" "Verifying DKMS..."; log_msg "INFO" "Verifying DKMS..."; sleep 2; local dkms_out; dkms_out=$(dkms status); log_msg "INFO" "DKMS Status: $dkms_out";
        # Check for *any* installed nvidia module, as cuda-drivers version might vary
        if echo "$dkms_out" | grep -q "nvidia/"; then print_color "$GREEN" "DKMS module built."; log_msg "INFO" "DKMS check PASSED."; return 0;
        else print_color "$RED" "ERROR: DKMS module NOT found!"; log_msg "ERROR" "DKMS check FAILED."; return 1; fi
    else
        log_msg "ERROR" "apt install cuda-drivers failed."; print_color "$YELLOW" "Attempting fix..."; run_command "dpkg --configure -a" false "dpkg cfg"; run_command "apt-get install -f -y" true "apt fix"; return 1;
    fi
}

install_nvidia_runfile() {
    local runfile_opts=(); declare -A runfile_map; local count=1; print_color "$CYAN" "\nSearching driver .run files in $USER_HOME..."; log_msg "INFO" "Searching runfiles in $USER_HOME."
    while IFS= read -r -d $'\0' f; do local bn; bn=$(basename "$f"); if [[ "$bn" != "cuda_"* ]]; then runfile_opts+=("$bn"); runfile_map[$count]="$bn"; ((count++)); fi; done < <(find "$USER_HOME" -maxdepth 1 -name 'NVIDIA-Linux-x86_64-*.run' -print0)
    if [[ ${#runfile_opts[@]} -eq 0 ]]; then print_color "$RED" "No driver .run files found in $USER_HOME."; log_msg "ERROR" "No driver runfiles found."; return 1; fi
    print_color "$YELLOW" "Select driver runfile:"; for i in "${!runfile_map[@]}"; do echo " $i) ${runfile_map[$i]}" >&2; done; local choice; local chosen_rn=""
    while [[ -z "$chosen_rn" ]]; do read -r -p "$(print_color "$YELLOW" "Choice: ")" choice < /dev/tty; if [[ "$choice" =~ ^[0-9]+$ && -v "runfile_map[$choice]" ]]; then chosen_rn="${runfile_map[$choice]}"; else print_color "$RED" "Invalid."; fi; done
    local runfile_path="$USER_HOME/$chosen_rn"; log_msg "USER" "Selected Runfile: $runfile_path"
    print_color "$CYAN" "\nStarting Runfile install: $chosen_rn..."; chmod +x "$runfile_path" || { log_msg "ERROR" "chmod failed"; return 1; }
    if ! check_tty; then return 1; fi
    local dm; dm=$(get_display_manager); if [[ -n "$dm" ]]; then run_command "systemctl stop $dm" false "Stop DM" || print_color "$YELLOW" "Warn: Stop DM failed."; fi
    print_color "$YELLOW" "Ensure Build Env (Menu 2) & Nouveau blacklist (Menu 7) are done.";
    print_color "$YELLOW" "Also ensure correct GCC is default or use 'export CC=/path/to/gcc-ver' before running script if build fails."
    print_color "$CYAN" "Running installer with --dkms flag (will ask questions)..."
    log_msg "EXEC" "$runfile_path --dkms"
    # Run interactively
    if "$runfile_path" --dkms; then
        local run_status=$?; log_msg "INFO" "Runfile finished status: $run_status.";
        if [[ $run_status -eq 0 ]]; then
            print_color "$CYAN" "Verifying DKMS..."; log_msg "INFO" "Verifying DKMS..."; sleep 2; local ver; ver=$(echo "$chosen_rn" | grep -oP '[0-9]+\.[0-9]+\.[0-9]+'); local dkms_out; dkms_out=$(dkms status); log_msg "INFO" "DKMS Status: $dkms_out";
            if echo "$dkms_out" | grep -q "nvidia/${ver}"; then print_color "$GREEN" "DKMS module built."; log_msg "INFO" "DKMS check PASSED."; return 0;
            else print_color "$RED" "ERROR: DKMS module NOT found!"; log_msg "ERROR" "DKMS check FAILED."; return 1; fi
        else print_color "$RED" "ERROR: Runfile installer failed! Status: $run_status"; return $run_status; fi
    else
        local run_status=$?; log_msg "ERROR" "Runfile installer failed. Status: $run_status."; print_color "$YELLOW" "Check /var/log/nvidia-installer.log"; if [[ -n "$dm" ]]; then run_command "systemctl start $dm" false "Start DM after fail" || print_color "$YELLOW" "Failed restart DM."; fi; return $run_status;
    fi
}

# --- Module: CUDA Toolkit Install ---
run_cuda_install() {
    print_color "$PURPLE" "\n--- Module: CUDA Toolkit Install ---"; log_msg "INFO" "Starting CUDA Install."
    print_color "$YELLOW" "Verifying active NVIDIA Driver..."; log_msg "INFO" "Checking nvidia-smi..."; local smi_out; smi_out=$(nvidia-smi 2>&1); local smi_st=$?; if [[ $smi_st -ne 0 ]]; then log_msg "WARN" "nvidia-smi failed. Status: $smi_st"; print_color "$RED" "WARN: nvidia-smi failed. Driver inactive?"; if ! prompt_confirm "Continue anyway (NOT Recommended)?"; then return 1; fi; else print_color "$GREEN" "nvidia-smi passed."; log_msg "INFO" "nvidia-smi passed."; local drv_ver; drv_ver=$(echo "$smi_out" | grep 'Driver Version:' | awk '{print $3}'); log_msg "INFO" "Active driver: $drv_ver"; print_color "$CYAN" "Active driver: $drv_ver"; fi
    local method=""; local cuda_runfile="$USER_HOME/cuda_12.2.2_535.104.05_linux.run"
    while true; do print_color "$YELLOW" "\nSelect CUDA install method:"; echo "  1) APT ('cuda-toolkit')"; echo "  2) Runfile ($cuda_runfile)"; read -r -p "$(print_color "$YELLOW" "Choice: ")" choice < /dev/tty; case "$choice" in 1) method="apt"; break;; 2) method="runfile"; break;; *) print_color "$RED" "Invalid.";; esac; done; log_msg "USER" "Selected CUDA method: $method"
    if [[ "$method" == "apt" ]]; then
        print_color "$CYAN" "\nInstalling CUDA via APT..."; log_msg "INFO" "Starting CUDA APT install."
        run_command "apt update" false "Update before CUDA" || print_color "$YELLOW" "Warn: apt update failed."; print_color "$CYAN" "Installing cuda-toolkit...";
        if run_command "apt install cuda-toolkit -y" true "Install CUDA Toolkit APT"; then
            log_msg "INFO" "CUDA APT install finished."; print_color "$GREEN" "CUDA APT install finished."; print_color "$CYAN" "Verifying nvcc..."; log_msg "INFO" "Verifying nvcc..."; local nvcc_path; nvcc_path=$(command -v nvcc || echo "/usr/local/cuda/bin/nvcc");
            if [[ -x "$nvcc_path" ]]; then local nvcc_ver; nvcc_ver=$("$nvcc_path" --version | grep 'release'); print_color "$GREEN" "nvcc found: $nvcc_ver"; log_msg "INFO" "nvcc PASSED: $nvcc_ver"; else print_color "$YELLOW" "nvcc not found. Update PATH."; log_msg "WARN" "nvcc check FAILED."; fi; print_color "$YELLOW" "Update PATH/LD_LIBRARY_PATH in ~/.bashrc if needed."; return 0;
        else log_msg "ERROR" "apt install cuda-toolkit failed."; return 1; fi
    elif [[ "$method" == "runfile" ]]; then
        print_color "$CYAN" "\nInstalling CUDA via Runfile ($cuda_runfile)..."; log_msg "INFO" "Starting CUDA Runfile install: $cuda_runfile"
        if [[ ! -f "$cuda_runfile" ]]; then log_msg "ERROR" "CUDA Runfile not found."; return 1; fi; chmod +x "$cuda_runfile" || { log_msg "ERROR" "chmod CUDA runfile failed"; return 1; }
        if ! check_tty; then return 1; fi; local dm; dm=$(get_display_manager); if [[ -n "$dm" ]]; then run_command "systemctl stop $dm" false "Stop DM for CUDA runfile" || print_color "$YELLOW" "Warn: Stop DM failed."; fi
        print_color "$YELLOW" "Recommended flags: --toolkit --no-opengl-libs"; local flags="--toolkit --no-opengl-libs"
        if ! prompt_confirm "Use recommended flags ($flags)? (N = Interactive)"; then flags=""; log_msg "USER" "Chose interactive CUDA runfile."; else log_msg "USER" "Chose recommended CUDA flags."; fi
        print_color "$CYAN" "Running CUDA Runfile..."; log_msg "EXEC" "$cuda_runfile $flags";
        if run_command "\"$cuda_runfile\" $flags" false "Run CUDA Installer"; then
            log_msg "INFO" "CUDA Runfile finished ok."; print_color "$GREEN" "CUDA Runfile finished."; print_color "$CYAN" "Verifying nvcc..."; log_msg "INFO" "Verifying nvcc..."; local nvcc_path="/usr/local/cuda/bin/nvcc";
            if [[ -x "$nvcc_path" ]]; then local nvcc_ver; nvcc_ver=$("$nvcc_path" --version | grep 'release'); print_color "$GREEN" "nvcc found: $nvcc_ver"; log_msg "INFO" "nvcc PASSED: $nvcc_ver"; else print_color "$YELLOW" "nvcc not found. Update PATH/LD_LIB."; log_msg "WARN" "nvcc FAILED."; fi; print_color "$YELLOW" "Update PATH/LD_LIBRARY_PATH in ~/.bashrc if needed."; return 0;
        else log_msg "ERROR" "CUDA Runfile failed."; print_color "$YELLOW" "Check /var/log/nvidia-installer.log"; if [[ -n "$dm" ]]; then run_command "systemctl start $dm" false "Start DM after CUDA fail" || print_color "$YELLOW" "Failed restart DM."; fi; return 1; fi
    fi
}

# --- Module: GRUB Fix ---
run_grub_fix() {
    print_color "$PURPLE" "\n--- Module: GRUB Configuration Fix ---"; log_msg "INFO" "Starting GRUB Fix."
    local grub_def="/etc/default/grub"; local grub_bak="/etc/default/grub.backup.$(date +%s)"; local cfg=""; local cfg_name=""
    print_color "$YELLOW" "Select GRUB action:"; echo " 1) Apply Standard Default"; echo " 2) Apply Verbose Boot"; echo " 3) Apply Failsafe (nomodeset)"; echo " 4) Apply Nvidia DRM Modeset Param"; echo " 5) Reinstall GRUB (EFI)"; echo " 6) Cancel"
    read -r -p "$(print_color "$YELLOW" "Choice [1-6]: ")" choice < /dev/tty
    case "$choice" in
        1) cfg_name="Standard"; cfg=$(cat <<'GRUBEOF'
GRUB_DEFAULT=0
GRUB_TIMEOUT_STYLE=hidden
GRUB_TIMEOUT=5
GRUB_DISTRIBUTOR=`lsb_release -i -s 2> /dev/null || echo Debian`
GRUB_CMDLINE_LINUX_DEFAULT="quiet splash"
GRUB_CMDLINE_LINUX=""
GRUBEOF
) ;;
        2) cfg_name="Verbose"; cfg=$(cat <<'GRUBEOF'
GRUB_DEFAULT=0
GRUB_TIMEOUT_STYLE=menu
GRUB_TIMEOUT=10
GRUB_DISTRIBUTOR=`lsb_release -i -s 2> /dev/null || echo Debian`
GRUB_CMDLINE_LINUX_DEFAULT=""
GRUB_CMDLINE_LINUX=""
GRUB_TERMINAL=console
GRUBEOF
) ;;
        3) cfg_name="Failsafe (nomodeset)"; cfg=$(cat <<'GRUBEOF'
GRUB_DEFAULT=0
GRUB_TIMEOUT_STYLE=menu
GRUB_TIMEOUT=10
GRUB_DISTRIBUTOR=`lsb_release -i -s 2> /dev/null || echo Debian`
GRUB_CMDLINE_LINUX_DEFAULT="nomodeset"
GRUB_CMDLINE_LINUX=""
GRUB_TERMINAL=console
GRUBEOF
) ;;
        4) cfg_name="Std + Nvidia DRM Modeset"; cfg=$(cat <<'GRUBEOF'
GRUB_DEFAULT=0
GRUB_TIMEOUT_STYLE=hidden
GRUB_TIMEOUT=5
GRUB_DISTRIBUTOR=`lsb_release -i -s 2> /dev/null || echo Debian`
GRUB_CMDLINE_LINUX_DEFAULT="quiet splash nvidia-drm.modeset=1" # Added nvidia-drm.modeset=1
GRUB_CMDLINE_LINUX=""
GRUBEOF
) ;;
        5) print_color "$CYAN" "Selected: Reinstall GRUB (EFI)."; log_msg "USER" "Selected GRUB Reinstall."
           if prompt_confirm "Run 'grub-install --recheck'? (Check EFI mount if chrooted)"; then
               if run_command "grub-install --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id=ubuntu --recheck" true "grub-install"; then
                   log_msg "INFO" "grub-install ok."; print_color "$CYAN" "Running update-grub...";
                   if run_command "update-grub" true "update-grub"; then log_msg "INFO" "update-grub ok."; return 0; else log_msg "ERROR" "update-grub failed."; return 1; fi
               else log_msg "ERROR" "grub-install failed."; return 1; fi
           else log_msg "USER" "Cancelled GRUB reinstall."; return 1; fi ;;
        *) print_color "$YELLOW" "Cancelled."; log_msg "USER" "Cancelled GRUB fix."; return 1 ;;
    esac
    if [[ -n "$cfg" ]]; then
        print_color "$CYAN" "\nSelected Config: $cfg_name"; print_color "$PURPLE" "--- Config ---"; print_color "$CYAN"; NO_TYPE_EFFECT=1 type_effect "$cfg"; print_color "$PURPLE" "--------------"; log_msg "INFO" "Applying GRUB cfg: $cfg_name"
        if prompt_confirm "Apply this to $grub_def?"; then
            print_color "$YELLOW" "Backing up to $grub_bak..."; if ! run_command "cp -a \"$grub_def\" \"$grub_bak\"" false "Backup GRUB"; then log_msg "ERROR" "Backup failed."; return 1; fi
            print_color "$CYAN" "Writing config..."; if echo "$cfg" | tee "$grub_def" > /dev/null; then
                log_msg "INFO" "Wrote config ok."; print_color "$CYAN" "Running update-grub...";
                if run_command "update-grub" true "update-grub after config"; then print_color "$GREEN" "GRUB updated."; log_msg "INFO" "GRUB updated ok."; return 0;
                else log_msg "ERROR" "update-grub failed."; print_color "$YELLOW" "Restore backup: sudo cp $grub_bak $grub_def && sudo update-grub"; return 1; fi
            else log_msg "ERROR" "Write failed."; return 1; fi
        else log_msg "USER" "Cancelled GRUB apply."; return 1; fi
    fi; return 0;
}

# --- Module: Kernel Fix ---
run_kernel_fix() {
    print_color "$PURPLE" "\n--- Module: Kernel Reset ---"; log_msg "INFO" "Starting Kernel Reset."
    print_color "$YELLOW" "Removes & reinstalls a kernel. RUN FROM A DIFFERENT WORKING KERNEL."
    local current_k; current_k=$(uname -r); log_msg "INFO" "Current kernel: $current_k"; print_color "$CYAN" "Current kernel: $current_k"
    print_color "$CYAN" "Identifying installed kernels..."; local klist_f; klist_f=$(mktemp); dpkg -l | grep -E '^ii.*linux-image-[0-9]' | grep -v 'unsigned' | awk '{print $2}' | sort -V > "$klist_f"; log_msg "INFO" "Kernel list: $klist_f"
    if ! [[ -s "$klist_f" ]]; then print_color "$RED" "ERROR: No kernels found!"; log_msg "ERROR" "No kernels listed."; rm "$klist_f"; return 1; fi
    print_color "$YELLOW" "Installed kernel images:"; cat "$klist_f" | sed 's/^/  /' >&2; echo "" >&2; local k_ver=""; local k_base=""
    while true; do read -r -p "$(print_color "$YELLOW" "Enter kernel version to fix (e.g., 6.8.0-57-generic): ")" k_ver < /dev/tty; k_base="linux-image-${k_ver}"; if grep -q "$k_base" "$klist_f"; then if [[ "$k_ver" == "$current_k" ]]; then print_color "$RED" "Cannot remove running kernel!"; log_msg "WARN" "Tried removing running kernel."; else kernel_to_fix="$k_ver"; break; fi; else print_color "$RED" "Kernel not found."; fi; done
    rm "$klist_f"; log_msg "USER" "Selected kernel fix: $kernel_to_fix"
    print_color "$RED" "\nWARNING: Will PURGE $kernel_to_fix packages & reinstall."
    if ! prompt_confirm "Sure? Booted from $current_k"; then log_msg "USER" "Cancelled kernel fix."; return 1; fi
    print_color "$CYAN" "Step 1: Purging $kernel_to_fix..."; local purge_pkgs="linux-image-${kernel_to_fix} linux-headers-${kernel_to_fix} linux-modules-${kernel_to_fix} linux-modules-extra-${kernel_to_fix}";
    if run_command "apt-get purge --autoremove -y $purge_pkgs" true "Purge Kernel $kernel_to_fix"; then log_msg "INFO" "Kernel purged ok."; else log_msg "ERROR" "Kernel purge failed."; print_color "$YELLOW" "Attempting fix..."; run_command "dpkg --configure -a" false "dpkg configure"; run_command "apt-get install -f -y" true "apt fix"; return 1; fi
    print_color "$CYAN" "Step 2: Updating GRUB..."; run_command "update-grub" true "Update GRUB after purge" || log_msg "ERROR" "update-grub failed."
    print_color "$CYAN" "Step 3: Reinstalling $kernel_to_fix..."; local install_cmd="apt update && apt install -y linux-image-${kernel_to_fix} linux-headers-${kernel_to_fix}"
    # Re-add HWE metapackage install here for convenience
    install_cmd+=" && apt install -y linux-generic-hwe-22.04"
    if run_command "$install_cmd" true "Reinstall Kernel $kernel_to_fix + HWE"; then log_msg "INFO" "Kernel reinstall ok."; else log_msg "ERROR" "Kernel reinstall failed."; return 1; fi
    print_color "$GREEN" "\n--- Kernel Reset Complete ---"; print_color "$YELLOW" "Reboot required to test '$kernel_to_fix'."; log_msg "INFO" "Kernel Reset finished."; return 0
}

# --- Module: Chroot Helper ---
run_chroot_helper() {
    print_color "$PURPLE" "\n--- Module: Chroot Helper (Live OS ONLY) ---"; log_msg "INFO" "Starting Chroot Helper."; print_color "$YELLOW" "Mounts system & enters chroot from Live OS."
    if mountpoint -q /cdrom || grep -q -E 'casper|toram|live' /proc/cmdline; then log_msg "INFO" "Live OS detected."; else print_color "$RED" "Error: Use from Live OS."; log_msg "ERROR" "Not Live OS?"; if ! prompt_confirm "Continue anyway?"; then return 1; fi; fi
    local root_part=""; local efi_part=""; local mount_p="/mnt/system"; local binds=( "/dev" "/dev/pts" "/proc" "/sys" )
    print_color "$CYAN" "\nNeed partitions."; lsblk -f >&2; while true; do read -r -p "$(print_color "$YELLOW" "ROOT partition: ")" root_part < /dev/tty; if [[ -b "$root_part" ]]; then break; else print_color "$RED" "Invalid."; fi; done; while true; do read -r -p "$(print_color "$YELLOW" "EFI partition: ")" efi_part < /dev/tty; if [[ -b "$efi_part" ]]; then break; else print_color "$RED" "Invalid."; fi; done; log_msg "USER" "Root: $root_part, EFI: $efi_part."
    print_color "$CYAN" "Unmounting previous..."; umount -R "$mount_p" &>/dev/null; print_color "$CYAN" "Mounting..."; mkdir -p "$mount_p/boot/efi" || { log_msg "ERROR" "mkdir fail"; return 1; }
    mount "$root_part" "$mount_p" || { log_msg "ERROR" "mount root fail"; return 1; }; mount "$efi_part" "$mount_p/boot/efi" || { log_msg "ERROR" "mount efi fail"; umount "$mount_p"; return 1; }
    print_color "$CYAN" "Binding..."; local bind_f=0; for p in "${binds[@]}"; do if ! mount --bind "$p" "$mount_p$p"; then log_msg "ERROR" "Bind $p fail"; bind_f=1; print_color "$RED" " ERROR: Bind $p fail!"; fi; done; if [[ $bind_f -eq 1 ]]; then print_color "$YELLOW" "Bind fails. Chroot incomplete."; else print_color "$GREEN" "Binds ok."; fi
    print_color "$CYAN" "Copying DNS..."; if cp --dereference /etc/resolv.conf "$mount_p/etc/resolv.conf"; then print_color "$GREEN" "DNS ok."; else log_msg "WARN" "DNS copy fail."; print_color "$YELLOW" "Warn: DNS copy fail."; fi
    print_color "$GREEN" "\nSystem mounted."; print_color "$YELLOW" "Entering chroot. Type 'exit' when done."; read -r -p "$(print_color "$YELLOW" "Press Enter...")" < /dev/tty
    log_msg "EXEC" "chroot $mount_p /bin/bash"; chroot "$mount_p" /bin/bash; local chroot_st=$?; log_msg "INFO" "Exited chroot status $chroot_st."
    print_color "$PURPLE" "\n--- Exited Chroot ---"; print_color "$YELLOW" "UNMOUNT MANUALLY:"; print_color "$CYAN" " sudo umount -R $mount_p"; return 0
}

# --- Module: View Logs ---
run_view_logs() {
    print_color "$PURPLE" "\n--- Module: Log Viewer ---"; log_msg "INFO" "Starting Log Viewer."
    while true; do
        print_color "$GREEN" "\nSelect log to view:"
        echo " 1) Nvidia Installer Log (/var/log/nvidia-installer.log)"; echo " 2) DKMS Build Logs (Latest nvidia)"; echo " 3) APT History Log (/var/log/apt/history.log)"; echo " 4) APT Terminal Log (/var/log/apt/term.log)"; echo " 5) Xorg Log (/var/log/Xorg.0.log)"; echo " 6) Xorg Log (Previous) (/var/log/Xorg.0.log.old)"; echo " 7) Journalctl - Current Boot Errors"; echo " 8) Journalctl - Previous Boot Errors"; echo " 9) Journalctl - Kernel Messages"; echo "10) This Script's Main Log ($MAIN_LOG_FILE)"; echo "11) Back to Main Menu";
        local choice; read -r -p "$(print_color "$YELLOW" "Choice [1-11]: ")" choice < /dev/tty
        case "$choice" in
            1) view_log_file "/var/log/nvidia-installer.log" "Nvidia Installer";;
            2) local latest_dkms; local k_v; k_v=$(uname -r); latest_dkms=$(find /var/lib/dkms/nvidia/ -name "make.log" -path "*/${k_v}/*" -printf "%T@ %p\n" 2>/dev/null | sort -nr | head -n 1 | cut -d' ' -f2-); if [[ -z "$latest_dkms" ]]; then latest_dkms=$(find /var/lib/dkms/nvidia/ -name "make.log" -printf "%T@ %p\n" 2>/dev/null | sort -nr | head -n 1 | cut -d' ' -f2-); fi; if [[ -n "$latest_dkms" ]]; then view_log_file "$latest_dkms" "DKMS Build"; else print_color "$YELLOW" "No DKMS logs found."; log_msg "WARN" "No DKMS logs."; read -r -p "$(print_color "$YELLOW" "Enter...")" < /dev/tty; fi ;;
            3) view_log_file "/var/log/apt/history.log" "APT History";;
            4) view_log_file "/var/log/apt/term.log" "APT Terminal";;
            5) view_log_file "/var/log/Xorg.0.log" "Xorg";;
            6) view_log_file "/var/log/Xorg.0.log.old" "Xorg Prev";;
            7) print_color "$CYAN" "Showing current errors (use Q to quit)..."; journalctl -b -p err < /dev/tty ;; # Pipe directly to pager
            8) print_color "$CYAN" "Showing previous errors (use Q to quit)..."; journalctl -b -1 -p err < /dev/tty ;;
            9) print_color "$CYAN" "Showing kernel messages (use Q to quit)..."; journalctl -k < /dev/tty ;;
           10) view_log_file "$MAIN_LOG_FILE" "Script Log";;
           11) log_msg "INFO" "Exiting Log Viewer."; break;; *) print_color "$RED" "Invalid." ;;
        esac; done; return 0;
}

# --- Prep Submenu ---
run_prep_submenu() {
     while true; do
         if command -v tput &> /dev/null; then tput clear; else clear; fi >&2
         print_color "$PURPLE" "\n=== Prep & Check Submenu ==="
         echo "  $(print_color "$CYAN" "1)") Manage Display Manager (Stop/Start/Status)"
         echo "  $(print_color "$CYAN" "2)") Prepare Build Environment (DKMS, Headers, Tools)"
         echo "  $(print_color "$CYAN" "3)") Manage GCC Version (Check, Install 12, Show Switch Cmds)"
         echo "  $(print_color "$CYAN" "4)") Return to Main Menu"
         local choice
         read -r -p "$(print_color "$YELLOW" "Enter choice [1-4]: ")" choice < /dev/tty
         case "$choice" in
             1) run_manage_display_manager ;;
             2) run_prepare_build_env ;;
             3) run_manage_gcc ;;
             4) break;; # Exit submenu loop
             *) print_color "$RED" "Invalid selection.";;
         esac
         local last_status=$?
         if [[ "$choice" -ge 1 && "$choice" -le 3 ]]; then # Only pause if an action ran
             if [[ $last_status -ne 0 ]]; then print_color "$YELLOW" "\nSub-module finished with errors (status $last_status)."; else print_color "$GREEN" "\nSub-module finished successfully."; fi
             read -r -p "$(print_color "$YELLOW" "\nPress Enter to return to submenu...")" < /dev/tty
         fi
    done
    return 0
}


# --- Main Menu ---
main_menu() {
    print_color "$PURPLE" "\n=== $(print_color "$GREEN" "NVIDIA") $(print_color "$CYAN" "MyBitch") $(print_color "$PURPLE" "Manager") v$SCRIPT_VERSION ==="
    print_color "$GREEN" "Select an operation:"
    echo "  $(print_color "$CYAN" " 1)") Prep / Check Environment (DM, DKMS, GCC)" # New Submenu
    echo "  $(print_color "$CYAN" " 2)") NVIDIA Deep Clean (Purge drivers/CUDA)"
    echo "  $(print_color "$CYAN" " 3)") NVIDIA Driver Install (APT or Runfile)"
    echo "  $(print_color "$CYAN" " 4)") Install CUDA Toolkit (APT or Runfile)"
    echo "  $(print_color "$CYAN" " 5)") Blacklist Nouveau Driver"
    echo "  $(print_color "$CYAN" " 6)") GRUB Fix / Reinstall / Params"
    echo "  $(print_color "$CYAN" " 7)") Kernel Reset (Remove & Reinstall)"
    echo "  $(print_color "$CYAN" " 8)") Chroot Helper (Live OS ONLY)"
    echo "  $(print_color "$CYAN" " 9)") View Logs (System, Nvidia, APT, etc.)"
    echo "  $(print_color "$CYAN" "10)") Exit"

    local choice
    read -r -p "$(print_color "$YELLOW" "Enter choice [1-10]: ")" choice < /dev/tty

    case "$choice" in
        1) run_prep_submenu ;; # Call new submenu
        2) run_nvidia_cleanup ;;
        3) run_nvidia_install ;;
        4) run_cuda_install ;;
        5) run_nouveau_blacklist ;;
        6) run_grub_fix ;;
        7) run_kernel_fix ;;
        8) run_chroot_helper ;;
        9) run_view_logs ;;
       10) print_color "$GREEN" "Keep hustlin'. Exiting..."; log_msg "INFO" "Exiting script."; exit 0 ;;
        *) print_color "$RED" "Invalid selection." ;;
    esac

    local last_status=$?
    if [[ "$choice" -ge 1 && "$choice" -le 10 ]]; then # Don't pause after invalid choice or exit
        if [[ $last_status -ne 0 ]]; then print_color "$YELLOW" "\nModule finished with errors (status $last_status). Check logs: $MAIN_LOG_FILE"; else print_color "$GREEN" "\nModule finished successfully."; fi
        read -r -p "$(print_color "$YELLOW" "\nPress Enter to return to menu...")" < /dev/tty
    fi
}

# --- Script Start ---
# Check sudo FIRST - it sets up USER_HOME and LOG paths
check_sudo

# Append to log file for history across runs
log_msg "INFO" "====== GPU Manager Started. Version $SCRIPT_VERSION ======"

# Main loop
while true; do
    if command -v tput &> /dev/null; then tput clear; else clear; fi >&2 # Clear screen
    main_menu
done
