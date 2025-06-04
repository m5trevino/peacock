#!/bin/bash

# --- FlintX GRUB Keymaster (v8 - ACTUALLY Fixed Ventoy Menu Generation) ---
# Auto-detects kernel/UUID, generates specific GRUB .cfg snippets
# on the local system, AND generates the Ventoy Menu Extension config
# pointing to those snippets using CORRECT GRUB syntax.

# --- Configuration ---
CONFIG_FILE="$HOME/.grub_keymaster_v8.conf" # New conf file name
DEFAULT_SNIPPET_DIR="/boot/grub_configs" # Default location for snippets on Debian
VENTOY_CONFIG_FILE_RELPATH="ventoy/ventoy_grub.cfg"
SNIPPET_BACKUP_DIR_RELPATH="backups"
VENTOY_BACKUP_DIR_RELPATH="ventoy/backups"
DEBIAN_DEFAULT_GRUB="/etc/default/grub"

# --- Helper Functions ---
prompt_yes_no() { local p="$1" d="${2:-N}" a; while true; do read -p "$p [Y/n]: " a; a="${a:-$d}"; if [[ "$a" =~ ^[Yy]$ ]]; then return 0; fi; if [[ "$a" =~ ^[Nn]$ ]]; then return 1; fi; echo "Please answer 'y' or 'n'."; done; }

# --- Load/Save/Prompt for Base Config (Paths) ---
load_base_config() { if [ -f "$CONFIG_FILE" ]; then source "$CONFIG_FILE"; if [ -z "$SAVED_SNIPPET_DIR" ] || [ -z "$SAVED_VENTOY_MOUNT" ]; then return 1; fi; if ! sudo test -d "$SAVED_VENTOY_MOUNT" || ! sudo test -d "$SAVED_SNIPPET_DIR"; then echo "[WARN] Saved paths invalid."; return 1; fi; return 0; fi; return 1; }
save_base_config() { local s="$1" v="$2"; echo "[INFO] Saving base settings..."; sudo touch "$CONFIG_FILE"; sudo chown "${SUDO_USER:-$(logname)}":"${SUDO_USER:-$(logname)}" "$CONFIG_FILE"; sudo chmod 600 "$CONFIG_FILE"; echo "# GK v8" | sudo tee "$CONFIG_FILE" > /dev/null; echo "SAVED_SNIPPET_DIR=\"$s\"" | sudo tee -a "$CONFIG_FILE" > /dev/null; echo "SAVED_VENTOY_MOUNT=\"$v\"" | sudo tee -a "$CONFIG_FILE" > /dev/null; echo "[INFO] Saved."; }
prompt_base_config() {
    local vm=false; while [ "$vm" = false ]; do read -e -p "Ventoy USB Mount Path: " VENTOY_MOUNT_POINT; VENTOY_MOUNT_POINT=$(eval echo "$VENTOY_MOUNT_POINT"); if [ -d "$VENTOY_MOUNT_POINT" ]; then vm=true; sudo mkdir -p "${VENTOY_MOUNT_POINT}/ventoy" || exit 1; echo "[OK] Ventoy: $VENTOY_MOUNT_POINT"; else echo "[ERR] Not found."; fi; done
    local vd=false; while [ "$vd" = false ]; do echo "[INFO] Recommended snippet location is /boot/grub_configs for GRUB."; read -e -p "Debian Snippet Dir [Default: ${DEFAULT_SNIPPET_DIR}]: " SNIPPET_DIR; SNIPPET_DIR="${SNIPPET_DIR:-$DEFAULT_SNIPPET_DIR}"; SNIPPET_DIR=$(eval echo "$SNIPPET_DIR"); if [[ "$SNIPPET_DIR" != "/boot/"* ]] && [[ "$SNIPPET_DIR" != "/root/"* ]]; then echo "[WARN] Path is not in /boot or /root. Ensure GRUB can access it."; fi; if sudo mkdir -p "$SNIPPET_DIR"; then echo "[OK] Snippets: $SNIPPET_DIR"; vd=true; else echo "[ERR] Cannot create/access."; fi; done
    if prompt_yes_no "Save these paths for next time?"; then save_base_config "$SNIPPET_DIR" "$VENTOY_MOUNT_POINT"; fi
}

# --- Detect System Info (Kernel/UUID) ---
detect_system_info() { echo "[INFO] Detecting system info..."; DETECTED_UUID=$(findmnt -n -o UUID /); read -p "Debian Root UUID [${DETECTED_UUID:-Not Found}]: " FINAL_UUID; FINAL_UUID="${FINAL_UUID:-$DETECTED_UUID}"; if ! [[ "$FINAL_UUID" =~ ^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$ ]]; then echo "[ERR] Invalid UUID."; exit 1; fi; echo "[OK] Using UUID: $FINAL_UUID"; DETECTED_KERNEL_PATH=$(ls -t /boot/vmlinuz-* 2>/dev/null | grep -v 'rescue\|recovery\|old' | head -n 1); if [ -n "$DETECTED_KERNEL_PATH" ] && [ -f "$DETECTED_KERNEL_PATH" ]; then kernel_version=$(basename "$DETECTED_KERNEL_PATH" | sed 's/^vmlinuz-//'); DETECTED_INITRD_PATH=$(ls -t "/boot/initrd.img-${kernel_version}"* 2>/dev/null | head -n 1); if [ ! -f "$DETECTED_INITRD_PATH" ]; then DETECTED_INITRD_PATH=""; fi; else DETECTED_KERNEL_PATH=""; DETECTED_INITRD_PATH=""; fi; if [ -z "$DETECTED_KERNEL_PATH" ]; then echo "[WARN] No kernel detected."; read -e -p "Enter Kernel Path: " FINAL_KERNEL_PATH; read -e -p "Enter Initrd Path: " FINAL_INITRD_PATH; else echo " Detected Kernel: $DETECTED_KERNEL_PATH"; echo " Detected Initrd: $DETECTED_INITRD_PATH"; if ! prompt_yes_no "Use detected paths?"; then read -e -p "Enter Kernel Path: " FINAL_KERNEL_PATH; read -e -p "Enter Initrd Path: " FINAL_INITRD_PATH; else FINAL_KERNEL_PATH="$DETECTED_KERNEL_PATH"; FINAL_INITRD_PATH="$DETECTED_INITRD_PATH"; fi; fi; if ! sudo test -f "$FINAL_KERNEL_PATH" || ! sudo test -f "$FINAL_INITRD_PATH"; then echo "[ERR] Kernel/initrd invalid."; exit 1; fi; echo "[OK] Using Kernel: $FINAL_KERNEL_PATH"; echo "[OK] Using Initrd: $FINAL_INITRD_PATH"; export FINAL_UUID FINAL_KERNEL_PATH FINAL_INITRD_PATH; }

# --- Generate All Snippets (.cfg files) ---
generate_all_snippets() { local sdir="$1"; echo "[INFO] Generating snippets in ${sdir}..."; local bakdir="${sdir}/${SNIPPET_BACKUP_DIR_RELPATH}"; sudo mkdir -p "$bakdir"; if sudo ls "${sdir}"/*.cfg > /dev/null 2>&1; then echo " Backing up existing..."; local ts=$(date +%Y%m%d_%H%M%S); sudo mkdir -p "${bakdir}/bak_${ts}"; if sudo test -d "${bakdir}/bak_${ts}"; then sudo mv "${sdir}"/*.cfg "${bakdir}/bak_${ts}/"; fi; fi; gen() { echo " -> $1"; printf "%s" "$2" | sudo tee "${sdir}/$1" > /dev/null ; sudo chmod 644 "${sdir}/$1"; }; k="$FINAL_KERNEL_PATH"; i="$FINAL_INITRD_PATH"; u="$FINAL_UUID"; common="insmod gzio part_gpt ext2; search --no-floppy --fs-uuid --set=root ${u}"; linux_base="linux ${k} root=UUID=${u} ro"; initrd_base="initrd ${i}"; nd="nouveau.modeset=0 rd.driver.blacklist=nouveau modprobe.blacklist=nouveau"; # Generated snippets do NOT contain menuentry wrappers
    gen "debian_gui_nomodeset.cfg" "# SNIP: GUI Nomodeset\nload_video\n${common}\n${linux_base} nomodeset\n${initrd_base}"
    gen "debian_gui_nomodeset_noefifb.cfg" "# SNIP: GUI Nomodeset NoEFIFB\nload_video\n${common}\n${linux_base} nomodeset video=efifb:off\n${initrd_base}"
    gen "debian_gui_nouveau_quiet.cfg" "# SNIP: GUI Nouveau Quiet\n${common}\n${linux_base} quiet\n${initrd_base}"
    gen "debian_gui_nouveau_verbose.cfg" "# SNIP: GUI Nouveau Verbose\n${common}\n${linux_base}\n${initrd_base}"
    gen "debian_gui_nouveau_drm_debug.cfg" "# SNIP: GUI Nouveau DRM Debug\n${common}\n${linux_base} drm.debug=0x1e log_buf_len=10M\n${initrd_base}"
    gen "debian_gui_nvidia_quiet.cfg" "# SNIP: GUI Nvidia Quiet\n${common}\n${linux_base} quiet nvidia-drm.modeset=1\n${initrd_base}"
    gen "debian_gui_nvidia_verbose.cfg" "# SNIP: GUI Nvidia Verbose\n${common}\n${linux_base} nvidia-drm.modeset=1\n${initrd_base}"
    gen "debian_gui_nvidia_drm_debug.cfg" "# SNIP: GUI Nvidia DRM Debug\n${common}\n${linux_base} nvidia-drm.modeset=1 drm.debug=0x1e log_buf_len=10M\n${initrd_base}"
    gen "debian_gui_nvidia_intel_pstate_disabled.cfg" "# SNIP: GUI Nvidia No P-State\n${common}\n${linux_base} quiet nvidia-drm.modeset=1 intel_pstate=disable\n${initrd_base}"
    gen "debian_gui_nvidia_max_cstate_1.cfg" "# SNIP: GUI Nvidia Max C1\n${common}\n${linux_base} quiet nvidia-drm.modeset=1 processor.max_cstate=1 intel_idle.max_cstate=1\n${initrd_base}"
    gen "debian_gui_nvidia_pcie_aspm_off.cfg" "# SNIP: GUI Nvidia No ASPM\n${common}\n${linux_base} quiet nvidia-drm.modeset=1 pcie_aspm=off\n${initrd_base}"
    gen "debian_recovery_basic.cfg" "# SNIP: Recovery Basic\n${common}\n${linux_base} single\n${initrd_base}"
    gen "debian_recovery_nomodeset.cfg" "# SNIP: Recovery Nomodeset\nload_video\n${common}\n${linux_base} single nomodeset\n${initrd_base}"
    gen "debian_tty_debug.cfg" "# SNIP: TTY Debug\n${common}\n${linux_base} 3 ${nd} debug ignore_loglevel log_buf_len=10M\n${initrd_base}"
    gen "debian_tty_nomodeset_nouveau_disabled.cfg" "# SNIP: TTY Nomodeset ND\n${common}\n${linux_base} 3 nomodeset ${nd}\n${initrd_base}"
    gen "debian_tty_nouveau_disabled.cfg" "# SNIP: TTY ND\n${common}\n${linux_base} quiet 3 ${nd}\n${initrd_base}"
    gen "debian_tty_nouveau_enabled.cfg" "# SNIP: TTY Nouveau Enabled\n${common}\n${linux_base} quiet 3\n${initrd_base}"
    gen "debian_tty_nvidia.cfg" "# SNIP: TTY Nvidia Active\n${common}\n${linux_base} quiet 3 nvidia-drm.modeset=1\n${initrd_base}"
    gen "debian_tty_debug_sysrq.cfg" "# SNIP: TTY Debug SysRq\n${common}\n${linux_base} 3 ${nd} debug ignore_loglevel log_buf_len=10M sysrq_always_enabled=1\n${initrd_base}"
    gen "debian_gui_nvidia_quiet_sysrq.cfg" "# SNIP: GUI Nvidia Quiet SysRq\n${common}\n${linux_base} quiet nvidia-drm.modeset=1 sysrq_always_enabled=1\n${initrd_base}"
    echo "[INFO] Snippet generation complete.";
}


# --- Generate Ventoy Menu (ventoy_grub.cfg) - CORRECTED ---
generate_ventoy_menu() {
    local snippet_dir="$1"; local part_uuid="$2"; local ventoy_mount="$3"
    local ventoy_cfg_file="${ventoy_mount}/${VENTOY_CONFIG_FILE_RELPATH}"
    local ventoy_backup_dir="${ventoy_mount}/${VENTOY_BACKUP_DIR_RELPATH}"

    echo "[INFO] Starting generation of ${ventoy_cfg_file}..."
    sudo mkdir -p "$(dirname "$ventoy_cfg_file")"

    # Backup existing file
    if sudo test -f "$ventoy_cfg_file"; then
        echo "[INFO] Backing up existing $ventoy_cfg_file..."
        sudo mkdir -p "$ventoy_backup_dir"
        local backup_ts=$(date +%Y%m%d_%H%M%S)
        sudo cp "$ventoy_cfg_file" "${ventoy_backup_dir}/ventoy_grub_${backup_ts}.cfg.bak" || echo "[WARN] USB Backup failed."
    fi

    # Write new header (includes find_debian_root function)
    echo "[INFO] Writing new ${ventoy_cfg_file}..."
    local temp_cfg_file=$(mktemp)
    chmod 644 "$temp_cfg_file"

    cat << HEADER_EOF > "$temp_cfg_file"
# --- FlintX Custom Debian Loader (Generated: $(date)) ---
set timeout=30
set menu_color_normal=white/black
set menu_color_highlight=black/cyan
set pagination=1

set flintx_target_uuid="${part_uuid}"
set flintx_config_path="${snippet_dir}" # Store FULL path on Debian FS

# Function to find the target Partition
function find_debian_root {
    insmod part_gpt || true; insmod ext2 || true; # Load needed modules
    # Add other fs mods if needed: insmod btrfs || true; insmod xfs || true;
    if search --no-floppy --fs-uuid --set=debian_root "\${flintx_target_uuid}"; then
        # Optional: Check if the config dir actually exists relative to found root
        # if [ -d "(\$debian_root)\${flintx_config_path}" ]; then
            return 0
        # else
        #     echo "ERROR: Found partition but config path \${flintx_config_path} invalid relative to it!"
        #     sleep 10; return 1;
        # fi
    else
        echo "ERROR: Debian Root UUID \${flintx_target_uuid} NOT FOUND!"; sleep 10; return 1;
    fi
}
menuentry "--- FlintX Debian Boot Options (UUID: ${part_uuid:0:8}...) ---" --class=header {}
HEADER_EOF
    if [ $? -ne 0 ]; then echo "[ERROR] Failed writing header."; rm -f "$temp_cfg_file"; return 1; fi

    # Add menu entries directly for each .cfg file found
    local count=0
    local cfg_file_count=$(sudo ls -1 "${snippet_dir}"/*.cfg 2>/dev/null | wc -l)
    if [ "$cfg_file_count" -eq 0 ]; then
        echo "[WARN] No '.cfg' snippets found in ${snippet_dir}!"
        echo "menuentry \"(No .cfg files found in ${snippet_dir})\" { sleep 5 }" >> "$temp_cfg_file"
    else
        # Helper function to generate the literal menuentry text safely
        generate_menu_entry_text() {
            local menu_title="$1"; local cfg_filename="$2"; local entry_class="$3"
            # Use printf to handle potential special characters and required GRUB escaping
            printf '    menuentry "%s" --class %s {\n        find_debian_root\n        if [ \$? -eq 0 ]; then\n            # Construct path within GRUB using variables set above\n            local cfg_path_on_debian="%s"\n            local target_cfg="(\$debian_root)\${cfg_path_on_debian}/%s"\n            echo "Loading config: \${target_cfg}"\n            if [ -e "\${target_cfg}" ]; then\n                configfile "\${target_cfg}"\n                # Fallback boot command if configfile just returns\n                echo "Configfile returned, attempting boot..."\n                boot\n            else\n                 echo "ERROR: Snippet \${target_cfg} not found!"\n                 sleep 5\n            fi\n        fi\n        sleep 1\n    }\n' \
                "$menu_title" "$entry_class" "$flintx_config_path" "$cfg_filename"
        }

        # Define Submenus and add entries by piping printf output
        echo "submenu '--> [GUI] Standard Modes' --class=gui {" >> "$temp_cfg_file"
        sudo find "${snippet_dir}" -maxdepth 1 \( -name 'debian_gui_nouveau*.cfg' -o -name 'debian_gui_nvidia_quiet.cfg' -o -name 'debian_gui_nvidia_verbose.cfg' -o -name 'debian_gui_nvidia_quiet_sysrq.cfg' \) -print0 | while IFS= read -r -d $'\0' f; do
            fn=$(basename "$f"); mn=$(echo "$fn" | sed -e 's/\.cfg$//;s/debian_gui_//;s/_/ /g;s/\b\(.\)/\u\1/g'); cl="debian"; if [[ "$fn" == *"nvidia"* ]]; then cl="nvidia"; fi; if [[ "$fn" == *"debug"* ]]; then cl="debug"; fi
            generate_menu_entry_text "$mn" "$fn" "$cl" >> "$temp_cfg_file"; count=$((count + 1)); done
        echo "    menuentry '<-- Back' --class=vtoyret VTOY_RET {}" >> "$temp_cfg_file"; echo "}" >> "$temp_cfg_file"

        echo "submenu '--> [TTY] Text Modes' --class=tty {" >> "$temp_cfg_file"
        sudo find "${snippet_dir}" -maxdepth 1 \( -name 'debian_tty*.cfg' ! -name '*sysrq*.cfg' ! -name '*debug*.cfg' \) -print0 | while IFS= read -r -d $'\0' f; do
             fn=$(basename "$f"); mn=$(echo "$fn" | sed -e 's/\.cfg$//;s/debian_tty_//;s/_/ /g;s/\b\(.\)/\u\1/g'); cl="debian"; if [[ "$fn" == *"nvidia"* ]]; then cl="nvidia"; fi; if [[ "$fn" == *"nomodeset"* ]]; then cl="fallback"; fi
             generate_menu_entry_text "$mn" "$fn" "$cl" >> "$temp_cfg_file"; count=$((count + 1)); done
        echo "    menuentry '<-- Back' --class=vtoyret VTOY_RET {}" >> "$temp_cfg_file"; echo "}" >> "$temp_cfg_file"

        echo "submenu '--> [GFX] Fallback / Advanced' --class=fallback {" >> "$temp_cfg_file"
        sudo find "${snippet_dir}" -maxdepth 1 \( -name 'debian_gui_nomodeset*.cfg' -o -name 'debian_gui_nvidia_intel*.cfg' -o -name 'debian_gui_nvidia_max*.cfg' -o -name 'debian_gui_nvidia_pcie*.cfg' \) -print0 | while IFS= read -r -d $'\0' f; do
           fn=$(basename "$f"); mn=$(echo "$fn" | sed -e 's/\.cfg$//;s/debian_gui_//;s/_/ /g;s/\b\(.\)/\u\1/g'); cl="fallback"; if [[ "$fn" == *"nvidia"* ]]; then cl="nvidia"; fi
           generate_menu_entry_text "$mn" "$fn" "$cl" >> "$temp_cfg_file"; count=$((count + 1)); done
        echo "    menuentry '<-- Back' --class=vtoyret VTOY_RET {}" >> "$temp_cfg_file"; echo "}" >> "$temp_cfg_file"

        echo "submenu '--> [DEBUG] Debug / Recovery' --class=debug {" >> "$temp_cfg_file"
        sudo find "${snippet_dir}" -maxdepth 1 \( -name '*debug*.cfg' -o -name '*recovery*.cfg' -o -name '*sysrq*.cfg' \) -print0 | while IFS= read -r -d $'\0' f; do
           fn=$(basename "$f"); mn=$(echo "$fn" | sed -e 's/\.cfg$//;s/debian_//;s/_/ /g;s/\b\(.\)/\u\1/g'); cl="debug"; if [[ "$fn" == *"recovery"* ]]; then cl="recovery"; fi; if [[ "$fn" == *"nvidia"* ]]; then cl="nvidia"; fi; if [[ "$fn" == *"tty"* ]]; then cl="tty"; fi
           generate_menu_entry_text "$mn" "$fn" "$cl" >> "$temp_cfg_file"; count=$((count + 1)); done
        echo "    menuentry '<-- Back' --class=vtoyret VTOY_RET {}" >> "$temp_cfg_file"; echo "}" >> "$temp_cfg_file"
    fi

    # Add final return entry
    cat << FOOTER_EOF >> "$temp_cfg_file"

menuentry '' --class=spacer {}
menuentry '<-- Return to Ventoy Main Menu [Esc]' --class=vtoyret VTOY_RET {}
FOOTER_EOF
    if [ $? -ne 0 ]; then echo "[ERROR] Failed writing footer."; rm -f "$temp_cfg_file"; return 1; fi

    # Copy temp file to final destination with sudo
    echo "[INFO] Copying temp file to ${ventoy_cfg_file}..."
    sudo cp "$temp_cfg_file" "$ventoy_cfg_file" || { echo "[ERROR] Failed copying."; rm -f "$temp_cfg_file"; return 1; }
    sudo chmod 644 "$ventoy_cfg_file" || echo "[WARN] Failed permissions."
    rm -f "$temp_cfg_file" # Clean up

    echo "[INFO] Ventoy menu generation complete. Processed $count entries."
    return 0
}


# --- Function: Set GRUB Tune ---
# (Function set_grub_tune remains unchanged from v4)
set_grub_tune() { echo "[INFO] Modifying GRUB_INIT_TUNE in ${DEBIAN_DEFAULT_GRUB}..."; if [ ! -f "${DEBIAN_DEFAULT_GRUB}" ]; then echo "[ERROR] Cannot find ${DEBIAN_DEFAULT_GRUB}."; return 1; fi; declare -A tunes; tunes["None"]="comment"; tunes["Super Mario"]="1000 334 1 334 1 0 1 334 1 0 1 261 1 334 1 0 1 392 2 0 4 196 2"; tunes["Mario Coin"]="600 988 1 1319 8"; tunes["Mario Mushroom"]="1750 523 1 392 1 523 1 659 1 784 1 1047 1 784 1 415 1 523 1 622 1 831 1 622 1 831 1 1046 1 1244 1 1661 1 1244 1 466 1 587 1 698 1 932 1 1195 1 1397 1 1865 1 1397 1"; tunes["Close Encounters"]="480 900 2 1000 2 800 2 400 2 600 3"; tunes["Für Elise"]="480 420 1 400 1 420 1 400 1 420 1 315 1 370 1 335 1 282 3 180 1 215 1 282 1 315 3 213 1 262 1 315 1 335 3 213 1 420 1 400 1 420 1 400 1 420 1 315 1 370 1 335 1 282 3 180 1 215 1 282 1 315 3 213 1 330 1 315 1 282 3"; tunes["Imperial March"]="480 440 4 440 4 440 4 349 3 523 1 440 4 349 3 523 1 440 8 659 4 659 4 659 4 698 3 523 1 415 4 349 3 523 1 440 8"; tunes["Random"]="random"; local options=(); options+=("None"); options+=("Random"); while IFS= read -r key; do [[ "$key" != "None" ]] && [[ "$key" != "Random" ]] && options+=("$key"); done < <(printf '%s\n' "${!tunes[@]}" | sort | grep -v -e '^None$' -e '^Random$'); echo "Available Tunes:"; for j in "${!options[@]}"; do printf " %2d) %s\n" $((j + 1)) "${options[$j]}"; done; local choice tune_name tune_string new_grub_line; while true; do read -p "Enter tune number (Enter to cancel): " choice; if [ -z "$choice" ]; then echo "[INFO] Cancelled."; return 1; fi; if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "${#options[@]}" ]; then tune_name="${options[$((choice-1))]}"; break; else echo "[ERROR] Invalid."; fi; done; echo "[INFO] Selected: $tune_name"; if [ "$tune_name" == "None" ]; then new_grub_line="#GRUB_INIT_TUNE=\"480 440 1\""; elif [ "$tune_name" == "Random" ]; then local actual_tunes=(); while IFS= read -r key; do actual_tunes+=("$key"); done < <(printf '%s\n' "${!tunes[@]}" | grep -v -e '^None$' -e '^Random$'); local rand_idx=$(( RANDOM % ${#actual_tunes[@]} )); local rand_tune_name="${actual_tunes[$rand_idx]}"; tune_string="${tunes[$rand_tune_name]}"; echo "[INFO] Randomly chose: $rand_tune_name"; new_grub_line="GRUB_INIT_TUNE=\"${tune_string}\""; else tune_string="${tunes[$tune_name]}"; new_grub_line="GRUB_INIT_TUNE=\"${tune_string}\""; fi; echo "[INFO] Applying to ${DEBIAN_DEFAULT_GRUB}..."; sudo cp "${DEBIAN_DEFAULT_GRUB}" "${DEBIAN_DEFAULT_GRUB}.bak.$(date +%Y%m%d_%H%M%S)"; local escaped=$(printf '%s\n' "$new_grub_line" | sed 's/[\&/]/\\&/g'); if sudo grep -q -E '^#?\s*GRUB_INIT_TUNE=' "${DEBIAN_DEFAULT_GRUB}"; then sudo sed -i "/^#\?\s*GRUB_INIT_TUNE=/c\\${escaped}" "${DEBIAN_DEFAULT_GRUB}"; else echo "$new_grub_line" | sudo tee -a "${DEBIAN_DEFAULT_GRUB}" > /dev/null; fi; echo "[SUCCESS] Applied. Run 'sudo update-grub'!"; return 0; }

# --- Main Script Logic ---
echo "--- FlintX GRUB Keymaster v8 ---"
if [ "$(id -u)" -ne 0 ]; then echo "[ERROR] Must run with sudo."; exit 1; fi
declare SNIPPET_DIR VENTOY_MOUNT_POINT PARTITION_UUID FINAL_UUID FINAL_KERNEL_PATH FINAL_INITRD_PATH
if load_base_config && prompt_yes_no "Use saved paths [Snippets: $SAVED_SNIPPET_DIR | Ventoy: $SAVED_VENTOY_MOUNT]?"; then SNIPPET_DIR="$SAVED_SNIPPET_DIR"; VENTOY_MOUNT_POINT="$SAVED_VENTOY_MOUNT"; echo "[INFO] Using saved."; sudo mkdir -p "${VENTOY_MOUNT_POINT}/ventoy"; else prompt_base_config; fi
while true; do clear; echo "--- Main Menu ---"; echo "Paths: Snippets=${SNIPPET_DIR} | Ventoy=${VENTOY_MOUNT_POINT}"; echo "System: Kernel=${FINAL_KERNEL_PATH:-?} | Initrd=${FINAL_INITRD_PATH:-?} | UUID=${FINAL_UUID:-?}"; echo "-----------------"; echo "1. Detect/Confirm System Info"; echo "2. Generate/Update Snippets"; echo "3. Generate Ventoy Menu"; echo "4. Set GRUB Boot Tune"; echo "5. DO ALL (1 -> 2 -> 3)"; echo "6. Exit"; read -p "Choose action (1-6): " choice
    case $choice in
        1) detect_system_info ;;
        2) if [ -z "$FINAL_KERNEL_PATH" ]; then echo "[WARN] Run 1 first."; else if prompt_yes_no "Generate/Update ALL snippets in '$SNIPPET_DIR'?"; then generate_all_snippets "$SNIPPET_DIR"; fi; fi ;;
        3) if [ -z "$FINAL_UUID" ]; then echo "[WARN] Run 1 first."; elif ! sudo test -d "$SNIPPET_DIR" || [ -z "$(sudo ls -A "${SNIPPET_DIR}"/*.cfg 2>/dev/null)" ]; then echo "[WARN] Run 2 first or check snippet dir."; else if prompt_yes_no "Generate Ventoy menu file?"; then generate_ventoy_menu "$SNIPPET_DIR" "$FINAL_UUID" "$VENTOY_MOUNT_POINT"; fi; fi ;;
        4) set_grub_tune ;;
        5) detect_system_info; if [ -n "$FINAL_KERNEL_PATH" ]; then if prompt_yes_no "OK to Generate Snippets?"; then generate_all_snippets "$SNIPPET_DIR"; if prompt_yes_no "OK to Generate Ventoy Menu?"; then generate_ventoy_menu "$SNIPPET_DIR" "$FINAL_UUID" "$VENTOY_MOUNT_POINT"; fi; fi; else echo "[ERR] Sysinfo failed."; fi ;;
        6) echo "[INFO] Exiting."; exit 0 ;;
        *) echo "[ERR] Invalid choice." ;;
    esac
    read -p "Press Enter to continue..."
done
exit 0
EOF
SNIPPET_BACKUP_DIR_RELPATH="grub_configs_backups"
VENTOY_BACKUP_DIR_RELPATH="ventoy/backups"
DEBIAN_DEFAULT_GRUB="/etc/default/grub"

# --- Helper Functions ---
prompt_yes_no() { local p="$1" d="${2:-N}" a; while true; do read -p "$p [Y/n]: " a; a="${a:-$d}"; if [[ "$a" =~ ^[Yy]$ ]]; then return 0; fi; if [[ "$a" =~ ^[Nn]$ ]]; then return 1; fi; echo "Please answer 'y' or 'n'."; done; }

# --- Load/Save/Prompt for Base Config (Paths) ---
load_base_config() { if [ -f "$CONFIG_FILE" ]; then source "$CONFIG_FILE"; if [ -z "$SAVED_SNIPPET_DIR" ] || [ -z "$SAVED_VENTOY_MOUNT" ]; then return 1; fi; if ! sudo test -d "$SAVED_VENTOY_MOUNT" || ! sudo test -d "$SAVED_SNIPPET_DIR"; then echo "[WARN] Saved paths invalid."; return 1; fi; return 0; fi; return 1; }
save_base_config() { local s="$1" v="$2"; echo "[INFO] Saving settings..."; sudo touch "$CONFIG_FILE"; sudo chown "${SUDO_USER:-$(logname)}":"${SUDO_USER:-$(logname)}" "$CONFIG_FILE"; sudo chmod 600 "$CONFIG_FILE"; echo "# GK v2" | sudo tee "$CONFIG_FILE" > /dev/null; echo "SAVED_SNIPPET_DIR=\"$s\"" | sudo tee -a "$CONFIG_FILE" > /dev/null; echo "SAVED_VENTOY_MOUNT=\"$v\"" | sudo tee -a "$CONFIG_FILE" > /dev/null; echo "[INFO] Saved."; }
prompt_base_config() { local vm=false; while [ "$vm" = false ]; do read -e -p "Ventoy USB Mount Path: " VENTOY_MOUNT_POINT; VENTOY_MOUNT_POINT=$(eval echo "$VENTOY_MOUNT_POINT"); if [ -d "$VENTOY_MOUNT_POINT" ]; then vm=true; sudo mkdir -p "${VENTOY_MOUNT_POINT}/ventoy" || exit 1; echo "[OK] Ventoy: $VENTOY_MOUNT_POINT"; else echo "[ERR] Not found."; fi; done; local vd=false; while [ "$vd" = false ]; do read -e -p "Debian Snippet Dir [${DEFAULT_SNIPPET_DIR}]: " SNIPPET_DIR; SNIPPET_DIR="${SNIPPET_DIR:-$DEFAULT_SNIPPET_DIR}"; SNIPPET_DIR=$(eval echo "$SNIPPET_DIR"); if sudo mkdir -p "$SNIPPET_DIR"; then echo "[OK] Snippets: $SNIPPET_DIR"; vd=true; else echo "[ERR] Cannot create/access."; fi; done; if prompt_yes_no "Save paths?"; then save_base_config "$SNIPPET_DIR" "$VENTOY_MOUNT_POINT"; fi; }

# --- Detect System Info (Kernel/UUID) ---
detect_system_info() { echo "[INFO] Detecting system info..."; DETECTED_UUID=$(findmnt -n -o UUID /); read -p "Debian Root UUID [${DETECTED_UUID:-Not Found}]: " FINAL_UUID; FINAL_UUID="${FINAL_UUID:-$DETECTED_UUID}"; if ! [[ "$FINAL_UUID" =~ ^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$ ]]; then echo "[ERR] Invalid UUID."; exit 1; fi; echo "[OK] Using UUID: $FINAL_UUID"; DETECTED_KERNEL_PATH=$(ls -t /boot/vmlinuz-* 2>/dev/null | grep -v 'rescue\|recovery\|old' | head -n 1); if [ -n "$DETECTED_KERNEL_PATH" ] && [ -f "$DETECTED_KERNEL_PATH" ]; then kernel_version=$(basename "$DETECTED_KERNEL_PATH" | sed 's/^vmlinuz-//'); DETECTED_INITRD_PATH=$(ls -t "/boot/initrd.img-${kernel_version}"* 2>/dev/null | head -n 1); if [ ! -f "$DETECTED_INITRD_PATH" ]; then DETECTED_INITRD_PATH=""; fi; else DETECTED_KERNEL_PATH=""; DETECTED_INITRD_PATH=""; fi; if [ -z "$DETECTED_KERNEL_PATH" ]; then echo "[WARN] No kernel detected."; read -e -p "Enter Kernel Path: " FINAL_KERNEL_PATH; read -e -p "Enter Initrd Path: " FINAL_INITRD_PATH; else echo " Detected Kernel: $DETECTED_KERNEL_PATH"; echo " Detected Initrd: $DETECTED_INITRD_PATH"; if ! prompt_yes_no "Use detected paths?"; then read -e -p "Enter Kernel Path: " FINAL_KERNEL_PATH; read -e -p "Enter Initrd Path: " FINAL_INITRD_PATH; else FINAL_KERNEL_PATH="$DETECTED_KERNEL_PATH"; FINAL_INITRD_PATH="$DETECTED_INITRD_PATH"; fi; fi; if ! sudo test -f "$FINAL_KERNEL_PATH" || ! sudo test -f "$FINAL_INITRD_PATH"; then echo "[ERR] Kernel/initrd invalid."; exit 1; fi; echo "[OK] Using Kernel: $FINAL_KERNEL_PATH"; echo "[OK] Using Initrd: $FINAL_INITRD_PATH"; export FINAL_UUID FINAL_KERNEL_PATH FINAL_INITRD_PATH; }

# --- Generate All Snippets (.cfg files) ---
generate_all_snippets() { local sdir="$1"; echo "[INFO] Generating snippets in ${sdir}..."; local bakdir="${sdir}/${SNIPPET_BACKUP_DIR_RELPATH}"; sudo mkdir -p "$bakdir"; if sudo ls "${sdir}"/*.cfg > /dev/null 2>&1; then echo " Backing up existing..."; local ts=$(date +%Y%m%d_%H%M%S); sudo mkdir -p "${bakdir}/bak_${ts}"; if sudo test -d "${bakdir}/bak_${ts}"; then sudo mv "${sdir}"/*.cfg "${bakdir}/bak_${ts}/"; fi; fi; gen() { echo " -> $1"; printf "%s" "$2" | sudo tee "${sdir}/$1" > /dev/null ; sudo chmod 644 "${sdir}/$1"; }; k="$FINAL_KERNEL_PATH"; i="$FINAL_INITRD_PATH"; u="$FINAL_UUID"; common="insmod gzio part_gpt ext2; search --fs-uuid --set=root ${u}"; linux_base="linux ${k} root=UUID=${u} ro"; initrd_base="initrd ${i}"; gen "debian_gui_nomodeset.cfg" "# SNIP: GUI Nomodeset\nload_video; ${common}; ${linux_base} nomodeset; ${initrd_base}"; gen "debian_gui_nomodeset_noefifb.cfg" "# SNIP: GUI Nomodeset NoEFIFB\nload_video; ${common}; ${linux_base} nomodeset video=efifb:off; ${initrd_base}"; gen "debian_gui_nouveau_quiet.cfg" "# SNIP: GUI Nouveau Quiet\n${common}; ${linux_base} quiet; ${initrd_base}"; gen "debian_gui_nouveau_verbose.cfg" "# SNIP: GUI Nouveau Verbose\n${common}; ${linux_base}; ${initrd_base}"; gen "debian_gui_nouveau_drm_debug.cfg" "# SNIP: GUI Nouveau DRM Debug\n${common}; ${linux_base} drm.debug=0x1e log_buf_len=10M; ${initrd_base}"; gen "debian_gui_nvidia_quiet.cfg" "# SNIP: GUI Nvidia Quiet\n${common}; ${linux_base} quiet nvidia-drm.modeset=1; ${initrd_base}"; gen "debian_gui_nvidia_verbose.cfg" "# SNIP: GUI Nvidia Verbose\n${common}; ${linux_base} nvidia-drm.modeset=1; ${initrd_base}"; gen "debian_gui_nvidia_drm_debug.cfg" "# SNIP: GUI Nvidia DRM Debug\n${common}; ${linux_base} nvidia-drm.modeset=1 drm.debug=0x1e log_buf_len=10M; ${initrd_base}"; gen "debian_gui_nvidia_intel_pstate_disabled.cfg" "# SNIP: GUI Nvidia No P-State\n${common}; ${linux_base} quiet nvidia-drm.modeset=1 intel_pstate=disable; ${initrd_base}"; gen "debian_gui_nvidia_max_cstate_1.cfg" "# SNIP: GUI Nvidia Max C1\n${common}; ${linux_base} quiet nvidia-drm.modeset=1 processor.max_cstate=1 intel_idle.max_cstate=1; ${initrd_base}"; gen "debian_gui_nvidia_pcie_aspm_off.cfg" "# SNIP: GUI Nvidia No ASPM\n${common}; ${linux_base} quiet nvidia-drm.modeset=1 pcie_aspm=off; ${initrd_base}"; gen "debian_recovery_basic.cfg" "# SNIP: Recovery Basic\n${common}; ${linux_base} single; ${initrd_base}"; gen "debian_recovery_nomodeset.cfg" "# SNIP: Recovery Nomodeset\nload_video; ${common}; ${linux_base} single nomodeset; ${initrd_base}"; nd="nouveau.modeset=0 rd.driver.blacklist=nouveau modprobe.blacklist=nouveau"; gen "debian_tty_debug.cfg" "# SNIP: TTY Debug\n${common}; ${linux_base} 3 ${nd} debug ignore_loglevel log_buf_len=10M; ${initrd_base}"; gen "debian_tty_nomodeset_nouveau_disabled.cfg" "# SNIP: TTY Nomodeset ND\n${common}; ${linux_base} 3 nomodeset ${nd}; ${initrd_base}"; gen "debian_tty_nouveau_disabled.cfg" "# SNIP: TTY ND\n${common}; ${linux_base} quiet 3 ${nd}; ${initrd_base}"; gen "debian_tty_nouveau_enabled.cfg" "# SNIP: TTY Nouveau Enabled\n${common}; ${linux_base} quiet 3; ${initrd_base}"; gen "debian_tty_nvidia.cfg" "# SNIP: TTY Nvidia Active\n${common}; ${linux_base} quiet 3 nvidia-drm.modeset=1; ${initrd_base}"; gen "debian_tty_debug_sysrq.cfg" "# SNIP: TTY Debug SysRq\n${common}; ${linux_base} 3 ${nd} debug ignore_loglevel log_buf_len=10M sysrq_always_enabled=1; ${initrd_base}"; gen "debian_gui_nvidia_quiet_sysrq.cfg" "# SNIP: GUI Nvidia Quiet SysRq\n${common}; ${linux_base} quiet nvidia-drm.modeset=1 sysrq_always_enabled=1; ${initrd_base}"; echo "[INFO] Snippet generation complete."; }

# --- Generate Ventoy Menu (ventoy_grub.cfg) ---
generate_ventoy_menu() {
    local snippet_dir="$1"; local part_uuid="$2"; local ventoy_mount="$3"
    local ventoy_cfg_file="${ventoy_mount}/${VENTOY_CONFIG_FILE_RELPATH}"
    local ventoy_backup_dir="${ventoy_mount}/${VENTOY_BACKUP_DIR_RELPATH}"

    echo "[INFO] Starting generation of ${ventoy_cfg_file}..."
    sudo mkdir -p "$(dirname "$ventoy_cfg_file")"
    # Backup existing file
    if sudo test -f "$ventoy_cfg_file"; then
        echo "[INFO] Backing up existing $ventoy_cfg_file..."
        sudo mkdir -p "$ventoy_backup_dir"
        local backup_ts=$(date +%Y%m%d_%H%M%S)
        sudo cp "$ventoy_cfg_file" "${ventoy_backup_dir}/ventoy_grub_${backup_ts}.cfg.bak" || echo "[WARN] USB Backup failed."
    fi

    # Write new header (needs sudo)
    echo "[INFO] Writing new ${ventoy_cfg_file}..."
    # Use temporary file to build content, then sudo cp
    local temp_cfg_file=$(mktemp)
    chmod 644 "$temp_cfg_file" # Ensure readable

    cat << HEADER_EOF > "$temp_cfg_file"
# --- FlintX Custom Debian Loader (Generated: $(date)) ---
set timeout=30
set menu_color_normal=white/black
set menu_color_highlight=black/cyan
set pagination=1

set flintx_target_uuid="${part_uuid}"
set flintx_config_path="${snippet_dir}"

function find_debian_root {
    insmod part_gpt || true; insmod ext2 || true;
    if search --no-floppy --fs-uuid --set=debian_root "\${flintx_target_uuid}"; then return 0; else
        echo "ERROR: Debian Root UUID \${flintx_target_uuid} NOT FOUND!"; sleep 10; return 1; fi
}
menuentry "--- FlintX Debian Boot Options (UUID: ${part_uuid:0:8}...) ---" --class=header {}
HEADER_EOF
    if [ $? -ne 0 ]; then echo "[ERROR] Failed writing header to temp file."; rm -f "$temp_cfg_file"; return 1; fi

    # Add menu entries directly
    local count=0
    local cfg_file_count=$(sudo ls -1 "${snippet_dir}"/*.cfg 2>/dev/null | wc -l)
    if [ "$cfg_file_count" -eq 0 ]; then
        echo "[WARN] No '.cfg' snippets found in ${snippet_dir}!"
        echo "menuentry \"(No .cfg files found in ${snippet_dir})\" { sleep 5 }" >> "$temp_cfg_file"
    else
        # Helper function (can stay local if only used here)
        add_ventoy_entry() {
            local menu_name="$1"; local cfg_filename="$2"; local entry_class="$3"
            # Use printf directly into the file append
            printf '    menuentry "%s" --class %s {\n        find_debian_root\n        if [ \$? -eq 0 ]; then\n            local cfg="(\$debian_root)%s/%s"\n            echo "Loading: \\\${cfg}"\n            if [ -e "\\\${cfg}" ]; then configfile "\\\${cfg}"; boot; else\n                 echo "ERROR: Snippet \\\${cfg} not found!"; sleep 5; fi\n        fi; sleep 1\n    }\n' \
                   "$menu_name" "$entry_class" "$flintx_config_path" "$cfg_filename" >> "$temp_cfg_file"
            count=$((count + 1))
        }

        # Define submenus and add entries
        echo "submenu '--> [GUI] Standard Modes' --class=gui {" >> "$temp_cfg_file"
        sudo find "${snippet_dir}" -maxdepth 1 \( -name 'debian_gui_nouveau*.cfg' -o -name 'debian_gui_nvidia_quiet.cfg' -o -name 'debian_gui_nvidia_verbose.cfg' -o -name 'debian_gui_nvidia_quiet_sysrq.cfg' \) -print0 | while IFS= read -r -d $'\0' f; do
            fn=$(basename "$f"); mn=$(echo "$fn" | sed -e 's/\.cfg$//;s/debian_gui_//;s/_/ /g;s/\b\(.\)/\u\1/g'); cl="debian"; if [[ "$fn" == *"nvidia"* ]]; then cl="nvidia"; fi; if [[ "$fn" == *"debug"* ]]; then cl="debug"; fi
            add_ventoy_entry "$mn" "$fn" "$cl"
        done
        echo "    menuentry '<-- Back' --class=vtoyret VTOY_RET {}" >> "$temp_cfg_file"; echo "}" >> "$temp_cfg_file"

        echo "submenu '--> [TTY] Text Modes' --class=tty {" >> "$temp_cfg_file"
        sudo find "${snippet_dir}" -maxdepth 1 \( -name 'debian_tty*.cfg' ! -name '*sysrq*.cfg' ! -name '*debug*.cfg' \) -print0 | while IFS= read -r -d $'\0' f; do
             fn=$(basename "$f"); mn=$(echo "$fn" | sed -e 's/\.cfg$//;s/debian_tty_//;s/_/ /g;s/\b\(.\)/\u\1/g'); cl="debian"; if [[ "$fn" == *"nvidia"* ]]; then cl="nvidia"; fi; if [[ "$fn" == *"nomodeset"* ]]; then cl="fallback"; fi
             add_ventoy_entry "$mn" "$fn" "$cl"
        done
        echo "    menuentry '<-- Back' --class=vtoyret VTOY_RET {}" >> "$temp_cfg_file"; echo "}" >> "$temp_cfg_file"

        echo "submenu '--> [GFX] Fallback / Advanced' --class=fallback {" >> "$temp_cfg_file"
        sudo find "${snippet_dir}" -maxdepth 1 \( -name 'debian_gui_nomodeset*.cfg' -o -name 'debian_gui_nvidia_intel*.cfg' -o -name 'debian_gui_nvidia_max*.cfg' -o -name 'debian_gui_nvidia_pcie*.cfg' \) -print0 | while IFS= read -r -d $'\0' f; do
           fn=$(basename "$f"); mn=$(echo "$fn" | sed -e 's/\.cfg$//;s/debian_gui_//;s/_/ /g;s/\b\(.\)/\u\1/g'); cl="fallback"; if [[ "$fn" == *"nvidia"* ]]; then cl="nvidia"; fi
           add_ventoy_entry "$mn" "$fn" "$cl"
        done
        echo "    menuentry '<-- Back' --class=vtoyret VTOY_RET {}" >> "$temp_cfg_file"; echo "}" >> "$temp_cfg_file"

        echo "submenu '--> [DEBUG] Debug / Recovery' --class=debug {" >> "$temp_cfg_file"
        sudo find "${snippet_dir}" -maxdepth 1 \( -name '*debug*.cfg' -o -name '*recovery*.cfg' -o -name '*sysrq*.cfg' \) -print0 | while IFS= read -r -d $'\0' f; do
           fn=$(basename "$f"); mn=$(echo "$fn" | sed -e 's/\.cfg$//;s/debian_//;s/_/ /g;s/\b\(.\)/\u\1/g'); cl="debug"; if [[ "$fn" == *"recovery"* ]]; then cl="recovery"; fi; if [[ "$fn" == *"nvidia"* ]]; then cl="nvidia"; fi; if [[ "$fn" == *"tty"* ]]; then cl="tty"; fi
           add_ventoy_entry "$mn" "$fn" "$cl"
        done
        echo "    menuentry '<-- Back' --class=vtoyret VTOY_RET {}" >> "$temp_cfg_file"; echo "}" >> "$temp_cfg_file"
    fi

    # Add final return entry
    cat << FOOTER_EOF >> "$temp_cfg_file"

menuentry '' --class=spacer {}
menuentry '<-- Return to Ventoy Main Menu [Esc]' --class=vtoyret VTOY_RET {}
FOOTER_EOF
    if [ $? -ne 0 ]; then echo "[ERROR] Failed writing footer to temp file."; rm -f "$temp_cfg_file"; return 1; fi

    # Copy temp file to final destination with sudo
    echo "[INFO] Copying temp file to ${ventoy_cfg_file}..."
    sudo cp "$temp_cfg_file" "$ventoy_cfg_file" || { echo "[ERROR] Failed copying to final destination."; rm -f "$temp_cfg_file"; return 1; }
    sudo chmod 644 "$ventoy_cfg_file" || echo "[WARN] Failed setting permissions on $ventoy_cfg_file."
    rm -f "$temp_cfg_file" # Clean up

    echo "[INFO] Ventoy menu generation complete. Processed $count entries."
    return 0
}


# --- Function: Set GRUB Tune ---
set_grub_tune() { echo "[INFO] Modifying GRUB_INIT_TUNE in ${DEBIAN_DEFAULT_GRUB}..."; if [ ! -f "${DEBIAN_DEFAULT_GRUB}" ]; then echo "[ERROR] Cannot find ${DEBIAN_DEFAULT_GRUB}."; return 1; fi; declare -A tunes; tunes["None"]="comment"; tunes["Super Mario"]="1000 334 1 334 1 0 1 334 1 0 1 261 1 334 1 0 1 392 2 0 4 196 2"; tunes["Mario Coin"]="600 988 1 1319 8"; tunes["Mario Mushroom"]="1750 523 1 392 1 523 1 659 1 784 1 1047 1 784 1 415 1 523 1 622 1 831 1 622 1 831 1 1046 1 1244 1 1661 1 1244 1 466 1 587 1 698 1 932 1 1195 1 1397 1 1865 1 1397 1"; tunes["Close Encounters"]="480 900 2 1000 2 800 2 400 2 600 3"; tunes["Für Elise"]="480 420 1 400 1 420 1 400 1 420 1 315 1 370 1 335 1 282 3 180 1 215 1 282 1 315 3 213 1 262 1 315 1 335 3 213 1 420 1 400 1 420 1 400 1 420 1 315 1 370 1 335 1 282 3 180 1 215 1 282 1 315 3 213 1 330 1 315 1 282 3"; tunes["Imperial March"]="480 440 4 440 4 440 4 349 3 523 1 440 4 349 3 523 1 440 8 659 4 659 4 659 4 698 3 523 1 415 4 349 3 523 1 440 8"; tunes["Random"]="random"; local options=(); options+=("None"); options+=("Random"); while IFS= read -r key; do [[ "$key" != "None" ]] && [[ "$key" != "Random" ]] && options+=("$key"); done < <(printf '%s\n' "${!tunes[@]}" | sort | grep -v -e '^None$' -e '^Random$'); echo "Available Tunes:"; for j in "${!options[@]}"; do printf " %2d) %s\n" $((j + 1)) "${options[$j]}"; done; local choice tune_name new_grub_line; while true; do read -p "Enter tune number (Enter to cancel): " choice; if [ -z "$choice" ]; then echo "[INFO] Cancelled."; return 1; fi; if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "${#options[@]}" ]; then tune_name="${options[$((choice-1))]}"; break; else echo "[ERROR] Invalid."; fi; done; echo "[INFO] Selected: $tune_name"; if [ "$tune_name" == "None" ]; then new_grub_line="#GRUB_INIT_TUNE=\"480 440 1\""; elif [ "$tune_name" == "Random" ]; then local actual_tunes=(); while IFS= read -r key; do actual_tunes+=("$key"); done < <(printf '%s\n' "${!tunes[@]}" | grep -v -e '^None$' -e '^Random$'); local rand_idx=$(( RANDOM % ${#actual_tunes[@]} )); local rand_tune_name="${actual_tunes[$rand_idx]}"; tune_string="${tunes[$rand_tune_name]}"; echo "[INFO] Randomly chose: $rand_tune_name"; new_grub_line="GRUB_INIT_TUNE=\"${tune_string}\""; else tune_string="${tunes[$tune_name]}"; new_grub_line="GRUB_INIT_TUNE=\"${tune_string}\""; fi; echo "[INFO] Applying to ${DEBIAN_DEFAULT_GRUB}..."; sudo cp "${DEBIAN_DEFAULT_GRUB}" "${DEBIAN_DEFAULT_GRUB}.bak.$(date +%Y%m%d_%H%M%S)"; local escaped=$(printf '%s\n' "$new_grub_line" | sed 's/[\&/]/\\&/g'); if sudo grep -q -E '^#?\s*GRUB_INIT_TUNE=' "${DEBIAN_DEFAULT_GRUB}"; then sudo sed -i "/^#\?\s*GRUB_INIT_TUNE=/c\\${escaped}" "${DEBIAN_DEFAULT_GRUB}"; else echo "$new_grub_line" | sudo tee -a "${DEBIAN_DEFAULT_GRUB}" > /dev/null; fi; echo "[SUCCESS] Applied. Run 'sudo update-grub'!"; return 0; }

# --- Main Script Logic ---
echo "--- FlintX GRUB Keymaster v5 ---"
if [ "$(id -u)" -ne 0 ]; then echo "[ERROR] Must run with sudo."; exit 1; fi
declare SNIPPET_DIR VENTOY_MOUNT_POINT PARTITION_UUID FINAL_UUID FINAL_KERNEL_PATH FINAL_INITRD_PATH
if load_base_config && prompt_yes_no "Use saved paths [Snippets: $SAVED_SNIPPET_DIR | Ventoy: $SAVED_VENTOY_MOUNT]?"; then SNIPPET_DIR="$SAVED_SNIPPET_DIR"; VENTOY_MOUNT_POINT="$SAVED_VENTOY_MOUNT"; echo "[INFO] Using saved."; sudo mkdir -p "${VENTOY_MOUNT_POINT}/ventoy"; else prompt_base_config; fi
while true; do clear; echo "--- Main Menu ---"; echo "Paths: Snippets=${SNIPPET_DIR} | Ventoy=${VENTOY_MOUNT_POINT}"; echo "System: Kernel=${FINAL_KERNEL_PATH:-?} | Initrd=${FINAL_INITRD_PATH:-?} | UUID=${FINAL_UUID:-?}"; echo "-----------------"; echo "1. Detect/Confirm System Info"; echo "2. Generate/Update Snippets"; echo "3. Generate Ventoy Menu"; echo "4. Set GRUB Boot Tune"; echo "5. DO ALL (1 -> 2 -> 3)"; echo "6. Exit"; read -p "Choose action (1-6): " choice
    case $choice in
        1) detect_system_info ;;
        2) if [ -z "$FINAL_KERNEL_PATH" ]; then echo "[WARN] Run 1 first."; else if prompt_yes_no "Generate/Update ALL snippets in '$SNIPPET_DIR'?"; then generate_all_snippets "$SNIPPET_DIR"; fi; fi ;;
        3) if [ -z "$FINAL_UUID" ]; then echo "[WARN] Run 1 first."; elif [ ! -d "$SNIPPET_DIR" ] || [ -z "$(sudo ls -A "${SNIPPET_DIR}"/*.cfg 2>/dev/null)" ]; then echo "[WARN] Run 2 first or check snippet dir."; else if prompt_yes_no "Generate Ventoy menu file?"; then generate_ventoy_menu "$SNIPPET_DIR" "$FINAL_UUID" "$VENTOY_MOUNT_POINT"; fi; fi ;;
        4) set_grub_tune ;;
        5) detect_system_info; if [ -n "$FINAL_KERNEL_PATH" ]; then if prompt_yes_no "OK to Generate Snippets?"; then generate_all_snippets "$SNIPPET_DIR"; if prompt_yes_no "OK to Generate Ventoy Menu?"; then generate_ventoy_menu "$SNIPPET_DIR" "$FINAL_UUID" "$VENTOY_MOUNT_POINT"; fi; fi; else echo "[ERR] Sysinfo failed."; fi ;;
        6) echo "[INFO] Exiting."; exit 0 ;;
        *) echo "[ERR] Invalid choice." ;;
    esac
    read -p "Press Enter to continue..."
done
exit 0
