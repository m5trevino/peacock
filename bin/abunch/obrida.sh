#!/bin/bash

MODULE_DIR="/home/flintx/obrida/modules"

# Step Menus
PS3="Select an option: "

step1_options=(
    "Start Emulator"
    "Check ADB Devices"
    "Enable ADB Root"
    "Check Local Machine IP Address"
    "Set Emulator Proxy"
    "Set Emulator Reverse TCP Port"
    "Verify SELinux Mode"
    "Check and Kill Existing Frida Server"
    "Set File Permissions"
    "Restart Frida Server"
    "Check Port Usage (lsof)"
    "Check PID of Ports (netstat)"
    "Run Frida Server on Emulator"
    "Back to Main Menu"
)

step2_options=(
    "Run Frida-PS -Uia"
    "Find Open Processes on Emulator"
    "APK Installation and Signing"
    "Filtered Process Listing"
    "Back to Main Menu"
)

step3_options=(
    "Launch Frida Script for App/Package"
    "Attach Frida to a Process by PID"
    "Run Objection - Explore App"
    "Bypass SSL Pinning with Objection"
    "Patch APK with Objection"
    "Start App and Run Frida Script"
    "Select and Run Frida Script on a Process"
    "Logcat Integration"
    "Back to Main Menu"
)

# Function to display the Step 1 menu
step1_menu() {
    select opt in "${step1_options[@]}"; do
        case $REPLY in
            1) bash "$MODULE_DIR/start_emulator.sh" ;;
            2) bash "$MODULE_DIR/check_adb_devices.sh" ;;
            3) bash "$MODULE_DIR/enable_adb_root.sh" ;;
            4) bash "$MODULE_DIR/check_ip_address.sh" ;;
            5) bash "$MODULE_DIR/set_emulator_proxy.sh" ;;
            6) bash "$MODULE_DIR/set_reverse_tcp.sh" ;;
            7) bash "$MODULE_DIR/verify_selinux_mode.sh" ;;
            8) bash "$MODULE_DIR/kill_frida_server.sh" ;;
            9) bash "$MODULE_DIR/set_file_permissions.sh" ;;
            10) bash "$MODULE_DIR/restart_frida_server.sh" ;;
            11) bash "$MODULE_DIR/check_port_usage.sh" ;;
            12) bash "$MODULE_DIR/check_port_pid.sh" ;;
            13) bash "$MODULE_DIR/run_frida_server.sh" ;;
            14) main_menu ;;
            *) echo "Invalid option, try again." ;;
        esac
    done
}

# Function to display the Step 2 menu
step2_menu() {
    select opt in "${step2_options[@]}"; do
        case $REPLY in
            1) bash "$MODULE_DIR/run_frida_ps.sh" ;;
            2) bash "$MODULE_DIR/find_open_emulator_processes.sh" ;;
            3) bash "$MODULE_DIR/apk_installation_and_signing.sh" ;;
            4) bash "$MODULE_DIR/filtered_process_listing.sh" ;;
            5) main_menu ;;
            *) echo "Invalid option, try again." ;;
        esac
    done
}

# Function to display the Step 3 menu
step3_menu() {
    select opt in "${step3_options[@]}"; do
        case $REPLY in
            1) bash "$MODULE_DIR/launch_frida_script.sh" ;;
            2) bash "$MODULE_DIR/attach_frida_to_pid.sh" ;;
            3) bash "$MODULE_DIR/run_objection_explore.sh" ;;
            4) bash "$MODULE_DIR/bypass_ssl_with_objection.sh" ;;
            5) bash "$MODULE_DIR/patch_apk.sh" ;;
            6) bash "$MODULE_DIR/start_app_and_run_frida.sh" ;;
            7) bash "$MODULE_DIR/select_frida_script.sh" ;;
            8) bash "$MODULE_DIR/logcat_stream.sh" ;;
            9) main_menu ;;
            *) echo "Invalid option, try again." ;;
        esac
    done
}

# Main Menu
main_menu() {
    echo "Welcome to Obrida - Frida Automation Tool"
    echo "-----------------------------------------"
    echo "1) Step 1: Setup and Preparation"
    echo "2) Step 2: Process Listing and Filtering"
    echo "3) Step 3: Enhanced Process Management"
    echo "4) Exit"
    echo "-----------------------------------------"
    read -p "Enter your choice: " choice

    case $choice in
        1) step1_menu ;;
        2) step2_menu ;;
        3) step3_menu ;;
        4) echo "Exiting..."; exit 0 ;;
        *) echo "Invalid option, try again."; main_menu ;;
    esac
}

# Run the main menu
main_menu
