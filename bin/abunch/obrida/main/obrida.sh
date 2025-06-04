#!/bin/bash

MODULE_DIR="/home/flintx/obrida/modules"
PYTHON_MODULES_DIR="/home/flintx/obrida/python_modules"

# Check if ADB is installed
check_adb() {
    if ! command -v adb &>/dev/null; then
        echo "[ERROR] ADB is not installed."
        echo "Would you like to install ADB? (y/n)"
        read -r install_choice
        if [[ "$install_choice" == "y" ]]; then
            sudo apt update && sudo apt install adb -y
        else
            echo "[ERROR] ADB is required. Exiting."
            exit 1
        fi
    else
        echo "[SUCCESS] ADB is installed."
    fi
}

# Proxy Setup
configure_proxy() {
    echo "Configuring Proxy..."
    bash "$MODULE_DIR/set_emulator_proxy.sh"
}

# Frida Hook Management
manage_frida_hooks() {
    echo "Available Hooks:"
    echo "1) Disable Secure Flag"
    echo "2) Bypass SSL Pinning"
    read -p "Choose a hook to apply: " hook_choice
    case "$hook_choice" in
        1) bash "$MODULE_DIR/launch_frida_script.sh" "/home/flintx/obrida/frida_hooks/disable_secure_flag.js" ;;
        2) bash "$MODULE_DIR/bypass_ssl_pinning.sh" ;;
        *) echo "[ERROR] Invalid choice." ;;
    esac
}

# Install Certificates
install_certificates() {
    echo "Installing Certificates..."
    python3 "$PYTHON_MODULES_DIR/cert.py"
}

# Main Menu
main_menu() {
    PS3="Select an option: "
    options=(
        "Setup ADB and Emulator"
        "Configure Proxy"
        "Manage Frida Hooks"
        "Install Certificates"
        "Exit"
    )
    select opt in "${options[@]}"; do
        case $REPLY in
            1) check_adb ;;
            2) configure_proxy ;;
            3) manage_frida_hooks ;;
            4) install_certificates ;;
            5) echo "Exiting..."; exit 0 ;;
            *) echo "[ERROR] Invalid option, try again." ;;
        esac
    done
}

# Run Main Menu
main_menu
