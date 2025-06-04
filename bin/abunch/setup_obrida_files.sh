#!/bin/bash

# Base directory for Obrida
BASE_DIR="/home/flintx/obrida"

# File definitions: Paths and content
declare -A files_content=(
    ["$BASE_DIR/main/obrida.sh"]="#!/bin/bash

MODULE_DIR=\"/home/flintx/obrida/modules\"
PYTHON_MODULES_DIR=\"/home/flintx/obrida/python_modules\"

# Check if ADB is installed
check_adb() {
    if ! command -v adb &>/dev/null; then
        echo \"[ERROR] ADB is not installed.\"
        echo \"Would you like to install ADB? (y/n)\"
        read -r install_choice
        if [[ \"\$install_choice\" == \"y\" ]]; then
            sudo apt update && sudo apt install adb -y
        else
            echo \"[ERROR] ADB is required. Exiting.\"
            exit 1
        fi
    else
        echo \"[SUCCESS] ADB is installed.\"
    fi
}

# Proxy Setup
configure_proxy() {
    echo \"Configuring Proxy...\"
    bash \"\$MODULE_DIR/set_emulator_proxy.sh\"
}

# Frida Hook Management
manage_frida_hooks() {
    echo \"Available Hooks:\"
    echo \"1) Disable Secure Flag\"
    echo \"2) Bypass SSL Pinning\"
    read -p \"Choose a hook to apply: \" hook_choice
    case \"\$hook_choice\" in
        1) bash \"\$MODULE_DIR/launch_frida_script.sh\" \"/home/flintx/obrida/frida_hooks/disable_secure_flag.js\" ;;
        2) bash \"\$MODULE_DIR/bypass_ssl_pinning.sh\" ;;
        *) echo \"[ERROR] Invalid choice.\" ;;
    esac
}

# Install Certificates
install_certificates() {
    echo \"Installing Certificates...\"
    python3 \"\$PYTHON_MODULES_DIR/cert.py\"
}

# Main Menu
main_menu() {
    PS3=\"Select an option: \"
    options=(
        \"Setup ADB and Emulator\"
        \"Configure Proxy\"
        \"Manage Frida Hooks\"
        \"Install Certificates\"
        \"Exit\"
    )
    select opt in \"\${options[@]}\"; do
        case \$REPLY in
            1) check_adb ;;
            2) configure_proxy ;;
            3) manage_frida_hooks ;;
            4) install_certificates ;;
            5) echo \"Exiting...\"; exit 0 ;;
            *) echo \"[ERROR] Invalid option, try again.\" ;;
        esac
    done
}

# Run Main Menu
main_menu"
    ["$BASE_DIR/modules/set_emulator_proxy.sh"]="#!/bin/bash

read -p \"Enter Proxy IP (default: 127.0.0.1): \" proxy_ip
proxy_ip=\${proxy_ip:-127.0.0.1}

read -p \"Enter Proxy Port (default: 8080): \" proxy_port
proxy_port=\${proxy_port:-8080}

adb shell settings put global http_proxy \"\$proxy_ip:\$proxy_port\"
echo \"[SUCCESS] Proxy set to \$proxy_ip:\$proxy_port\""
    ["$BASE_DIR/python_modules/cert.py"]="#!/usr/bin/env python3

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import CertificateBuilder, NameOID
from datetime import datetime, timedelta
from uuid import uuid4
import os

def generate_certificate():
    print(\"[INFO] Generating Certificate...\")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    cert = (
        CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, \"Obrida Root CA\")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, \"Obrida Root CA\")]))
        .public_key(public_key)
        .serial_number(uuid4().int)
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365 * 2))
        .sign(private_key, hashes.SHA256())
    )

    with open(\"obrida_ca.pem\", \"wb\") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(\"[SUCCESS] Certificate Generated.\")

def install_certificate():
    print(\"[INFO] Installing Certificate on Device...\")
    os.system(\"adb push obrida_ca.pem /data/local/tmp/\")
    os.system(\"adb shell mv /data/local/tmp/obrida_ca.pem /system/etc/security/cacerts/\")
    os.system(\"adb shell chmod 644 /system/etc/security/cacerts/obrida_ca.pem\")
    print(\"[SUCCESS] Certificate Installed.\")

if __name__ == \"__main__\":
    generate_certificate()
    install_certificate()"
    ["$BASE_DIR/frida_hooks/disable_secure_flag.js"]="Java.perform(() => {
    const Activity = Java.use(\"android.app.Activity\");
    Activity.getWindow.implementation = function () {
        this.setFlags(0, 128); // Disable SECURE flag
        return this.getWindow();
    };
    console.log(\"SECURE flag disabled.\");
});"
    ["$BASE_DIR/requirements.txt"]="cryptography
frida-tools"
)

# Create or update files
for file_path in "${!files_content[@]}"; do
    echo "[INFO] Creating or updating: $file_path"
    mkdir -p "$(dirname "$file_path")" # Ensure directory exists
    echo -e "${files_content[$file_path]}" > "$file_path" # Write content to file
    if [[ "$file_path" == *.sh ]]; then
        chmod +x "$file_path" # Make scripts executable
    fi
done

echo "[SUCCESS] All files have been created or updated."
