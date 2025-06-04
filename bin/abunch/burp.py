import subprocess
import os
import time

# Define the paths
cert_dir = "/home/flintx/flow/certs/"
android_cert_dir = "/mnt/sdcard/Download/"

# ANSI escape codes for cyberpunk color scheme
CYAN = "\033[1;36m"
GREEN = "\033[1;32m"
PURPLE = "\033[1;35m"
YELLOW = "\033[1;33m"
RED = "\033[1;31m"
RESET = "\033[0m"

# Helper function to run a command
def run_command(command):
    print(f"{CYAN}Executing: {command}{RESET}")
    try:
        subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"{RED}Error executing command: {e}{RESET}")

# Start Burp Suite with provided launch command
def start_burp():
    try:
        subprocess.Popen([
            "/opt/jdk-21.0.5+11-jre/bin/java",
            "--add-opens=java.desktop/javax.swing=ALL-UNNAMED",
            "--add-opens=java.base/java.lang=ALL-UNNAMED",
            "--add-opens=java.base/jdk.internal.org.objectweb.asm=ALL-UNNAMED",
            "--add-opens=java.base/jdk.internal.org.objectweb.asm.tree=ALL-UNNAMED",
            "--add-opens=java.base/jdk.internal.org.objectweb.asm.Opcodes=ALL-UNNAMED",
            "-javaagent:/home/flintx/burp/burploader.jar",
            "-noverify",
            "-jar",
            "/home/flintx/burp/burpsuite.jar"
        ])
        print(f"{GREEN}Burp Suite is starting...{RESET}")
    except Exception as e:
        print(f"{RED}Error starting Burp Suite: {e}{RESET}")

# List the certificates in the cert folder
def list_certs():
    cert_files = [f for f in os.listdir(cert_dir) if f.endswith('.der') or f.endswith('.pem')]
    return cert_files

# Convert DER to PEM
def convert_der_to_pem():
    cert_files = [f for f in os.listdir(cert_dir) if f.endswith('.der')]
    if not cert_files:
        print(f"{RED}No DER files found.{RESET}")
        return
    print(f"{CYAN}DER files found:{RESET}")
    for index, cert in enumerate(cert_files, start=1):
        print(f"{PURPLE}{index}. {cert}{RESET}")

    choice = input(f"{YELLOW}Convert all DER files to PEM? (y/n): {RESET}")
    if choice.lower() == "y":
        for cert in cert_files:
            der_path = os.path.join(cert_dir, cert)
            pem_path = os.path.join(cert_dir, cert.replace('.der', '.pem'))
            command = f"openssl x509 -inform der -in {der_path} -out {pem_path}"
            subprocess.run(command, shell=True, check=True)
            print(f"{GREEN}Converted {cert} to PEM.{RESET}")

# Push PEM to Android
def push_pem_to_android():
    pem_files = [f for f in os.listdir(cert_dir) if f.endswith('.pem')]
    if not pem_files:
        print(f"{RED}No PEM files found.{RESET}")
        return
    print(f"{CYAN}PEM files found:{RESET}")
    for index, pem in enumerate(pem_files, start=1):
        print(f"{PURPLE}{index}. {pem}{RESET}")

    choice = input(f"{YELLOW}Push all PEM files to Android? (y/n): {RESET}")
    if choice.lower() == "y":
        for pem in pem_files:
            pem_path = os.path.join(cert_dir, pem)
            command = f"adb push {pem_path} {android_cert_dir}"
            subprocess.run(command, shell=True, check=True)
            print(f"{GREEN}Pushed {pem} to Android.{RESET}")

# Pull Certs from Android
def pull_certs_from_android():
    try:
        result = subprocess.check_output(f"adb shell ls {android_cert_dir}", shell=True, text=True).strip()
        if not result:
            print(f"{RED}No files found on Android.{RESET}")
            return
        cert_files = result.splitlines()
        print(f"{CYAN}Certificates found on Android:{RESET}")
        for index, cert in enumerate(cert_files, start=1):
            print(f"{PURPLE}{index}. {cert}{RESET}")

        choice = input(f"{YELLOW}Pull all certificates back to local cert folder? (y/n): {RESET}")
        if choice.lower() == "y":
            for cert in cert_files:
                command = f"adb pull {android_cert_dir}/{cert} {cert_dir}"
                subprocess.run(command, shell=True, check=True)
                print(f"{GREEN}Pulled {cert} to local certs folder.{RESET}")
    except Exception as e:
        print(f"{RED}Error pulling certs from Android: {e}{RESET}")

# Menu
def main_menu():
    while True:
        os.system('clear')
        print(f"{PURPLE}--- BURP MENU ---{RESET}")
        print(f"{YELLOW}1. Start Burp{RESET}")
        print(f"{YELLOW}2. View Certs{RESET}")
        print(f"{YELLOW}3. Convert DER to PEM{RESET}")
        print(f"{YELLOW}4. Push PEM to Android{RESET}")
        print(f"{YELLOW}5. Pull Certs from Android{RESET}")
        print(f"{YELLOW}6. Exit{RESET}")
        print("\n")

        choice = input(f"{CYAN}Select an option: {RESET}")
        if choice == "1":
            start_burp()
        elif choice == "2":
            cert_files = list_certs()
            if cert_files:
                print(f"{CYAN}Certificates found in certs folder:{RESET}")
                for index, cert in enumerate(cert_files, start=1):
                    print(f"{PURPLE}{index}. {cert}{RESET}")
            else:
                print(f"{RED}No certificates found.{RESET}")
        elif choice == "3":
            convert_der_to_pem()
        elif choice == "4":
            push_pem_to_android()
        elif choice == "5":
            pull_certs_from_android()
        elif choice == "6":
            print(f"{GREEN}Exiting...{RESET}")
            break
        else:
            print(f"{RED}Invalid choice. Please try again.{RESET}")
        input(f"{CYAN}\nPress Enter to continue...{RESET}")

if __name__ == "__main__":
    main_menu()
