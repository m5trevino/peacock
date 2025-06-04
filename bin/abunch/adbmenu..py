import os
import subprocess
import time
from pathlib import Path

# Colors for Cyberpunk theme
CYAN = "\033[1;36m"
GREEN = "\033[1;32m"
PURPLE = "\033[1;35m"
YELLOW = "\033[1;33m"
RED = "\033[1;31m"
RESET = "\033[0m"

# Helper functions
def run_command(command):
    print(f"{CYAN}Executing: {command}{RESET}")
    try:
        output = subprocess.check_output(command, shell=True, text=True)
        print(f"{GREEN}Output:\n{output}{RESET}")
        return output.strip()
    except subprocess.CalledProcessError as e:
        error_message = e.output if e.output else "Unknown Error"
        print(f"{RED}Error: {error_message}{RESET}")
        return None

# General Menu

def display_dashboard(dashboard_data):
    os.system('clear')
    print(f"{PURPLE}--- DASHBOARD ---{RESET}")
    for key, value in dashboard_data.items():
        print(f"{YELLOW}{key}: {value}{RESET}")
    print(f"\n{CYAN}Command Log:{RESET}")
    for cmd in dashboard_data.get('log', []):
        print(f"- {cmd}")

def adb_dashboard():
    emulator_name = run_command('adb devices | grep emulator | cut -f1') or "No Emulator Detected"
    ip_address = run_command('hostname -I').split()[0] if run_command('hostname -I') else "Unknown IP"
    proxy = run_command('adb shell settings get global http_proxy') or "No Proxy Set"
    reverse_tcp = run_command('adb reverse --list') or "No Reverse TCP Mappings"
    selinux = run_command('adb shell getenforce') or "SELinux Status Unknown"
    adb_root = "Active" if "already running as root" in (run_command('adb root') or '') else "Not Active"
    return {
        'Emulator': emulator_name,
        'IP Address': ip_address,
        'Proxy': proxy,
        'Reverse TCP': reverse_tcp,
        'SELinux': selinux,
        'ADB Root': adb_root,
        'log': []
    }

def main_menu():
    dashboard_data = adb_dashboard()
    while True:
        display_dashboard(dashboard_data)
        print(f"{YELLOW}--- Main Menu ---{RESET}")
        print("1. Set Emulator Proxy")
        print("2. Set Reverse Port")
        print("3. Set Forward Port")
        print("4. Launch Burp Menu")
        print("5. Launch Mitmproxy Menu")
        print("6. Launch Frida Menu")
        print("7. Exit")
        choice = input(f"{CYAN}Select an option: {RESET}")

        if choice == '1':
            proxy_ip = input("Enter Proxy IP (default: 192.168.1.100): ") or "192.168.1.100"
            proxy_port = input("Enter Proxy Port (default: 8080): ") or "8080"
            command = f"adb shell settings put global http_proxy {proxy_ip}:{proxy_port}"
            run_command(command)
        elif choice == '2':
            local_port = input("Enter Local Port: ")
            remote_port = input("Enter Remote Port: ")
            run_command(f"adb reverse tcp:{remote_port} tcp:{local_port}")
        elif choice == '3':
            local_port = input("Enter Local Port: ")
            remote_port = input("Enter Remote Port: ")
            run_command(f"adb forward tcp:{local_port} tcp:{remote_port}")
        elif choice == '4':
            burp_menu()
        elif choice == '5':
            mitmproxy_menu()
        elif choice == '6':
            frida_menu()
        elif choice == '7':
            print(f"{GREEN}Exiting...{RESET}")
            break
        else:
            print(f"{RED}Invalid choice. Try again.{RESET}")
        time.sleep(2)

# Burp menu
def burp_menu():
    while True:
        print(f"{PURPLE}--- BURP MENU ---{RESET}")
        print("1. Start Burp")
        print("2. View Certs")
        print("3. Convert DER to PEM")
        print("4. Push PEM to Android")
        print("5. Pull Certs from Android")
        print("6. Exit")

        choice = input(f"{CYAN}Select an option: {RESET}")
        if choice == '1':
            run_command('burp')
        elif choice == '2':
            certs = Path('/home/flintx/flow/certs').glob('*.pem')
            for cert in certs:
                print(cert.name)
        elif choice == '3':
            run_command('openssl x509 -inform der -in /path/to/derfile.der -out /path/to/pemfile.pem')
        elif choice == '4':
            run_command('adb push /path/to/pemfile.pem /mnt/sdcard/Download/')
        elif choice == '5':
            run_command('adb pull /mnt/sdcard/Download/cert.pem /home/flintx/flow/certs/')
        elif choice == '6':
            break
        else:
            print(f"{RED}Invalid choice.{RESET}")
        input(f"{CYAN}Press Enter to continue...{RESET}")

# Placeholder for Mitmproxy and Frida menus
def mitmproxy_menu():
    print(f"{YELLOW}Mitmproxy menu is under development.{RESET}")
    time.sleep(2)

def frida_menu():
    print(f"{YELLOW}Frida menu is under development.{RESET}")
    time.sleep(2)

if __name__ == "__main__":
    main_menu()
