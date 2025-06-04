import subprocess
import os
import time

# ANSI escape codes for cyberpunk color scheme
CYAN = "\033[1;36m"
GREEN = "\033[1;32m"
PURPLE = "\033[1;35m"
YELLOW = "\033[1;33m"
RED = "\033[1;31m"
RESET = "\033[0m"

# Dashboard function
def display_dashboard():
    os.system('clear')
    print(f"{PURPLE}--- ADB MENU DASHBOARD ---{RESET}")
    emulator_status = run_command("adb devices | grep emulator") or "No Emulator Detected"
    ip_address = run_command("hostname -I | awk '{print $1}'") or "Unknown IP"
    proxy_status = run_command("adb shell settings get global http_proxy") or "Proxy Not Set"
    reverse_tcp_status = run_command("adb reverse --list") or "No Reverse TCP Mappings"
    selinux_status = run_command("adb shell getenforce") or "Unknown SELinux Status"
    adb_root_status = run_command("adb shell whoami") == "root" and "Active" or "Inactive"

    print(f"{CYAN}Emulator: {emulator_status}{RESET}")
    print(f"{CYAN}IP Address: {ip_address}{RESET}")
    print(f"{CYAN}Proxy: {proxy_status}{RESET}")
    print(f"{CYAN}Reverse TCP: {reverse_tcp_status}{RESET}")
    print(f"{CYAN}SELinux: {selinux_status}{RESET}")
    print(f"{CYAN}ADB Root: {adb_root_status}{RESET}")
    print()

# Helper function to run a command
def run_command(command):
    print(f"{CYAN}Executing: {command}{RESET}")
    try:
        result = subprocess.check_output(command, shell=True, text=True).strip()
        return result
    except subprocess.CalledProcessError:
        return None

# Prompt for SELinux mode
def reconfigure_selinux():
    current_status = run_command("adb shell getenforce")
    print(f"{CYAN}Current SELinux status: {current_status}{RESET}")
    print(f"{YELLOW}Select SELinux mode:{RESET}")
    print("1. Permissive")
    print("2. Enforcing")
    mode_choice = input(f"{CYAN}Enter your choice (1 or 2): {RESET} ").strip()
    
    if mode_choice == '1':
        run_command("adb root")
        result = run_command("adb shell setenforce 0")
        mode = 'Permissive' if not result or 'Permission denied' not in result else 'Failed (Permission Denied)'
    elif mode_choice == '2':
        run_command("adb root")
        result = run_command("adb shell setenforce 1")
        mode = 'Enforcing' if not result or 'Permission denied' not in result else 'Failed (Permission Denied)'
    else:
        print(f"{RED}Invalid choice. Please enter 1 or 2.{RESET}")
        return

    print(f"{GREEN}SELinux set to {mode}{RESET}")

# Prompt for IP and Port
def set_emulator_proxy():
    current_ip = run_command("hostname -I | awk '{print $1}'")
    print(f"{CYAN}Detected Local IP Address: {current_ip}{RESET}")
    confirm_ip = input(f"{YELLOW}Is this the correct IP to use for the proxy? (y/n): {RESET}")
    if confirm_ip.lower() != 'y':
        current_ip = input(f"{CYAN}Enter the correct IP address: {RESET}")

    proxy_port = input(f"{CYAN}Enter the proxy port (default: 8080): {RESET}") or "8080"
    run_command(f"adb shell settings put global http_proxy {current_ip}:{proxy_port}")
    print(f"{GREEN}Proxy set to {current_ip}:{proxy_port}{RESET}")

# Burp Integration
def launch_burp():
    run_command("python3 /home/flintx/flow/burp.py")
    prompt_for_frida()

# Mitmproxy Integration
def launch_mitmproxy():
    run_command("python3 /home/flintx/flow/mitm.py")
    prompt_for_frida()

# Frida Integration
def launch_frida_menu():
    subprocess.Popen(["gnome-terminal", "--", "python3", "/home/flintx/flow/fridamenu.py"])
    print(f"{GREEN}Frida menu launched in a new terminal!{RESET}")

# Prompt for Frida after launching Burp or Mitmproxy
def prompt_for_frida():
    choice = input(f"{CYAN}Do you want to launch fridamenu.py in a new terminal? (y/n): {RESET}").lower()
    if choice == 'y':
        launch_frida_menu()
    else:
        print(f"{YELLOW}Returning to menu...{RESET}")

# Main Menu
def main_menu():
    while True:
        display_dashboard()
        print(f"{PURPLE}--- MAIN MENU ---{RESET}")
        print("1. Set Emulator Proxy")
        print("2. Set Reverse Port")
        print("3. Set Forward Port")
        print("4. Reconfigure SELinux")
        print("5. Enable ADB Root")
        print("6. Kill ADB Server")
        print("7. Start ADB Server")
        print("8. Reset Global Proxy")
        print("9. Reboot Emulator")
        print("10. Check ADB Settings")
        print("11. Launch Burp")
        print("12. Launch Mitmproxy")
        print("13. Launch Frida Menu")
        print("14. Exit")
        
        choice = input(f"{CYAN}Select an option: {RESET}")
        if choice == '1':
            set_emulator_proxy()
        elif choice == '2':
            run_command("adb reverse tcp:8080 tcp:8080")
        elif choice == '3':
            run_command("adb forward tcp:8080 tcp:8080")
        elif choice == '4':
            reconfigure_selinux()
        elif choice == '5':
            run_command("adb root")
        elif choice == '6':
            run_command("adb kill-server")
        elif choice == '7':
            run_command("adb start-server")
        elif choice == '8':
            run_command("adb shell settings put global http_proxy \"\"")
        elif choice == '9':
            run_command("adb reboot")
        elif choice == '10':
            print(f"{CYAN}Checking ADB settings...{RESET}")
            run_command("adb shell getprop")
        elif choice == '11':
            launch_burp()
        elif choice == '12':
            launch_mitmproxy()
        elif choice == '13':
            launch_frida_menu()
        elif choice == '14':
            print(f"{GREEN}Exiting...{RESET}")
            break
        else:
            print(f"{RED}Invalid choice. Try again.{RESET}")
        time.sleep(2)

if __name__ == "__main__":
    main_menu()
