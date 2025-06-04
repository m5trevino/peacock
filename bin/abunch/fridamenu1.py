import subprocess
import os
import time

# Define colors
DARK_RED = '\033[31m'
BRIGHT_RED = '\033[91m'
BRIGHT_GREEN = '\033[92m'
BRIGHT_PURPLE = '\033[95m'
BOLD = '\033[1m'
RESET = '\033[0m'

# Define paths
LOCAL_FRIDA_DIR = "/home/flintx/flow/fridafiles"
DEVICE_FRIDA_SERVER_PATH = "/data/local/tmp/frida-server"
DEVICE_FRIDA_GADGET_PATH = "/data/local/tmp/frida-gadget"
DEVICE_TMP_DIR = "/data/local/tmp/"

# Helper function to run shell commands
def run_command(command):
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout.strip()

# Check if Frida Server file exists on the device
def check_frida_server_path():
    output = run_command(f"adb shell ls {DEVICE_FRIDA_SERVER_PATH} 2>/dev/null")
    if "No such file or directory" in output or not output:
        return f"{BOLD}{DARK_RED}Frida-Server NOT FOUND{RESET}"
    else:
        return f"{BOLD}{BRIGHT_GREEN}Frida-Server found at {DEVICE_FRIDA_SERVER_PATH}{RESET}"

# Check if Frida Gadget file exists on the device
def check_frida_gadget_path():
    output = run_command(f"adb shell ls {DEVICE_FRIDA_GADGET_PATH} 2>/dev/null")
    if "No such file or directory" in output or not output:
        return f"{BOLD}{DARK_RED}Frida-Gadget NOT FOUND{RESET}"
    else:
        return f"{BOLD}{BRIGHT_GREEN}Frida-Gadget found at {DEVICE_FRIDA_GADGET_PATH}{RESET}"

# Check if Frida Server is active using lsof and netstat
def check_if_frida_server_is_active():
    lsof_output = run_command("lsof -i :27042")
    netstat_output = run_command("netstat -tuln | grep :27042")
    if lsof_output or netstat_output:
        pid = run_command("ps aux | grep frida-server | grep -v grep | awk '{print $2}'")
        return f"{BOLD}{BRIGHT_GREEN}Frida Server is ACTIVE - PID: {pid} - PORT: 27042{RESET}"
    else:
        return f"{BOLD}{DARK_RED}Frida Server is NOT ACTIVE{RESET}"

# Fetch device architecture
def get_device_architecture():
    output = run_command("adb shell getprop ro.product.cpu.abi")
    if not output:
        return f"{BOLD}{DARK_RED}Architecture: UNKNOWN{RESET}"
    return f"{BOLD}{BRIGHT_GREEN}Architecture: {output}{RESET}"

# Start Frida Server on the device
def start_frida_server():
    print("Attempting to start Frida Server on the device...")
    command = f"adb shell {DEVICE_FRIDA_SERVER_PATH}"
    print(f"{BOLD}{BRIGHT_PURPLE}Command: {command}{RESET}")
    output = run_command(command)
    print(f"{BOLD}{BRIGHT_GREEN}CLI Output:{RESET}\n{output}")
    input(f"\n{BRIGHT_PURPLE}Press Enter to return to the menu.{RESET}")

# List files in the local Frida directory and allow selection
def list_and_select_file():
    files = [f for f in os.listdir(LOCAL_FRIDA_DIR) if os.path.isfile(os.path.join(LOCAL_FRIDA_DIR, f))]
    if not files:
        print(f"{BOLD}{DARK_RED}No files found in {LOCAL_FRIDA_DIR}{RESET}")
        return None
    print("Available files:")
    for idx, file in enumerate(files, 1):
        print(f"{BRIGHT_GREEN}{idx}. {file}{RESET}")
    try:
        choice = int(input("Enter the number of the file to send: "))
        if 1 <= choice <= len(files):
            return files[choice - 1]
        else:
            print(f"{BOLD}{BRIGHT_RED}Invalid choice. Please try again.{RESET}")
            return None
    except ValueError:
        print(f"{BOLD}{BRIGHT_RED}Invalid input. Please enter a number.{RESET}")
        return None

# Push a file to the device and set permissions
def push_file_to_device(local_file, device_path):
    print(f"Pushing {local_file} to device: {device_path}")
    full_local_path = os.path.join(LOCAL_FRIDA_DIR, local_file)
    output = run_command(f"adb push {full_local_path} {device_path}")
    print(output)
    print(f"Setting permissions for {device_path}")
    permission_output = run_command(f"adb shell chmod 755 {device_path}")
    print(permission_output)

# Push Frida Server to device
def push_frida_server():
    print(f"Pushing Frida-Server to device...")
    selected_file = list_and_select_file()
    if selected_file:
        push_file_to_device(selected_file, DEVICE_FRIDA_SERVER_PATH)
        print(f"{BOLD}{BRIGHT_GREEN}File {selected_file} successfully pushed and permissions set.{RESET}")

# Push Frida Gadget to device
def push_frida_gadget():
    print(f"Pushing Frida-Gadget to device...")
    selected_file = list_and_select_file()
    if selected_file:
        push_file_to_device(selected_file, DEVICE_FRIDA_GADGET_PATH)
        print(f"{BOLD}{BRIGHT_GREEN}File {selected_file} successfully pushed and permissions set.{RESET}")

# Remove files interactively from /data/local/tmp/
def remove_files_interactively(device_path=DEVICE_TMP_DIR):
    print(f"{BOLD}Fetching files from {device_path}...{RESET}")
    file_list = run_command(f"adb shell ls {device_path}").splitlines()
    if "No such file or directory" in file_list or not file_list:
        print(f"{BOLD}{DARK_RED}No files found in {device_path}.{RESET}")
        return
    for file in file_list:
        if file.strip():
            full_path = os.path.join(device_path, file)
            response = input(f"Delete {BOLD}{file}{RESET}? [y/N]: ").strip().lower()
            if response == 'y':
                run_command(f"adb shell rm {full_path}")
                print(f"{BOLD}{BRIGHT_GREEN}Deleted: {file}{RESET}")
            else:
                print(f"{BOLD}{BRIGHT_PURPLE}Skipped: {file}{RESET}")

# Display the dashboard
def show_dashboard():
    os.system('clear')
    print("┣▇▇▇═─ Frida Menu Dashboard ┣▇▇▇═─")
    print(f"Device:")
    print(check_frida_server_path())
    print(check_frida_gadget_path())
    print(get_device_architecture())
    print(check_if_frida_server_is_active())
    frida_version = run_command("pip list | grep frida | grep -v frida-tools | grep -v frida-gadget | awk '{print $2}'")
    frida_tools_version = run_command("pip list | grep frida-tools | awk '{print $2}'")
    frida_gadget_version = run_command("pip list | grep frida-gadget | awk '{print $2}'")
    print(f"Local: Frida {BOLD}{BRIGHT_GREEN}{frida_version}{RESET} - "
          f"Frida Tools {BOLD}{BRIGHT_GREEN}{frida_tools_version}{RESET} - "
          f"Frida Gadget {BOLD}{BRIGHT_GREEN}{frida_gadget_version}{RESET}")
    print("┣▇▇▇═─ ┣▇▇▇═─ ┣▇▇▇═─ ┣▇▇▇═─ ┣▇▇▇═─ ┣▇▇▇═─")
    print("")

# Menu
def show_menu():
    while True:
        show_dashboard()
        print("┣▇▇▇═─ Frida Menu ┣▇▇▇═─")
        print(f"{BRIGHT_GREEN}1. Start Frida Server{RESET}")
        print(f"{BRIGHT_PURPLE}2. Restart Frida Server{RESET}")
        print(f"{BRIGHT_GREEN}3. Push Frida Server to Device{RESET}")
        print(f"{BRIGHT_PURPLE}4. Push Frida Gadget to Device{RESET}")
        print(f"{BRIGHT_GREEN}5. Check Permissions for Frida Server and Gadget{RESET}")
        print(f"{BRIGHT_PURPLE}6. Set Permissions for Frida Server and Gadget{RESET}")
        print(f"{BRIGHT_GREEN}7. Remove Frida Server and Gadget (Interactive){RESET}")
        print(f"{BRIGHT_PURPLE}8. Check if Frida Server is Active{RESET}")
        print(f"{BRIGHT_GREEN}9. View Logs{RESET}")
        print(f"{BRIGHT_PURPLE}10. Check with lsof and netstat{RESET}")
        print(f"{BRIGHT_GREEN}11. Exit{RESET}")
        print("")
        
        choice = input("Enter your choice: ")
        if choice == '1':
            start_frida_server()
        elif choice == '2':
            remove_files_interactively()
            push_frida_server()
        elif choice == '3':
            push_frida_server()
        elif choice == '4':
            push_frida_gadget()
        elif choice == '5':
            print("Permissions can be checked using `adb shell ls -l`.")
        elif choice == '6':
            pass
        elif choice == '7':
            remove_files_interactively()
        elif choice == '8':
            print(check_if_frida_server_is_active())
            input(f"{BRIGHT_PURPLE}Press Enter to return to the menu.{RESET}")
        elif choice == '9':
            os.system("tail -n 10 fridamenu.log")
        elif choice == '10':
            check_frida_server_status()
        elif choice == '11':
            print(f"{BRIGHT_PURPLE}Exiting...{RESET}")
            break
        else:
            print(f"{DARK_RED}Invalid choice. Try again!{RESET}")
        time.sleep(2)

# Main entry point
if __name__ == "__main__":
    show_menu()
