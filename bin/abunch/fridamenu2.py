import os
import subprocess
import time

# Colors for Cyberpunk theme
CYAN = "\033[1;36m"
GREEN = "\033[1;32m"
PURPLE = "\033[1;35m"
YELLOW = "\033[1;33m"
RED = "\033[1;31m"
RESET = "\033[0m"

# Paths and settings
LOCAL_FRIDA_DIR = "/home/flintx/flow/fridafiles"
DEVICE_FRIDA_SERVER_PATH = "/data/local/tmp/frida-server"
DEVICE_FRIDA_GADGET_PATH = "/data/local/tmp/frida-gadget"
DEVICE_TMP_DIR = "/data/local/tmp/"
DEFAULT_FRIDA_SCRIPT_DIR = "/home/flintx/fridascripts"

# Helper functions
def run_command(command):
    print(f"{CYAN}Executing: {command}{RESET}")
    try:
        output = subprocess.check_output(command, shell=True, text=True)
        return output.strip()
    except subprocess.CalledProcessError as e:
        return None

def display_dashboard():
    os.system('clear')
    print(f"{PURPLE}--- FRIDA MENU DASHBOARD ---{RESET}")
    emulator_name = run_command('adb devices | grep emulator | cut -f1') or "No Emulator Detected"
    architecture = run_command('adb shell getprop ro.product.cpu.abi') or "UNKNOWN"
    frida_server_status = check_frida_server_status()
    gadget_status = check_frida_gadget_path()

    print(f"{YELLOW}Device:{RESET}")
    print(f"{GREEN}Frida-Server found at {frida_server_status}{RESET}")
    print(f"{GREEN}Frida-Gadget found at {gadget_status}{RESET}")
    print(f"{GREEN}Architecture: {architecture}{RESET}")
    print(f"{RED if not check_if_frida_server_is_active() else GREEN}Frida Server is NOT ACTIVE{RESET}")
    print(f"{YELLOW}Local: {get_local_frida_versions()}{RESET}")
    print("\n")

# Check if Frida Server and Gadget paths exist
def check_frida_server_status():
    return run_command(f'adb shell ls {DEVICE_FRIDA_SERVER_PATH}') or "NOT FOUND"

def check_frida_gadget_path():
    return run_command(f'adb shell ls {DEVICE_FRIDA_GADGET_PATH}') or "NOT FOUND"

# Check if Frida Server is active
def check_if_frida_server_is_active():
    return run_command('lsof -i :27042') is not None

def get_local_frida_versions():
    frida_version = run_command("pip list | grep -E '^frida\s' | awk '{print $2}'")
    tools_version = run_command("pip list | grep -E '^frida-tools\s' | awk '{print $2}'")
    return f"Frida {frida_version.strip() if frida_version else 'N/A'} - Frida Tools {tools_version.strip() if tools_version else 'N/A'}"

# Frida Menu Options
def push_frida_server():
    selected_file = list_and_select_file(LOCAL_FRIDA_DIR)
    if selected_file:
        push_file_to_device(selected_file, DEVICE_FRIDA_SERVER_PATH)

def push_frida_gadget():
    selected_file = list_and_select_file(LOCAL_FRIDA_DIR)
    if selected_file:
        push_file_to_device(selected_file, DEVICE_FRIDA_GADGET_PATH)

def push_file_to_device(local_file, device_path):
    run_command(f'adb push {os.path.join(LOCAL_FRIDA_DIR, local_file)} {device_path}')
    run_command(f'adb shell chmod 755 {device_path}')

def start_frida_server():
    run_command(f'adb shell {DEVICE_FRIDA_SERVER_PATH}')

def restart_frida_server():
    run_command('adb shell killall frida-server')
    start_frida_server()

def list_and_select_file(directory):
    files = [f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))]
    if not files:
        print(f"{RED}No files found in {directory}{RESET}")
        return None
    print(f"{CYAN}Available files:{RESET}")
    for idx, file in enumerate(files, 1):
        print(f"{GREEN}{idx}. {file}{RESET}")
    try:
        choice = int(input(f"{YELLOW}Enter the number of the file to select: {RESET}"))
        return files[choice - 1] if 1 <= choice <= len(files) else None
    except ValueError:
        print(f"{RED}Invalid input.{RESET}")
        return None

def launch_frida_script():
    print(f"{CYAN}Listing installed apps...{RESET}")
    apps = run_command('adb shell pm list packages').splitlines()
    apps = [app.split(':')[1] for app in apps]
    for idx, app in enumerate(apps, 1):
        print(f"{GREEN}{idx}. {app}{RESET}")
    try:
        app_choice = int(input(f"{YELLOW}Select app by number: {RESET}")) - 1
        app_name = apps[app_choice]
        script_file = list_and_select_file(DEFAULT_FRIDA_SCRIPT_DIR)
        if script_file:
            run_command(f'frida -U -f {app_name} -l {os.path.join(DEFAULT_FRIDA_SCRIPT_DIR, script_file)}')
    except (ValueError, IndexError):
        print(f"{RED}Invalid app selection.{RESET}")

def attach_to_process_by_pid():
    pid = input(f"{YELLOW}Enter the PID to attach to: {RESET}")
    if pid.isdigit():
        run_command(f'frida -U -n {pid}')
    else:
        print(f"{RED}Invalid PID.{RESET}")

def trace_function():
    package = input(f"{YELLOW}Enter the package name to trace: {RESET}")
    function_name = input(f"{YELLOW}Enter the function name to trace: {RESET}")
    if package and function_name:
        run_command(f'frida-trace -U -n {package} -m {function_name}')
    else:
        print(f"{RED}Invalid input.{RESET}")

# Main Menu
def main_menu():
    while True:
        display_dashboard()
        print(f"{YELLOW}--- Main Menu ---{RESET}")
        print("1. Start Frida Server")
        print("2. Restart Frida Server")
        print("3. Push Frida Server to Device")
        print("4. Push Frida Gadget to Device")
        print("5. Launch Frida Script")
        print("6. Attach to Process by PID")
        print("7. Trace a Function")
        print("8. Kill Frida Server on Device")
        print("9. Check if Frida Server is Active")
        print("10. Exit")

        choice = input(f"{CYAN}Select an option: {RESET}")

        if choice == '1':
            start_frida_server()
        elif choice == '2':
            restart_frida_server()
        elif choice == '3':
            push_frida_server()
        elif choice == '4':
            push_frida_gadget()
        elif choice == '5':
            launch_frida_script()
        elif choice == '6':
            attach_to_process_by_pid()
        elif choice == '7':
            trace_function()
        elif choice == '8':
            run_command('adb shell killall frida-server')
        elif choice == '9':
            print(check_if_frida_server_is_active())
            input(f"{PURPLE}Press Enter to return to the menu.{RESET}")
        elif choice == '10':
            print(f"{GREEN}Exiting...{RESET}")
            break
        else:
            print(f"{RED}Invalid choice. Try again.{RESET}")
        time.sleep(2)

if __name__ == "__main__":
    main_menu()