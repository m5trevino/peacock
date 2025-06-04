import os
import subprocess
import time

# Log to keep track of executed commands
log = []

# Helper function to add entries to the log
def add_to_log(command, output):
    log_entry = {
        "command": command,
        "output": output
    }
    log.append(log_entry)
    if len(log) > 5:  # Limit log to the last 5 commands
        log.pop(0)

# Get Local IP Address
def get_local_ip():
    try:
        ip = subprocess.check_output(['hostname', '-I']).decode().split()[0]
    except Exception as e:
        ip = "Unknown"
    return ip

# Get Emulator Name
def get_emulator_name():
    try:
        output = subprocess.check_output(['adb', 'devices']).decode()
        lines = output.strip().split("\n")[1:]
        if lines:
            emulator = lines[0].split("\t")[0]
        else:
            emulator = "No Emulator Detected"
    except Exception as e:
        emulator = "Error Detecting Emulator"
    return emulator

# Check ADB Settings Status
def check_adb_settings():
    try:
        proxy = subprocess.check_output("adb shell settings get global http_proxy", shell=True).decode().strip()
        proxy = proxy if proxy else "No Proxy Set"
    except subprocess.CalledProcessError:
        proxy = "Error Fetching Proxy"

    try:
        reverse_list = subprocess.check_output("adb reverse --list", shell=True).decode().strip()
        reverse_list = reverse_list if reverse_list else "No Reverse Mappings"
    except subprocess.CalledProcessError:
        reverse_list = "Error Fetching Reverse Mappings"

    try:
        selinux_status = subprocess.check_output("adb shell getenforce", shell=True).decode().strip()
    except subprocess.CalledProcessError:
        selinux_status = "Error Fetching SELinux Status"

    try:
        adb_root_status = subprocess.check_output("adb root", shell=True).decode().strip()
        if "already running as root" in adb_root_status:
            adb_root_status = "ADB Root Active"
        else:
            adb_root_status = "ADB Root Not Active"
    except subprocess.CalledProcessError:
        adb_root_status = "Error Fetching ADB Root Status"

    return {
        "Proxy": proxy,
        "Reverse TCP": reverse_list,
        "SELinux": selinux_status,
        "ADB Root": adb_root_status
    }

# Display Log
def display_log():
    print("\033[1;33m[COMMAND LOG]\033[0m")
    if not log:
        print("No commands executed yet.")
    else:
        for i, entry in enumerate(log, start=1):
            print(f"{i}. {entry['command']}")
            print(f"   Output: {entry['output']}")

# Rename terminal
def rename_terminal(new_title):
    os.system(f"xdotool getactivewindow set_window --name {new_title}")

# Launch Frida Menu
def launch_frida_menu():
    try:
        print("Launching Frida Menu...")
        subprocess.Popen(["xfce4-terminal", "--title=fridamenu", "-e", "python3 /home/flintx/flow/fridamenu.py"])
        os.system(f"xdotool set_desktop_for_window $(xdotool getactivewindow) 2")
    except Exception as e:
        print(f"Error launching Frida Menu: {e}")

# Menu and Dashboard Management
def main_menu():
    rename_terminal("adbmenu")
    while True:
        os.system('clear')
        # Fetch dynamic data
        ip_address = get_local_ip()
        emulator_name = get_emulator_name()
        adb_status = check_adb_settings()

        # Display log and dashboard
        display_log()
        print(f"\033[1;32m[ADB DASHBOARD]\033[0m")
        print(f"Emulator: \033[1;34m{emulator_name}\033[0m")
        print(f"IP Address: \033[1;34m{ip_address}\033[0m")
        print(f"Proxy: \033[1;34m{adb_status['Proxy']}\033[0m")
        print(f"Reverse TCP: \033[1;34m{adb_status['Reverse TCP']}\033[0m")
        print(f"SELinux: \033[1;34m{adb_status['SELinux']}\033[0m")
        print(f"ADB Root: \033[1;34m{adb_status['ADB Root']}\033[0m")
        print("\033[1;33m--- Menu ---\033[0m")

        print("1. Set Emulator Proxy")
        print("2. Set Reverse Port")
        print("3. Set Forward Port")
        print("4. Kill ADB Server")
        print("5. Start ADB Server")
        print("6. Reset Global Proxy")
        print("7. Reboot Emulator")
        print("8. Reconfigure SELinux")
        print("9. Check ADB Settings")
        print("10. Enable ADB Root")
        print("11. Launch Frida Menu")
        print("12. Exit")
        print("\n")

        # Handle menu choices
        choice = input("Select an option: ")
        if choice == "12":
            print("Exiting...")
            break
        elif choice == "1":
            set_proxy()
        elif choice == "2":
            set_reverse_port()
        elif choice == "3":
            set_forward_port()
        elif choice == "4":
            manage_adb_server("kill")
        elif choice == "5":
            manage_adb_server("start")
        elif choice == "6":
            reset_proxy()
        elif choice == "7":
            reboot_emulator()
        elif choice == "8":
            reconfigure_selinux()
        elif choice == "9":
            check_adb_status_menu()
        elif choice == "10":
            enable_adb_root()
        elif choice == "11":
            launch_frida_menu()
            break
        else:
            print("Invalid choice. Please try again.")
        time.sleep(2)

# Individual Features Implementation
def set_proxy():
    ip = input("Enter Proxy IP (default: 192.168.1.100): ") or "192.168.1.100"
    port = input("Enter Proxy Port (default: 8080): ") or "8080"
    command = f"adb shell settings put global http_proxy {ip}:{port}"
    output = execute_command(command)
    add_to_log(command, output)

def set_reverse_port():
    local_port = input("Enter Local Port: ")
    emulator_port = input("Enter Emulator Port: ")
    command = f"adb reverse tcp:{emulator_port} tcp:{local_port}"
    output = execute_command(command)
    add_to_log(command, output)

def set_forward_port():
    local_port = input("Enter Local Port: ")
    emulator_port = input("Enter Emulator Port: ")
    command = f"adb forward tcp:{local_port} tcp:{emulator_port}"
    output = execute_command(command)
    add_to_log(command, output)

def manage_adb_server(action):
    command = f"adb {action}-server"
    output = execute_command(command)
    add_to_log(command, output)

def reset_proxy():
    command = "adb shell settings put global http_proxy \"\""
    output = execute_command(command)
    add_to_log(command, output)

def reboot_emulator():
    command = "adb reboot"
    output = execute_command(command)
    add_to_log(command, output)

def reconfigure_selinux():
    print("1. Set to Enforcing")
    print("2. Set to Permissive")
    choice = input("Select SELinux mode: ")
    if choice == "1":
        command = "adb shell setenforce 1"
    elif choice == "2":
        command = "adb shell setenforce 0"
    else:
        print("Invalid choice.")
        return
    output = execute_command(command)
    add_to_log(command, output)

def check_adb_status_menu():
    status = check_adb_settings()
    print("\n[ADB SETTINGS STATUS]")
    print(f"Proxy: {status['Proxy']}")
    print(f"Reverse TCP: {status['Reverse TCP']}")
    print(f"SELinux: {status['SELinux']}")
    print(f"ADB Root: {status['ADB Root']}")
    input("\nPress Enter to return to the menu...")

def enable_adb_root():
    command = "adb root"
    output = execute_command(command)
    add_to_log(command, output)

def execute_command(command):
    try:
        print(f"Executing: {command}")
        output = subprocess.check_output(command, shell=True).decode()
        print(f"Output: {output}")
        return output
    except subprocess.CalledProcessError as e:
        error_message = e.output.decode() if e.output else "Unknown Error"
        print(f"Error: {error_message}")
        return error_message

if __name__ == "__main__":
    main_menu()
