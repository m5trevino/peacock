import os
import subprocess
import time
import requests
import wget

# ANSI escape codes for Cyberpunk theme
CYAN = "\033[1;36m"
GREEN = "\033[1;32m"
PURPLE = "\033[1;35m"
YELLOW = "\033[1;33m"
RED = "\033[1;31m"
RESET = "\033[0m"

# Configuration paths and constants
LOCAL_FRIDA_DIR = "/home/flintx/flow/fridafiles"
FRIDA_SERVER_DIR = "/home/flintx/flow/fridafiles/frida.server"
FRIDA_GADGET_DIR = "/home/flintx/flow/fridafiles/frida.gadget"
DEVICE_FRIDA_SERVER_PATH = "/data/local/tmp/frida-server"
DEVICE_FRIDA_GADGET_PATH = "/data/local/tmp/frida-gadget"
DEVICE_TMP_DIR = "/data/local/tmp/"
DEFAULT_FRIDA_SCRIPT_DIR = "/home/flintx/fridascripts"
CERT_DIR = "/home/flintx/flow/certs/"
ANDROID_CERT_DIR = "/sdcard/Download/"
JAVA_PATH = "/opt/jdk-21.0.5+11-jre/bin/java"
BURP_JAR_PATH = "/home/flintx/burp/burpsuite.jar"
BURP_LOADER_PATH = "/home/flintx/burp/burploader.jar"
MITMPROXY_CERT_PATH = os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.pem")

# Helper function to run a command
def run_command(command, suppress_output=False):
    print(f"{CYAN}Executing: {command}{RESET}")
    try:
        if suppress_output:
            result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            return result.stdout.strip()
        else:
            result = subprocess.check_output(command, shell=True, text=True).strip()
            return result
    except subprocess.CalledProcessError as e:
        print(f"{RED}Error executing command: {e}{RESET}")
        return None

# Frida Helper Functions
def get_device_architecture():
    arch = run_command('adb shell getprop ro.product.cpu.abi')
    return arch.strip() if arch else "unknown"

def get_matching_frida_server(arch, version):
    server_files = os.listdir(FRIDA_SERVER_DIR)
    matching_file = next((f for f in server_files if version in f and arch in f), None)
    return matching_file

def download_frida_files(version, arch):
    base_url = f"https://github.com/frida/frida/releases/download/{version}"

    # Download server
    server_file = f"frida-server-{version}-android-{arch}"
    server_url = f"{base_url}/{server_file}.xz"

    # Download gadget
    gadget_file = f"frida-gadget-{version}-android-{arch}"
    gadget_url = f"{base_url}/{gadget_file}.so.xz"

    print(f"{CYAN}Downloading Frida files...{RESET}")

    # Create directories if they don't exist
    os.makedirs(FRIDA_SERVER_DIR, exist_ok=True)
    os.makedirs(FRIDA_GADGET_DIR, exist_ok=True)

    try:
        # Download and extract server
        run_command(f"wget {server_url} -O {FRIDA_SERVER_DIR}/{server_file}.xz")
        run_command(f"xz -d {FRIDA_SERVER_DIR}/{server_file}.xz")

        # Download and extract gadget
        run_command(f"wget {gadget_url} -O {FRIDA_GADGET_DIR}/{gadget_file}.so.xz")
        run_command(f"xz -d {FRIDA_GADGET_DIR}/{gadget_file}.so.xz")

        print(f"{GREEN}Successfully downloaded Frida files{RESET}")
        return True
    except Exception as e:
        print(f"{RED}Error downloading Frida files: {e}{RESET}")
        return False

def sync_frida_versions():
    print(f"{CYAN}Synchronizing Frida versions...{RESET}")

    # Get local Frida version
    local_version = run_command("pip list | grep -E '^frida\\s' | awk '{print $2}'")
    if not local_version:
        print(f"{RED}Frida not installed locally{RESET}")
        return False

    # Get device architecture
    arch = get_device_architecture()
    if arch == "unknown":
        print(f"{RED}Could not determine device architecture{RESET}")
        return False

    print(f"{YELLOW}Local Frida version: {local_version}{RESET}")
    print(f"{YELLOW}Device architecture: {arch}{RESET}")

    # Install/Update local Frida packages
    print(f"{CYAN}Installing/Updating Frida packages...{RESET}")
    run_command(f"pip install --upgrade frida=={local_version}")
    run_command(f"pip install --upgrade frida-tools")

    # Download matching Frida server and gadget if needed
    matching_server = get_matching_frida_server(arch, local_version)
    if not matching_server:
        print(f"{YELLOW}Downloading matching Frida server and gadget...{RESET}")
        if not download_frida_files(local_version, arch):
            return False

def remove_frida_from_local():
    print(f"{CYAN}Removing Frida from local machine...{RESET}")
    run_command("pip uninstall -y frida frida-tools")
    print(f"{GREEN}Frida removed from local machine.{RESET}")

def remove_frida_from_device():
    print(f"{CYAN}Removing Frida from device...{RESET}")
    run_command("adb shell rm -f /data/local/tmp/frida-server")
    run_command("adb shell rm -f /data/local/tmp/frida-gadget")
    print(f"{GREEN}Frida removed from device.{RESET}")

    # Push files to device
    print(f"{CYAN}Pushing Frida files to device...{RESET}")
    matching_server = get_matching_frida_server(arch, local_version)
    if matching_server:
        push_file_to_device(os.path.join("frida.server", matching_server), DEVICE_FRIDA_SERVER_PATH)

    # Also push the Frida gadget
    matching_gadget = f"frida-gadget-{local_version}-android-{arch}.so"
    gadget_path = os.path.join(FRIDA_GADGET_DIR, matching_gadget)
    if os.path.exists(gadget_path):
        push_file_to_device(os.path.join("frida.gadget", matching_gadget), DEVICE_FRIDA_GADGET_PATH)

    # Restart Frida server
    print(f"{CYAN}Restarting Frida server...{RESET}")
    restart_frida_server()

    print(f"{GREEN}Frida synchronization complete!{RESET}")
    return True

def fresh_install_frida():
    remove_frida_from_local()
    remove_frida_from_device()
    print(f"{CYAN}Installing Frida fresh...{RESET}")

    # Assuming you have the latest version in mind, you can adjust this as needed

    latest_version = "16.6.6"  # Update this to the desired version
    arch = get_device_architecture()
    download_frida_files(latest_version, arch)
    push_file_to_device(os.path.join("frida.server", f"frida-server-{latest_version}-android-{arch}"), DEVICE_FRIDA_SERVER_PATH)
    push_file_to_device(os.path.join("frida.gadget", f"frida-gadget-{latest_version}-android-{arch}.so"), DEVICE_FRIDA_GADGET_PATH)
    print(f"{GREEN}Frida has been installed fresh on both local machine and device.{RESET}")

def check_frida_server_status():
    return run_command(f'adb shell ls {DEVICE_FRIDA_SERVER_PATH}') or "NOT FOUND"

def check_frida_gadget_path():
    try:
        result = run_command(f'adb shell ls {DEVICE_FRIDA_GADGET_PATH}')
        return result if result else "NOT FOUND"
    except Exception:
        return "NOT FOUND"

def check_if_frida_server_is_active():
    try:
        result = run_command('lsof -i :27042', suppress_output=True)
        return result is not None and result != ""
    except Exception:
        return False

def get_local_frida_versions():
    frida_version = run_command("pip list | grep -E '^frida\s' | awk '{print $2}'")
    tools_version = run_command("pip list | grep -E '^frida-tools\s' | awk '{print $2}'")
    return f"Frida {frida_version.strip() if frida_version else 'N/A'} - Frida Tools {tools_version.strip() if tools_version else 'N/A'}"

def display_frida_dashboard():
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
    print(f"{RED if not check_if_frida_server_is_active() else GREEN}Frida Server is {'NOT ' if not check_if_frida_server_is_active() else ''}ACTIVE{RESET}")
    print(f"{YELLOW}Local: {get_local_frida_versions()}{RESET}")
    print("\n")

# Frida Menu Functions
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

def push_file_to_device(local_file, device_path):
    run_command(f'adb push {os.path.join(LOCAL_FRIDA_DIR, local_file)} {device_path}')
    run_command(f'adb shell chmod 755 {device_path}')

def push_frida_server():
    selected_file = list_and_select_file(FRIDA_SERVER_DIR)
    if selected_file:
        push_file_to_device(os.path.join("frida.server", selected_file), DEVICE_FRIDA_SERVER_PATH)

def push_frida_gadget():
    selected_file = list_and_select_file(FRIDA_GADGET_DIR)
    if selected_file:
        push_file_to_device(os.path.join("frida.gadget", selected_file), DEVICE_FRIDA_GADGET_PATH)

def start_frida_server():
    run_command(f'adb shell {DEVICE_FRIDA_SERVER_PATH}')

def restart_frida_server():
    try:
        print(f"{CYAN}Stopping Frida server (if running)...{RESET}")
        run_command('adb shell killall frida-server')
    except Exception:
        print(f"{YELLOW}Frida server was not running. Proceeding to start it...{RESET}")
    print(f"{CYAN}Starting Frida server...{RESET}")
    run_command(f'adb shell {DEVICE_FRIDA_SERVER_PATH} &')

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

def frida_menu():
    while True:
        display_frida_dashboard()
        print(f"{YELLOW}--- Frida Menu ---{RESET}")
        print("1. Start Frida Server")
        print("2. Restart Frida Server")
        print("3. Push Frida Server to Device")
        print("4. Push Frida Gadget to Device")
        print("5. Launch Frida Script")
        print("6. Attach to Process by PID")
        print("7. Trace a Function")
        print("8. Kill Frida Server on Device")
        print("9. Check if Frida Server is Active")
        print("10. Sync Frida Versions")
        print("11. Fresh Install Frida")  # New option
        print("12. Return to Main Menu")

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
            sync_frida_versions()
            input(f"{PURPLE}Press Enter to return to the menu.{RESET}")
        elif choice == '11':
            fresh_install_frida()  # Call the fresh install function
            input(f"{PURPLE}Press Enter to return to the menu.{RESET}")
        elif choice == '12':
            print(f"{GREEN}Returning to main menu...{RESET}")
            break
        else:
            print(f"{RED}Invalid choice. Try again.{RESET}")
            time.sleep(2)

# Function to import Mitmproxy certificate
def import_mitmproxy_cert():
    if not os.path.exists(MITMPROXY_CERT_PATH):
        print(f"{RED}Mitmproxy certificate not found at {MITMPROXY_CERT_PATH}.{RESET}")
        return

    dest_path = os.path.join(CERT_DIR, "mitmproxy-ca-cert.pem")
    try:
        subprocess.run(f"cp {MITMPROXY_CERT_PATH} {dest_path}", shell=True, check=True)
        print(f"{GREEN}Imported Mitmproxy certificate to {dest_path}.{RESET}")
    except subprocess.CalledProcessError as e:
        print(f"{RED}Error importing Mitmproxy certificate: {e}{RESET}")

# Burp Functions
def start_burp():
    try:
        subprocess.Popen([
            JAVA_PATH,
            "--add-opens=java.desktop/javax.swing=ALL-UNNAMED",
            "--add-opens=java.base/java.lang=ALL-UNNAMED",
            "--add-opens=java.base/jdk.internal.org.objectweb.asm=ALL-UNNAMED",
            "--add-opens=java.base/jdk.internal.org.objectweb.asm.tree=ALL-UNNAMED",
            "--add-opens=java.base/jdk.internal.org.objectweb.asm.Opcodes=ALL-UNNAMED",
            "-javaagent:" + BURP_LOADER_PATH,
            "-noverify",
            "-jar",
            BURP_JAR_PATH
        ])
        print(f"{GREEN}Burp Suite is starting...{RESET}")
    except Exception as e:
        print(f"{RED}Error starting Burp Suite: {e}{RESET}")

def list_certs():
    cert_files = [f for f in os.listdir(CERT_DIR) if f.endswith('.der') or f.endswith('.pem')]
    return cert_files

def convert_der_to_pem():
    cert_files = [f for f in os.listdir(CERT_DIR) if f.endswith('.der')]
    if not cert_files:
        print(f"{RED}No DER files found.{RESET}")
        return
    print(f"{CYAN}DER files found:{RESET}")
    for index, cert in enumerate(cert_files, 1):
        print(f"{PURPLE}{index}. {cert}{RESET}")

    choice = input(f"{YELLOW}Convert all DER files to PEM? (y/n): {RESET}")
    if choice.lower() == "y":
        for cert in cert_files:
            der_path = os.path.join(CERT_DIR, cert)
            pem_path = os.path.join(CERT_DIR, cert.replace('.der', '.pem'))
            command = f"openssl x509 -inform der -in {der_path} -out {pem_path}"
            subprocess.run(command, shell=True, check=True)
            print(f"{GREEN}Converted {cert} to PEM.{RESET}")

def push_pem_to_android():
    pem_files = [f for f in os.listdir(CERT_DIR) if f.endswith('.pem')]
    if not pem_files:
        print(f"{RED}No PEM files found.{RESET}")
        return
    print(f"{CYAN}PEM files found:{RESET}")
    for index, pem in enumerate(pem_files, 1):
        print(f"{PURPLE}{index}. {pem}{RESET}")

    choice = input(f"{YELLOW}Push all PEM files to Android? (y/n): {RESET}")
    if choice.lower() == "y":
        for pem in pem_files:
            pem_path = os.path.join(CERT_DIR, pem)
            command = f"adb push {pem_path} {ANDROID_CERT_DIR}"
            try:
                subprocess.run(command, shell=True, check=True)
                print(f"{GREEN}Pushed {pem} to Android.{RESET}")
            except subprocess.CalledProcessError as e:
                print(f"{RED}Error pushing {pem} to Android: {e}{RESET}")

def pull_certs_from_android():
    try:
        result = subprocess.check_output(f"adb shell ls {ANDROID_CERT_DIR}", shell=True, text=True).strip()
        if not result:
            print(f"{RED}No files found on Android.{RESET}")
            return
        cert_files = result.splitlines()
        print(f"{CYAN}Certificates found on Android:{RESET}")
        for index, cert in enumerate(cert_files, 1):
            print(f"{PURPLE}{index}. {cert}{RESET}")

        choice = input(f"{YELLOW}Pull all certificates back to local cert folder? (y/n): {RESET}")
        if choice.lower() == "y":
            for cert in cert_files:
                command = f"adb pull {ANDROID_CERT_DIR}/{cert} {CERT_DIR}"
                subprocess.run(command, shell=True, check=True)
                print(f"{GREEN}Pulled {cert} to local certs folder.{RESET}")
    except Exception as e:
        print(f"{RED}Error pulling certs from Android: {e}{RESET}")

# Mitmproxy Functions
def start_mitmproxy():
    run_command("mitmproxy")

def run_mitmdump():
    save_dir = input(f"{CYAN}Enter the directory to save the HAR file: {RESET}")
    if not os.path.isdir(save_dir):
        print(f"{RED}Invalid directory. Please try again.{RESET}")
        return
    command = f"mitmdump --set hardump={os.path.join(save_dir, 'dump.har')}"
    run_command(command)

def start_mitmweb():
    try:
        with open(os.devnull, 'w') as devnull:
            subprocess.Popen(["mitmweb"], stderr=devnull)
        print(f"{GREEN}Mitmweb started successfully{RESET}")
    except Exception as e:
        print(f"{RED}Error starting mitmweb: {e}{RESET}")

def mitmproxy_menu():
    while True:
        display_dashboard()
        print(f"{YELLOW}--- MITMPROXY MENU ---{RESET}")
        print("1. Start Mitmproxy")
        print("2. Start Mitmdump with HAR output")
        print("3. Start Mitmweb")
        print("4. View Certificates")
        print("5. Import Mitmproxy Certificate")
        print("6. Return to Main Menu")

        choice = input(f"{CYAN}Select an option: {RESET}")
        if choice == '1':
            start_mitmproxy()
        elif choice == '2':
            run_mitmdump()
        elif choice == '3':
            start_mitmweb()
        elif choice == '4':
            cert_files = list_certs()
            if cert_files:
                print(f"{CYAN}Certificates found:{RESET}")
                for cert in cert_files:
                    print(f"- {cert}")
            else:
                print(f"{RED}No certificates found.{RESET}")
            input(f"{CYAN}Press Enter to continue...{RESET}")
        elif choice == '5':
            import_mitmproxy_cert()
        elif choice == '6':
            print(f"{GREEN}Returning to main menu...{RESET}")
            break
        else:
            print(f"{RED}Invalid choice. Try again.{RESET}")
            time.sleep(2)

# ADB Functions
def display_dashboard():
    os.system('clear')
    print(f"{PURPLE}--- TOOLKIT DASHBOARD ---{RESET}")
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

def set_emulator_proxy():
    current_ip = run_command("hostname -I | awk '{print $1}'")
    print(f"{CYAN}Detected Local IP Address: {current_ip}{RESET}")
    confirm_ip = input(f"{YELLOW}Is this the correct IP to use for the proxy? (y/n): {RESET}")
    if confirm_ip.lower() != 'y':
        current_ip = input(f"{CYAN}Enter the correct IP address: {RESET}")

    proxy_port = input(f"{CYAN}Enter the proxy port (default: 8080): {RESET}") or "8080"
    run_command(f"adb shell settings put global http_proxy {current_ip}:{proxy_port}")
    print(f"{GREEN}Proxy set to {current_ip}:{proxy_port}{RESET}")

def set_reverse_port():
    local_port = input(f"{CYAN}Enter the local port to reverse (default: 8080): {RESET}") or "8080"
    run_command(f"adb reverse tcp:{local_port} tcp:{local_port}")
    print(f"{GREEN}Reverse proxy set for port {local_port}{RESET}")

def set_forward_port():
    local_port = input(f"{CYAN}Enter the local port to forward (default: 8080): {RESET}") or "8080"
    run_command(f"adb forward tcp:{local_port} tcp:{local_port}")
    print(f"{GREEN}Forward proxy set for port {local_port}{RESET}")

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
        print("10. Launch Burp")
        print("11. Launch Mitmproxy")
        print("12. Launch Frida Menu")
        print("13. Import Mitmproxy Certificate")
        print("14. Exit")

        choice = input(f"{CYAN}Select an option: {RESET}")
        if choice == '1':
            set_emulator_proxy()
        elif choice == '2':
            set_reverse_port()
        elif choice == '3':
            set_forward_port()
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
            start_burp()
        elif choice == '11':
            mitmproxy_menu()
        elif choice == '12':
            frida_menu()
        elif choice == '13':
            import_mitmproxy_cert()
        elif choice == '14':
            print(f"{GREEN}Exiting...{RESET}")
            break
        else:
            print(f"{RED}Invalid choice. Try again.{RESET}")
            time.sleep(2)

if __name__ == "__main__":
    main_menu()