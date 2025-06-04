#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import subprocess
import time
import requests
# import wget # Commented out as wget command is run via subprocess

# START ### CONFIGURATION & CONSTANTS ###
# --- Cyberpunk Colors ---
CYAN = "\033[1;36m"
GREEN = "\033[1;32m"
PURPLE = "\033[1;35m"
PINK = "\033[1;95m" # Using Pink instead of Purple for more contrast sometimes
YELLOW = "\033[1;33m"
RED = "\033[1;31m"
RESET = "\033[0m"
BRIGHT_GREEN = "\033[1;92m"
BRIGHT_PURPLE = "\033[1;95m"

# --- Configuration Paths ---
# Using os.path.expanduser to handle ~ correctly
HOME_DIR = os.path.expanduser("~")
FLOW_DIR = os.path.join(HOME_DIR, "flow")
LOCAL_FRIDA_DIR = os.path.join(FLOW_DIR, "fridafiles")
FRIDA_SERVER_DIR = os.path.join(LOCAL_FRIDA_DIR, "frida.server")
FRIDA_GADGET_DIR = os.path.join(LOCAL_FRIDA_DIR, "frida.gadget")
DEVICE_FRIDA_SERVER_PATH = "/data/local/tmp/frida-server"
DEVICE_FRIDA_GADGET_PATH = "/data/local/tmp/frida-gadget"
DEVICE_TMP_DIR = "/data/local/tmp/"
DEFAULT_FRIDA_SCRIPT_DIR = os.path.join(HOME_DIR, "fridascripts")
CERT_DIR = os.path.join(FLOW_DIR, "certs")
ANDROID_CERT_DIR = "/sdcard/Download/" # Standard Android download dir
JAVA_PATH = "/opt/jdk-21.0.5+11-jre/bin/java" # Check if this path is universal or specific
BURP_DIR = os.path.join(HOME_DIR, "burp")
BURP_JAR_PATH = os.path.join(BURP_DIR, "burpsuite.jar")
BURP_LOADER_PATH = os.path.join(BURP_DIR, "burploader.jar")
MITMPROXY_CERT_PATH = os.path.join(HOME_DIR, ".mitmproxy/mitmproxy-ca-cert.pem")

# --- Banner ---
BANNER = f"""
{BRIGHT_PURPLE} █████╗ ███╗   ██╗██████╗ ██████╗  ██████╗ ██╗██████╗     {RESET}
{BRIGHT_PURPLE}██╔══██╗████╗  ██║██╔══██╗██╔══██╗██╔═══██╗██║██╔══██╗    {RESET}
{BRIGHT_PURPLE}███████║██╔██╗ ██║██║  ██║██████╔╝██║   ██║██║██║  ██║    {RESET}
{BRIGHT_PURPLE}██╔══██║██║╚██╗██║██║  ██║██╔══██╗██║   ██║██║██║  ██║    {RESET}
{BRIGHT_PURPLE}██║  ██║██║ ╚████║██████╔╝██║  ██║╚██████╔╝██║██████╔╝    {RESET}
{BRIGHT_PURPLE}╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝╚═════╝     {RESET}
{BRIGHT_GREEN}                                                          {RESET}
{BRIGHT_GREEN}████████╗██████╗  █████╗ ███████╗███████╗██╗ ██████╗      {RESET}
{BRIGHT_GREEN}╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝██║██╔════╝      {RESET}
{BRIGHT_GREEN}   ██║   ██████╔╝███████║█████╗  █████╗  ██║██║           {RESET}
{BRIGHT_GREEN}   ██║   ██╔══██╗██╔══██║██╔══╝  ██╔══╝  ██║██║           {RESET}
{BRIGHT_GREEN}   ██║   ██║  ██║██║  ██║██║     ██║     ██║╚██████╗      {RESET}
{BRIGHT_GREEN}   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝     ╚═╝ ╚═════╝      {RESET}
{CYAN}                                                          {RESET}
{CYAN}████████╗ ██████╗  ██████╗ ██╗     ██╗  ██╗██╗████████╗   {RESET}
{CYAN}╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██║ ██╔╝██║╚══██╔══╝   {RESET}
{CYAN}   ██║   ██║   ██║██║   ██║██║     █████╔╝ ██║   ██║      {RESET}
{CYAN}   ██║   ██║   ██║██║   ██║██║     ██╔═██╗ ██║   ██║      {RESET}
{CYAN}   ██║   ╚██████╔╝╚██████╔╝███████╗██║  ██╗██║   ██║      {RESET}
{CYAN}   ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝   ╚═╝      {RESET}
"""
# FINISH ### CONFIGURATION & CONSTANTS ###

# START ### HELPER FUNCTIONS ###
def run_command(command, suppress_output=False, ignore_errors=False, return_stderr=False):
    """Executes a shell command."""
    # print(f"{CYAN}Executing: {command}{RESET}") # Removed noisy execution print
    try:
        process = subprocess.run(
            command,
            shell=True,
            check=not ignore_errors, # Raise exception if ignore_errors is False and return code is non-zero
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        if process.returncode != 0 and not ignore_errors:
             print(f"{RED}Error executing command: `{command}`{RESET}")
             print(f"{RED}Stderr: {process.stderr.strip()}{RESET}")
             return None # Indicate error explicitly

        # Decide what to return based on flags
        if return_stderr:
            return process.stderr.strip()
        else:
            output = process.stdout.strip()
            if not suppress_output and output:
                 # print(f"{GREEN}Output: {output}{RESET}") # Optional: uncomment for debugging success outputs
                 pass # Keep it clean by default
            return output

    except subprocess.CalledProcessError as e:
        # This block might only be reached if check=True and ignore_errors=False
        if not ignore_errors:
            print(f"{RED}Error executing command: `{command}`{RESET}")
            print(f"{RED}Stderr: {e.stderr.strip()}{RESET}")
        return e.stderr.strip() if return_stderr else None # Return stderr or None on error
    except FileNotFoundError:
        print(f"{RED}Error: Command not found for `{command}`. Is the tool installed and in PATH?{RESET}")
        return None
    except Exception as e:
        print(f"{RED}An unexpected error occurred with command `{command}`: {e}{RESET}")
        return None

def list_and_select_file(directory, file_description="files"):
    """Lists files in a directory and prompts user for selection."""
    try:
        files = [f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))]
        if not files:
            print(f"{RED}No {file_description} found in {directory}{RESET}")
            return None
        print(f"{CYAN}Available {file_description}:{RESET}")
        for idx, file in enumerate(files, 1):
            print(f"{GREEN}{idx}. {file}{RESET}")
        while True:
            try:
                choice = input(f"{YELLOW}Enter the number of the {file_description} to select (or 0 to cancel): {RESET}")
                choice_int = int(choice)
                if choice_int == 0:
                    return None
                if 1 <= choice_int <= len(files):
                    return files[choice_int - 1]
                else:
                    print(f"{RED}Invalid selection. Please enter a number between 1 and {len(files)}.{RESET}")
            except ValueError:
                print(f"{RED}Invalid input. Please enter a number.{RESET}")
    except FileNotFoundError:
        print(f"{RED}Error: Directory not found: {directory}{RESET}")
        return None
    except Exception as e:
        print(f"{RED}Error listing files in {directory}: {e}{RESET}")
        return None

def clear_screen():
    """Clears the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

def pause_briefly(seconds=1):
    """Pause execution briefly."""
    time.sleep(seconds)

def wait_for_enter(prompt=f"{PURPLE}Press Enter to return to the menu...{RESET}"):
    """Waits for the user to press Enter."""
    input(prompt)

# FINISH ### HELPER FUNCTIONS ###

# START ### DASHBOARD FUNCTIONS ###
def get_local_ip():
    """Gets the primary local IP address."""
    ip = run_command("hostname -I | awk '{print $1}'", suppress_output=True, ignore_errors=True)
    return ip or "Unknown IP"

def get_emulator_name():
    """Gets the name/ID of the first connected emulator/device."""
    output = run_command("adb devices", suppress_output=True, ignore_errors=True)
    if output:
        lines = output.strip().split("\n")
        if len(lines) > 1:
            # Look for device/emulator, ignore unauthorized/offline
            for line in lines[1:]:
                 parts = line.split("\t")
                 if len(parts) == 2 and parts[1] == 'device':
                     return parts[0] # Return the first connected device/emulator ID
    return "No Device/Emulator Detected"

def check_adb_status():
    """Fetches various ADB status points, handling errors cleanly."""
    emulator_name = get_emulator_name() # Check device presence first

    if "No Device" in emulator_name:
        # If no device, other checks will fail, return default statuses
        return {
            "Emulator": emulator_name,
            "Proxy": "N/A (No Device)",
            "Reverse TCP": "N/A (No Device)",
            "SELinux": "N/A (No Device)",
            "ADB Root": "N/A (No Device)"
        }

    # Proceed with checks only if a device is detected
    proxy_output = run_command("adb shell settings get global http_proxy", suppress_output=True, ignore_errors=True)
    proxy = proxy_output if proxy_output and proxy_output != 'null' else "Not Set"

    reverse_list_output = run_command("adb reverse --list", suppress_output=True, ignore_errors=True)
    reverse_list = reverse_list_output if reverse_list_output else "No Mappings"

    selinux_output = run_command("adb shell getenforce", suppress_output=True, ignore_errors=True)
    selinux_status = selinux_output if selinux_output else "Unknown Status"

    # Check root status carefully
    whoami_output = run_command("adb shell whoami", suppress_output=True, ignore_errors=True)
    adb_root_status = "Active" if whoami_output == "root" else "Inactive"
    # Add check for adb root command itself needed? adb root might restart connection
    # adb_root_command_output = run_command("adb root", suppress_output=True, ignore_errors=True)
    # if "restarting adbd as root" in adb_root_command_output:
    #     time.sleep(3) # Give adb time to restart
    #     whoami_output = run_command("adb shell whoami", suppress_output=True, ignore_errors=True)
    #     adb_root_status = "Active" if whoami_output == "root" else "Inactive (Restart Failed?)"
    # elif "adbd is already running as root" in adb_root_command_output:
    #      adb_root_status = "Active"


    return {
        "Emulator": emulator_name,
        "Proxy": proxy,
        "Reverse TCP": reverse_list,
        "SELinux": selinux_status,
        "ADB Root": adb_root_status
    }

def display_dashboard():
    """Displays the main dashboard."""
    clear_screen()
    print(BANNER)
    print(f"{PINK}--- TOOLKIT DASHBOARD ---{RESET}")
    ip_address = get_local_ip()
    adb_status = check_adb_status()

    print(f"{BRIGHT_GREEN}Host IP:     {CYAN}{ip_address}{RESET}")
    print(f"{BRIGHT_GREEN}Device:      {CYAN}{adb_status['Emulator']}{RESET}")
    print(f"{BRIGHT_GREEN}ADB Root:    {CYAN}{adb_status['ADB Root']}{RESET}")
    print(f"{BRIGHT_GREEN}SELinux:     {CYAN}{adb_status['SELinux']}{RESET}")
    print(f"{BRIGHT_GREEN}Proxy:       {CYAN}{adb_status['Proxy']}{RESET}")
    print(f"{BRIGHT_GREEN}Reverse TCP: {CYAN}{adb_status['Reverse TCP']}{RESET}")
    print("-" * 30) # Separator

# FINISH ### DASHBOARD FUNCTIONS ###

# START ### ADB & DEVICE FUNCTIONS ###

def set_emulator_proxy():
    """Sets the global HTTP proxy on the connected device."""
    current_ip = get_local_ip()
    print(f"{CYAN}Detected Local IP Address: {YELLOW}{current_ip}{RESET}")
    confirm_ip = input(f"{YELLOW}Use this IP for the proxy? (Y/n): {RESET}").strip().lower()
    if confirm_ip == 'n':
        current_ip = input(f"{CYAN}Enter the correct proxy IP address: {RESET}").strip()
        if not current_ip:
             print(f"{RED}IP address cannot be empty. Aborting.{RESET}")
             return

    proxy_port = input(f"{CYAN}Enter the proxy port (default: 8080): {RESET}").strip() or "8080"
    if not proxy_port.isdigit():
        print(f"{RED}Invalid port number. Aborting.{RESET}")
        return

    print(f"{CYAN}Setting proxy to {current_ip}:{proxy_port}...{RESET}")
    result = run_command(f"adb shell settings put global http_proxy {current_ip}:{proxy_port}", ignore_errors=False)
    if result is not None: # Command executed (even if no output)
        print(f"{GREEN}Proxy set successfully (verify on device).{RESET}")
    else:
        print(f"{RED}Failed to set proxy. Is a device connected and authorized?{RESET}")

def reset_global_proxy():
    """Resets the global HTTP proxy on the device."""
    print(f"{CYAN}Resetting global proxy...{RESET}")
    result = run_command("adb shell settings put global http_proxy \"\"", ignore_errors=False)
    if result is not None:
        print(f"{GREEN}Global proxy reset successfully.{RESET}")
    else:
        print(f"{RED}Failed to reset proxy.{RESET}")

def set_reverse_port():
    """Sets up ADB reverse port forwarding."""
    local_port = input(f"{CYAN}Enter the LOCAL port (on this machine) (e.g., 8080): {RESET}").strip()
    remote_port = input(f"{CYAN}Enter the REMOTE port (on the device) (default: same as local): {RESET}").strip() or local_port

    if not local_port.isdigit() or not remote_port.isdigit():
        print(f"{RED}Invalid port number(s). Aborting.{RESET}")
        return

    print(f"{CYAN}Setting up reverse forward: device:{remote_port} -> host:{local_port}...{RESET}")
    result = run_command(f"adb reverse tcp:{remote_port} tcp:{local_port}", ignore_errors=False)
    if result is not None:
        print(f"{GREEN}Reverse forward rule added/updated. Current rules:{RESET}")
        run_command("adb reverse --list") # Show current list
    else:
        print(f"{RED}Failed to set reverse port forward.{RESET}")

def set_forward_port():
    """Sets up ADB forward port forwarding."""
    local_port = input(f"{CYAN}Enter the LOCAL port (on this machine) (e.g., 8080): {RESET}").strip()
    remote_port = input(f"{CYAN}Enter the REMOTE port (on the device) (default: same as local): {RESET}").strip() or local_port

    if not local_port.isdigit() or not remote_port.isdigit():
        print(f"{RED}Invalid port number(s). Aborting.{RESET}")
        return

    print(f"{CYAN}Setting up forward: host:{local_port} -> device:{remote_port}...{RESET}")
    result = run_command(f"adb forward tcp:{local_port} tcp:{remote_port}", ignore_errors=False)
    if result is not None:
        print(f"{GREEN}Forward rule added/updated. Current rules:{RESET}")
        run_command("adb forward --list") # Show current list
    else:
        print(f"{RED}Failed to set forward port.{RESET}")

def reconfigure_selinux():
    """Sets SELinux to Permissive or Enforcing mode."""
    current_status = run_command("adb shell getenforce", suppress_output=True, ignore_errors=True)
    print(f"{CYAN}Current SELinux status: {YELLOW}{current_status or 'Unknown'}{RESET}")
    print(f"{YELLOW}Select target SELinux mode:{RESET}")
    print(f"{GREEN}1. Permissive (0){RESET}")
    print(f"{GREEN}2. Enforcing (1){RESET}")
    mode_choice = input(f"{CYAN}Enter your choice (1 or 2): {RESET} ").strip()

    target_mode_value = -1
    target_mode_name = ""
    if mode_choice == '1':
        target_mode_value = 0
        target_mode_name = "Permissive"
    elif mode_choice == '2':
        target_mode_value = 1
        target_mode_name = "Enforcing"
    else:
        print(f"{RED}Invalid choice. Aborting.{RESET}")
        return

    print(f"{CYAN}Attempting to set SELinux to {target_mode_name} ({target_mode_value})...{RESET}")
    print(f"{YELLOW}Ensuring ADB root...{RESET}")
    run_command("adb root", suppress_output=True, ignore_errors=True) # Attempt root, ignore output/errors for now
    # Wait a bit for adb to potentially restart if rooting
    root_confirm = run_command("adb shell whoami", suppress_output=True, ignore_errors=True)
    if root_confirm != 'root':
        print(f"{YELLOW}ADB is not running as root. Command might fail.{RESET}")
    else:
        print(f"{GREEN}ADB running as root.{RESET}")

    # Set SELinux status
    result = run_command(f"adb shell setenforce {target_mode_value}", ignore_errors=False) # Don't ignore errors here

    # Verify
    new_status = run_command("adb shell getenforce", suppress_output=True, ignore_errors=True)
    if new_status == target_mode_name:
        print(f"{GREEN}SELinux successfully set to {new_status}.{RESET}")
    elif result is None: # Check if the command itself failed
        print(f"{RED}Failed to execute setenforce command.{RESET}")
    else: # Command ran but status didn't change or is unexpected
        print(f"{RED}Failed to set SELinux to {target_mode_name}. Current status: {new_status or 'Unknown'}. Check ADB root status and device compatibility.{RESET}")


def manage_adb_server(action):
    """Starts or kills the ADB server."""
    print(f"{CYAN}{action.capitalize()}ing ADB server...{RESET}")
    result = run_command(f"adb {action}-server", ignore_errors=False)
    if result is not None:
        print(f"{GREEN}ADB server command '{action}-server' executed.{RESET}")
        if action == "start":
             print(f"{YELLOW}Waiting a moment for server to initialize...{RESET}")
             pause_briefly(2)
    else:
        print(f"{RED}Failed to execute 'adb {action}-server'.{RESET}")

def enable_adb_root():
    """Attempts to restart ADBD in root mode."""
    print(f"{CYAN}Attempting to enable ADB root...{RESET}")
    result = run_command("adb root", ignore_errors=True) # Ignore errors because it might already be root
    if result is None:
         print(f"{RED}Command 'adb root' failed to execute.{RESET}")
         return

    if "restarting adbd as root" in result:
        print(f"{GREEN}ADB restarting as root. Wait a few seconds...{RESET}")
        pause_briefly(3)
        new_status = run_command("adb shell whoami", suppress_output=True, ignore_errors=True)
        if new_status == "root":
             print(f"{GREEN}ADB is now running as root.{RESET}")
        else:
             print(f"{RED}Failed to restart ADB as root. Current user: {new_status or 'Unknown'}{RESET}")
    elif "adbd is already running as root" in result:
        print(f"{GREEN}ADB is already running as root.{RESET}")
    else:
        # It might have failed silently or returned unexpected output
        print(f"{YELLOW}Command executed, but status unclear. Checking 'adb shell whoami'...{RESET}")
        new_status = run_command("adb shell whoami", suppress_output=True, ignore_errors=True)
        if new_status == "root":
            print(f"{GREEN}Confirmed: ADB is running as root.{RESET}")
        else:
            print(f"{RED}ADB is not running as root. User: {new_status or 'Unknown'}{RESET}")

def reboot_emulator():
    """Reboots the connected device."""
    print(f"{CYAN}Rebooting device...{RESET}")
    result = run_command("adb reboot", ignore_errors=False)
    if result is not None:
        print(f"{GREEN}Reboot command sent. Connection will be lost temporarily.{RESET}")
    else:
        print(f"{RED}Failed to send reboot command.{RESET}")

def check_port_pid():
    """Checks which process is using a specific local TCP port."""
    port = input(f"{CYAN}Enter the local TCP port number to check: {RESET}").strip()
    if not port.isdigit():
        print(f"{RED}Invalid port number.{RESET}")
        return

    print(f"{CYAN}Checking for process using local TCP port {port}...{RESET}")
    # Try lsof first, more common and often more detailed
    command_lsof = f"lsof -i TCP:{port} -sTCP:LISTEN -P -n"
    result_lsof = run_command(command_lsof, suppress_output=True, ignore_errors=True)

    pid_found = None
    if result_lsof:
        lines = result_lsof.strip().split('\n')
        if len(lines) > 1: # Header + data lines
            for line in lines[1:]: # Skip header
                 parts = line.split()
                 if len(parts) > 1:
                     pid = parts[1]
                     process_name = parts[0]
                     user = parts[2]
                     print(f"{GREEN}Port {port} is being used by:{RESET}")
                     print(f"  PID: {YELLOW}{pid}{RESET}")
                     print(f"  Process: {YELLOW}{process_name}{RESET}")
                     print(f"  User: {YELLOW}{user}{RESET}")
                     # You can add more details parsed from lsof if needed
                     pid_found = pid
                     break # Found the first listener, good enough for now

    if not pid_found:
         # Try ss as a fallback
         command_ss = f"ss -ltnp 'sport = :{port}'"
         result_ss = run_command(command_ss, suppress_output=True, ignore_errors=True)
         if result_ss:
             lines = result_ss.strip().split('\n')
             if len(lines) > 1: # Header + data lines
                 line = lines[1] # Get the first data line
                 if 'users:' in line:
                      pid_part = line.split('users:(')[1].split(',')[1].split('=')[1]
                      process_name = line.split('users:(')[1].split('"')[1]
                      print(f"{GREEN}Port {port} is being used by (via ss):{RESET}")
                      print(f"  PID: {YELLOW}{pid_part}{RESET}")
                      print(f"  Process: {YELLOW}{process_name}{RESET}")
                      pid_found = pid_part

    if not pid_found:
        print(f"{YELLOW}No listening process found for local TCP port {port}.{RESET}")

# FINISH ### ADB & DEVICE FUNCTIONS ###

# START ### BURP FUNCTIONS ###
def start_burp():
    """Launches Burp Suite using the loader."""
    print(f"{CYAN}Attempting to launch Burp Suite...{RESET}")
    burp_command = [
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
    ]
    try:
        # Check if paths exist
        if not os.path.exists(JAVA_PATH):
             print(f"{RED}Error: Java path not found: {JAVA_PATH}{RESET}")
             return
        if not os.path.exists(BURP_LOADER_PATH):
             print(f"{RED}Error: Burp Loader path not found: {BURP_LOADER_PATH}{RESET}")
             return
        if not os.path.exists(BURP_JAR_PATH):
             print(f"{RED}Error: Burp JAR path not found: {BURP_JAR_PATH}{RESET}")
             return

        # Launch as a background process
        subprocess.Popen(burp_command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"{GREEN}Burp Suite launch command executed. Check for Burp window.{RESET}")
    except Exception as e:
        print(f"{RED}Error launching Burp Suite: {e}{RESET}")
        print(f"{YELLOW}Command attempted: {' '.join(burp_command)}{RESET}")

# FINISH ### BURP FUNCTIONS ###

# START ### MITMPROXY FUNCTIONS ###
def import_mitmproxy_cert():
    """Copies the Mitmproxy CA cert to the toolkit's certs directory."""
    if not os.path.exists(MITMPROXY_CERT_PATH):
        print(f"{RED}Mitmproxy certificate not found at {MITMPROXY_CERT_PATH}.{RESET}")
        print(f"{YELLOW}Ensure mitmproxy has been run once to generate it.{RESET}")
        return

    # Ensure target directory exists
    os.makedirs(CERT_DIR, exist_ok=True)

    dest_path = os.path.join(CERT_DIR, "mitmproxy-ca-cert.pem")
    try:
        # Use subprocess.run for better control/feedback if needed
        copy_command = f"cp \"{MITMPROXY_CERT_PATH}\" \"{dest_path}\""
        run_command(copy_command, ignore_errors=False) # Let run_command handle output/errors
        print(f"{GREEN}Imported Mitmproxy certificate to {dest_path}.{RESET}")
        print(f"{YELLOW}You may need to push this to the device and install it.{RESET}")
    except Exception as e: # Catch potential errors from run_command if it fails internally
         print(f"{RED}Error importing Mitmproxy certificate: {e}{RESET}")


def start_mitmproxy():
    """Starts mitmproxy in the terminal."""
    print(f"{CYAN}Starting mitmproxy... (Press q to quit mitmproxy){RESET}")
    # This will take over the current terminal
    os.system("mitmproxy") # Use os.system to run interactively in the current shell

def run_mitmdump():
    """Runs mitmdump to save traffic to a HAR file."""
    save_dir = input(f"{CYAN}Enter the directory to save the HAR file (e.g., /tmp): {RESET}").strip()
    if not save_dir or not os.path.isdir(save_dir):
        print(f"{RED}Invalid or non-existent directory. Aborting.{RESET}")
        return
    har_file_path = os.path.join(save_dir, 'mitm_dump.har')
    command = f"mitmdump --set hardump={har_file_path}"
    print(f"{CYAN}Starting mitmdump. Output will be saved to {har_file_path}. Press Ctrl+C to stop.{RESET}")
    # This will also take over the terminal until stopped
    os.system(command)

def start_mitmweb():
    """Starts mitmweb in the background."""
    print(f"{CYAN}Starting mitmweb in the background...{RESET}")
    try:
        # Run in background, suppress output
        subprocess.Popen(["mitmweb"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"{GREEN}Mitmweb should be starting. Access it via http://127.0.0.1:8081{RESET}")
    except FileNotFoundError:
        print(f"{RED}Error: 'mitmweb' command not found. Is mitmproxy installed?{RESET}")
    except Exception as e:
        print(f"{RED}Error starting mitmweb: {e}{RESET}")

def mitmproxy_menu():
    """Displays the Mitmproxy sub-menu."""
    while True:
        display_dashboard() # Show context
        print(f"{PINK}--- MITMPROXY MENU ---{RESET}")
        print(f"{GREEN}1.{CYAN} Start Mitmproxy (Interactive Console){RESET}")
        print(f"{GREEN}2.{CYAN} Start Mitmdump (Save to HAR){RESET}")
        print(f"{GREEN}3.{CYAN} Start Mitmweb (Web UI - Background){RESET}")
        print(f"{GREEN}4.{CYAN} Import Mitmproxy CA Cert (to {CERT_DIR}){RESET}")
        print(f"{GREEN}5.{CYAN} Return to Main Menu{RESET}")

        choice = input(f"{YELLOW}Select an option: {RESET}").strip()
        if choice == '1':
            start_mitmproxy()
            # Need to redraw dashboard after mitmproxy exits
        elif choice == '2':
            run_mitmdump()
            # Need to redraw dashboard after mitmdump exits
        elif choice == '3':
            start_mitmweb()
            pause_briefly(2) # Give it a moment to start
        elif choice == '4':
            import_mitmproxy_cert()
            wait_for_enter()
        elif choice == '5':
            print(f"{GREEN}Returning to main menu...{RESET}")
            break
        else:
            print(f"{RED}Invalid choice. Try again.{RESET}")
            pause_briefly(1)

# FINISH ### MITMPROXY FUNCTIONS ###

# START ### FRIDA FUNCTIONS ###

# --- Frida Helpers (from toolkit.py, adapted) ---
def get_device_architecture():
    """Gets the primary CPU architecture of the connected device."""
    arch = run_command('adb shell getprop ro.product.cpu.abi', suppress_output=True, ignore_errors=True)
    return arch.strip() if arch else "unknown"

def find_local_frida_file(directory, version, arch, file_prefix, file_suffix):
    """Finds a matching Frida file locally."""
    try:
        if not os.path.isdir(directory):
            return None
        files = os.listdir(directory)
        # Construct a pattern: prefix-version-android-arch*suffix
        # Be flexible with potential variations in filenames
        pattern_core = f"{file_prefix}-{version}-android-{arch}"
        matching_files = [
            f for f in files
            if pattern_core in f and f.endswith(file_suffix)
           ]

        if matching_files:
            # Maybe sort by modification time if multiple matches? For now, take the first.
            return os.path.join(directory, matching_files[0])
        return None
    except Exception as e:
        print(f"{RED}Error searching for Frida file in {directory}: {e}{RESET}")
        return None


def download_frida_file(version, arch, file_type):
    """Downloads and extracts a specific Frida file (server or gadget)."""
    base_url = f"https://github.com/frida/frida/releases/download/{version}"
    is_server = file_type == "server"
    file_prefix = "frida-server" if is_server else "frida-gadget"
    file_suffix = ".so" if not is_server else "" # Server has no suffix before .xz
    target_dir = FRIDA_SERVER_DIR if is_server else FRIDA_GADGET_DIR
    # Handle arm64 vs aarch64 naming conventions if needed
    github_arch = arch # Assume it matches for now
    if arch == 'arm64': github_arch = 'arm64v8' # Common discrepancy, adjust if needed for other archs

    file_name_base = f"{file_prefix}-{version}-android-{github_arch}{file_suffix}"
    download_url = f"{base_url}/{file_name_base}.xz"
    local_xz_path = os.path.join(target_dir, f"{file_name_base}.xz")
    local_extracted_path = os.path.join(target_dir, file_name_base)

    print(f"{CYAN}Attempting to download {file_type} from: {download_url}{RESET}")
    os.makedirs(target_dir, exist_ok=True)

    # Use wget via run_command
    wget_command = f"wget \"{download_url}\" -O \"{local_xz_path}\""
    print(f"{YELLOW}Running: {wget_command}{RESET}")
    download_result = run_command(wget_command, ignore_errors=False) # Show errors if wget fails

    if download_result is None:
         print(f"{RED}Download failed for {file_name_base}.xz. Check URL and network.{RESET}")
         if os.path.exists(local_xz_path): os.remove(local_xz_path) # Clean up failed download
         return None

    print(f"{GREEN}Download successful. Extracting...{RESET}")
    # Use xz via run_command
    extract_command = f"xz -d \"{local_xz_path}\""
    extract_result = run_command(extract_command, ignore_errors=False)

    if extract_result is None:
        print(f"{RED}Extraction failed for {local_xz_path}. Is 'xz-utils' installed?{RESET}")
        # Keep the .xz file for manual inspection? Or remove? Let's remove.
        # if os.path.exists(local_xz_path): os.remove(local_xz_path)
        return None

    print(f"{GREEN}Successfully downloaded and extracted {file_type} to {local_extracted_path}{RESET}")
    return local_extracted_path


def sync_frida_versions():
    """Synchronizes local and device Frida versions."""
    print(f"{PINK}--- Synchronizing Frida Versions ---{RESET}")

    # 1. Get local Frida (pip) version
    local_version_output = run_command("pip show frida | grep Version", suppress_output=True, ignore_errors=True)
    local_version = local_version_output.split(': ')[1].strip() if local_version_output else None

    if not local_version:
        install_frida = input(f"{YELLOW}Frida not found locally via pip. Install latest? (y/n): {RESET}").lower()
        if install_frida == 'y':
             print(f"{CYAN}Installing latest frida and frida-tools via pip...{RESET}")
             run_command("pip install --upgrade frida frida-tools", ignore_errors=False)
             local_version_output = run_command("pip show frida | grep Version", suppress_output=True, ignore_errors=True)
             local_version = local_version_output.split(': ')[1].strip() if local_version_output else None
             if not local_version:
                  print(f"{RED}Failed to install or detect local Frida version. Aborting sync.{RESET}")
                  return False
        else:
             print(f"{RED}Local Frida required for sync. Aborting.{RESET}")
             return False

    print(f"{GREEN}Local Frida Version: {local_version}{RESET}")

    # 2. Get device architecture
    arch = get_device_architecture()
    if arch == "unknown":
        print(f"{RED}Could not determine device architecture. Is a device connected?{RESET}")
        return False
    print(f"{GREEN}Device Architecture: {arch}{RESET}")

    # 3. Check/Download Frida Server for device
    print(f"{CYAN}Checking for matching Frida Server ({version}/{arch})...{RESET}")
    server_path = find_local_frida_file(FRIDA_SERVER_DIR, local_version, arch, "frida-server", "")
    if not server_path or not os.path.exists(server_path):
        print(f"{YELLOW}Frida Server not found locally. Attempting download...{RESET}")
        server_path = download_frida_file(local_version, arch, "server")
        if not server_path:
            print(f"{RED}Failed to obtain Frida Server for {local_version}/{arch}. Aborting sync.{RESET}")
            return False
    else:
         print(f"{GREEN}Found local Frida Server: {os.path.basename(server_path)}{RESET}")


    # 4. Check/Download Frida Gadget for device
    print(f"{CYAN}Checking for matching Frida Gadget ({version}/{arch})...{RESET}")
    gadget_path = find_local_frida_file(FRIDA_GADGET_DIR, local_version, arch, "frida-gadget", ".so")
    if not gadget_path or not os.path.exists(gadget_path):
        print(f"{YELLOW}Frida Gadget not found locally. Attempting download...{RESET}")
        gadget_path = download_frida_file(local_version, arch, "gadget")
        # Gadget download failure is less critical than server, maybe just warn?
        if not gadget_path:
            print(f"{YELLOW}Warning: Failed to obtain Frida Gadget for {local_version}/{arch}. Gadget functionality unavailable.{RESET}")
        else:
             print(f"{GREEN}Found local Frida Gadget: {os.path.basename(gadget_path)}{RESET}")
    else:
        print(f"{GREEN}Found local Frida Gadget: {os.path.basename(gadget_path)}{RESET}")


    # 5. Push files to device
    print(f"{CYAN}Pushing files to {DEVICE_TMP_DIR}...{RESET}")
    server_pushed = push_file_to_device(server_path, DEVICE_FRIDA_SERVER_PATH)
    if not server_pushed:
         print(f"{RED}Failed to push Frida Server. Aborting sync.{RESET}")
         return False

    if gadget_path and os.path.exists(gadget_path):
        gadget_pushed = push_file_to_device(gadget_path, DEVICE_FRIDA_GADGET_PATH)
        if not gadget_pushed:
             print(f"{YELLOW}Warning: Failed to push Frida Gadget.{RESET}")
    else:
         print(f"{YELLOW}Skipping Gadget push (not found locally or failed download).{RESET}")


    # 6. Ensure permissions and restart server
    print(f"{CYAN}Setting permissions and restarting Frida Server on device...{RESET}")
    run_command(f"adb shell chmod 755 {DEVICE_FRIDA_SERVER_PATH}", suppress_output=True, ignore_errors=True)
    if gadget_path and os.path.exists(gadget_path) and gadget_pushed:
         run_command(f"adb shell chmod 755 {DEVICE_FRIDA_GADGET_PATH}", suppress_output=True, ignore_errors=True)

    restart_frida_server()

    print(f"{GREEN}Frida synchronization complete!{RESET}")
    return True


def remove_frida_from_local():
    """Uninstalls Frida and Frida-tools using pip."""
    print(f"{CYAN}Uninstalling Frida from local machine (pip)...{RESET}")
    result = run_command("pip uninstall -y frida frida-tools", ignore_errors=False)
    if result is not None:
        print(f"{GREEN}Frida uninstalled locally.{RESET}")
    else:
        print(f"{RED}Failed to uninstall Frida locally.{RESET}")

def remove_frida_from_device():
    """Removes Frida server and gadget from the device's /data/local/tmp."""
    print(f"{CYAN}Removing Frida files from device ({DEVICE_TMP_DIR})...{RESET}")
    run_command(f"adb shell rm -f {DEVICE_FRIDA_SERVER_PATH}", suppress_output=True, ignore_errors=True)
    run_command(f"adb shell rm -f {DEVICE_FRIDA_GADGET_PATH}", suppress_output=True, ignore_errors=True)
    print(f"{GREEN}Frida files removed from device.{RESET}")

def fresh_install_frida():
    """Removes existing Frida installs and attempts a fresh setup based on latest release."""
    print(f"{PINK}--- Fresh Frida Install ---{RESET}")
    confirm = input(f"{YELLOW}This will REMOVE existing Frida (local & device) and install fresh. Continue? (y/n): {RESET}").lower()
    if confirm != 'y':
        print(f"{CYAN}Aborted.{RESET}")
        return

    # 1. Remove
    remove_frida_from_local()
    remove_frida_from_device()
    pause_briefly(1)

    # 2. Attempt install (sync logic will handle download/push)
    print(f"{CYAN}Attempting synchronization to install fresh...{RESET}")
    sync_success = sync_frida_versions()

    if sync_success:
        print(f"{GREEN}Fresh Frida installation process completed.{RESET}")
    else:
        print(f"{RED}Fresh Frida installation failed during synchronization step.{RESET}")


def check_frida_server_path():
    """Checks if the frida-server executable exists on the device."""
    result = run_command(f'adb shell ls {DEVICE_FRIDA_SERVER_PATH}', suppress_output=True, ignore_errors=True)
    return result or "NOT FOUND"

def check_frida_gadget_path():
    """Checks if the frida-gadget library exists on the device."""
    result = run_command(f'adb shell ls {DEVICE_FRIDA_GADGET_PATH}', suppress_output=True, ignore_errors=True)
    return result or "NOT FOUND"

def check_if_frida_server_is_active():
    """Checks if the frida-server process is running on the device."""
    # Look for the process directly on the device
    command = f"adb shell pgrep -f 'frida-server'"
    result = run_command(command, suppress_output=True, ignore_errors=True)
    return bool(result) # Returns True if PID is found, False otherwise


def get_local_frida_versions():
    """Gets installed versions of Frida packages via pip."""
    frida_version_output = run_command("pip show frida | grep Version", suppress_output=True, ignore_errors=True)
    tools_version_output = run_command("pip show frida-tools | grep Version", suppress_output=True, ignore_errors=True)
    frida_version = frida_version_output.split(': ')[1].strip() if frida_version_output else 'N/A'
    tools_version = tools_version_output.split(': ')[1].strip() if tools_version_output else 'N/A'
    return f"Frida: {frida_version} / Tools: {tools_version}"


def push_file_to_device(local_file_path, device_path):
    """Pushes a local file to the device and sets permissions."""
    if not os.path.exists(local_file_path):
         print(f"{RED}Error: Local file not found: {local_file_path}{RESET}")
         return False

    print(f"{CYAN}Pushing {os.path.basename(local_file_path)} to {device_path}...{RESET}")
    push_result = run_command(f'adb push "{local_file_path}" "{device_path}"', ignore_errors=False)

    if push_result is None:
        print(f"{RED}Failed to push {os.path.basename(local_file_path)}.{RESET}")
        return False

    # Set permissions after successful push
    chmod_result = run_command(f'adb shell chmod 755 "{device_path}"', ignore_errors=False)
    if chmod_result is None:
         print(f"{YELLOW}Warning: Failed to set permissions for {device_path} on device.{RESET}")
         # Continue anyway, push succeeded
         return True # Push succeeded, permission fail is warning

    print(f"{GREEN}Push successful.{RESET}")
    return True


def push_frida_server():
    """Prompts user to select a local frida-server file and pushes it."""
    print(f"{CYAN}Select Frida Server file to push from {FRIDA_SERVER_DIR}{RESET}")
    selected_file = list_and_select_file(FRIDA_SERVER_DIR, "Frida Server files")
    if selected_file:
        local_path = os.path.join(FRIDA_SERVER_DIR, selected_file)
        push_file_to_device(local_path, DEVICE_FRIDA_SERVER_PATH)


def push_frida_gadget():
    """Prompts user to select a local frida-gadget file and pushes it."""
    print(f"{CYAN}Select Frida Gadget file to push from {FRIDA_GADGET_DIR}{RESET}")
    selected_file = list_and_select_file(FRIDA_GADGET_DIR, "Frida Gadget files")
    if selected_file:
        local_path = os.path.join(FRIDA_GADGET_DIR, selected_file)
        push_file_to_device(local_path, DEVICE_FRIDA_GADGET_PATH)

def start_frida_server():
    """Starts the frida-server on the device in the background."""
    print(f"{CYAN}Checking if server exists on device...{RESET}")
    server_status = check_frida_server_path()
    if "NOT FOUND" in server_status:
         print(f"{RED}Frida server not found at {DEVICE_FRIDA_SERVER_PATH}. Push it first or sync.{RESET}")
         return

    print(f"{CYAN}Attempting to start Frida server in the background...{RESET}")
    # Run in background using '&', suppress output as it might be noisy
    run_command(f'adb shell "{DEVICE_FRIDA_SERVER_PATH} &"', suppress_output=True, ignore_errors=True)
    # Check if it's running after a short delay
    pause_briefly(2)
    if check_if_frida_server_is_active():
        print(f"{GREEN}Frida server started (or was already running).{RESET}")
    else:
        print(f"{RED}Failed to start Frida server or it exited quickly. Check ADB connection and server file.{RESET}")

def kill_frida_server():
     """Kills any running frida-server process on the device."""
     print(f"{CYAN}Attempting to kill Frida server on device...{RESET}")
     run_command('adb shell "killall frida-server"', suppress_output=True, ignore_errors=True) # Use quotes for shell command
     # Verify
     pause_briefly(1)
     if not check_if_frida_server_is_active():
         print(f"{GREEN}Frida server process killed (or was not running).{RESET}")
     else:
         print(f"{RED}Failed to kill Frida server process. Manual check needed?{RESET}")

def restart_frida_server():
    """Kills existing frida-server and starts a new one."""
    kill_frida_server() # Stop existing first
    start_frida_server() # Start new one

def list_device_apps():
    """Lists installed packages on the device."""
    print(f"{CYAN}Fetching installed packages...{RESET}")
    output = run_command("adb shell pm list packages -3", suppress_output=True, ignore_errors=True) # Show 3rd party apps only
    if not output:
        output = run_command("adb shell pm list packages", suppress_output=True, ignore_errors=True) # Fallback to all apps
    if not output:
        print(f"{RED}Could not list packages. Is device connected?{RESET}")
        return None

    packages = [line.split(':')[1] for line in output.strip().splitlines() if ':' in line]
    packages.sort()
    return packages


def launch_frida_script():
    """Selects an app and a script, then launches Frida."""
    apps = list_device_apps()
    if not apps:
        return

    print(f"{CYAN}Installed Packages (Third-Party Preferred):{RESET}")
    for idx, app in enumerate(apps, 1):
        print(f"{GREEN}{idx}. {app}{RESET}")

    try:
        app_choice = int(input(f"{YELLOW}Select app by number to attach to: {RESET}")) - 1
        if not (0 <= app_choice < len(apps)):
            print(f"{RED}Invalid app selection.{RESET}")
            return
        app_name = apps[app_choice]
    except ValueError:
        print(f"{RED}Invalid input.{RESET}")
        return

    print(f"{CYAN}Selected app: {app_name}{RESET}")
    print(f"{CYAN}Select Frida script to load from {DEFAULT_FRIDA_SCRIPT_DIR}{RESET}")
    script_file = list_and_select_file(DEFAULT_FRIDA_SCRIPT_DIR, "Frida scripts")
    if not script_file:
        print(f"{RED}No script selected.{RESET}")
        return

    script_path = os.path.join(DEFAULT_FRIDA_SCRIPT_DIR, script_file)
    if not os.path.exists(script_path):
         print(f"{RED}Error: Script file not found: {script_path}{RESET}")
         return

    command = f'frida -U -f {app_name} -l "{script_path}" --pause' # Add --pause to allow attach in zygote
    print(f"{PINK}Executing: {command}{RESET}")
    print(f"{YELLOW}Frida will launch/attach to the app. App might pause on launch, press %resume in Frida console if needed.{RESET}")
    # Run interactively in the current terminal
    os.system(command)

def attach_to_process():
    """Lists running processes and attaches Frida."""
    print(f"{CYAN}Fetching running processes (frida-ps -Uai)...{RESET}")
    # Using frida-ps is often better than adb shell ps for apps
    ps_command = "frida-ps -Uai"
    processes_output = run_command(ps_command, suppress_output=True, ignore_errors=True)

    if not processes_output:
        print(f"{RED}Failed to get process list via frida-ps. Is frida-server running?{RESET}")
        # Fallback maybe?
        # processes_output = run_command("adb shell ps -A", suppress_output=True, ignore_errors=True)
        return

    processes = []
    lines = processes_output.strip().split('\n')
    print(f"{PURPLE}{lines[0]}{RESET}") # Print header
    for line in lines[1:]:
         parts = line.split()
         if len(parts) >= 2:
             pid = parts[0]
             name = parts[1]
             identifier = parts[2] if len(parts) > 2 else "" # App identifier if available
             processes.append({'pid': pid, 'name': name, 'identifier': identifier, 'line': line})

    if not processes:
         print(f"{YELLOW}No running applications found via frida-ps.{RESET}")
         return

    print(f"{CYAN}Running Applications:{RESET}")
    for idx, proc in enumerate(processes, 1):
        # Make output cleaner
        print(f"{GREEN}{idx:>3}. {PURPLE}{proc['pid']:<6}{RESET} {CYAN}{proc['name']:<30}{RESET} {YELLOW}{proc['identifier']}{RESET}")

    try:
        choice = int(input(f"{YELLOW}Select process by number to attach to: {RESET}")) - 1
        if not (0 <= choice < len(processes)):
            print(f"{RED}Invalid selection.{RESET}")
            return
        target_pid = processes[choice]['pid']
        target_name = processes[choice]['name'] # Could use identifier too
        print(f"{CYAN}Selected: PID {target_pid} ({target_name}){RESET}")
    except ValueError:
        print(f"{RED}Invalid input.{RESET}")
        return

    print(f"{CYAN}Select Frida script to load (optional, press Enter to skip):{RESET}")
    script_file = list_and_select_file(DEFAULT_FRIDA_SCRIPT_DIR, "Frida scripts")
    script_path = os.path.join(DEFAULT_FRIDA_SCRIPT_DIR, script_file) if script_file else None

    if script_path and not os.path.exists(script_path):
         print(f"{RED}Error: Script file not found: {script_path}{RESET}")
         return

    command = f'frida -U -p {target_pid}'
    if script_path:
        command += f' -l "{script_path}"'

    print(f"{PINK}Executing: {command}{RESET}")
    os.system(command)

def trace_function():
    """Uses frida-trace to trace specific methods."""
    target = input(f"{YELLOW}Enter target (Package Name, PID, or Process Name): {RESET}").strip()
    if not target:
         print(f"{RED}Target cannot be empty.{RESET}")
         return

    method = input(f"{YELLOW}Enter method/pattern to trace (e.g., '*Activity*!on*', 'java.net.Socket.*'): {RESET}").strip()
    if not method:
         print(f"{RED}Method cannot be empty.{RESET}")
         return

    # Determine if target is PID or Name/Package
    target_flag = "-p" if target.isdigit() else "-Uf" if '.' in target else "-Un" # Basic heuristic
    # More robust: use frida-ps to resolve name to PID if needed? Overkill for now.

    command = f'frida-trace {target_flag} {target} -m "{method}"'
    print(f"{PINK}Executing: {command}{RESET}")
    os.system(command)

def display_frida_dashboard_data():
     """Fetches and returns data for the Frida dashboard display."""
     arch = get_device_architecture()
     server_path = check_frida_server_path()
     gadget_path = check_frida_gadget_path()
     is_active = check_if_frida_server_is_active()
     local_versions = get_local_frida_versions()

     return {
         "Architecture": arch,
         "Server Path": server_path,
         "Gadget Path": gadget_path,
         "Server Active": is_active,
         "Local Versions": local_versions
     }

def frida_menu():
    """Displays the Frida sub-menu."""
    while True:
        clear_screen()
        print(BANNER) # Show main banner for context
        print(f"{PINK}--- FRIDA TOOLKIT ---{RESET}")

        # Frida Dashboard Section
        print(f"{PURPLE}--- Frida Status ---{RESET}")
        frida_data = display_frida_dashboard_data()
        active_color = GREEN if frida_data["Server Active"] else RED
        active_text = "ACTIVE" if frida_data["Server Active"] else "INACTIVE"
        print(f"{BRIGHT_GREEN}Local:  {CYAN}{frida_data['Local Versions']}{RESET}")
        print(f"{BRIGHT_GREEN}Device Arch: {CYAN}{frida_data['Architecture']}{RESET}")
        print(f"{BRIGHT_GREEN}Server Path: {CYAN}{frida_data['Server Path']}{RESET}")
        print(f"{BRIGHT_GREEN}Gadget Path: {CYAN}{frida_data['Gadget Path']}{RESET}")
        print(f"{BRIGHT_GREEN}Server Status: {active_color}{active_text}{RESET}")
        print("-" * 30)

        # Frida Menu Options
        print(f"{PINK}--- Frida Actions ---{RESET}")
        print(f"{GREEN} 1.{CYAN} Start Server{RESET}")
        print(f"{GREEN} 2.{CYAN} Restart Server{RESET}")
        print(f"{GREEN} 3.{CYAN} Kill Server{RESET}")
        print(f"{GREEN} 4.{CYAN} Sync Versions (Local <-> Device){RESET}")
        print(f"{GREEN} 5.{CYAN} Push Server Manually{RESET}")
        print(f"{GREEN} 6.{CYAN} Push Gadget Manually{RESET}")
        print(f"{GREEN} 7.{CYAN} Launch App with Script{RESET}")
        print(f"{GREEN} 8.{CYAN} Attach to Running Process{RESET}")
        print(f"{GREEN} 9.{CYAN} Trace Method (frida-trace){RESET}")
        print(f"{GREEN}10.{CYAN} Check PID for Port{RESET}")
        print(f"{GREEN}11.{CYAN} Fresh Install Frida (Remove & Sync){RESET}")
        print(f"{GREEN}12.{CYAN} Return to Main Menu{RESET}")

        choice = input(f"{YELLOW}Select an option: {RESET}").strip()

        if choice == '1':
            start_frida_server()
            wait_for_enter()
        elif choice == '2':
            restart_frida_server()
            wait_for_enter()
        elif choice == '3':
            kill_frida_server()
            wait_for_enter()
        elif choice == '4':
            sync_frida_versions()
            wait_for_enter()
        elif choice == '5':
            push_frida_server()
            wait_for_enter()
        elif choice == '6':
            push_frida_gadget()
            wait_for_enter()
        elif choice == '7':
            launch_frida_script()
            # Interactive, wait is implicit until frida exits
            wait_for_enter("Frida exited. Press Enter to continue...")
        elif choice == '8':
            attach_to_process()
            wait_for_enter("Frida exited. Press Enter to continue...")
        elif choice == '9':
            trace_function()
            wait_for_enter("Frida Trace exited. Press Enter to continue...")
        elif choice == '10':
            check_port_pid() # Call the shared function
            wait_for_enter()
        elif choice == '11':
            fresh_install_frida()
            wait_for_enter()
        elif choice == '12':
            print(f"{GREEN}Returning to main menu...{RESET}")
            break
        else:
            print(f"{RED}Invalid choice. Try again.{RESET}")
            pause_briefly(1)

# FINISH ### FRIDA FUNCTIONS ###

# START ### MAIN MENU ###
def main_menu():
    """Displays the main menu and handles user input."""
    while True:
        display_dashboard() # Clears screen and shows banner/status
        print(f"{PINK}--- MAIN MENU ---{RESET}")
        # Group related functions
        print(f"{PURPLE} ADB & Device Management:{RESET}")
        print(f"{GREEN} 1.{CYAN} Set Emulator Proxy{RESET}")
        print(f"{GREEN} 2.{CYAN} Reset Global Proxy{RESET}")
        print(f"{GREEN} 3.{CYAN} Set Reverse Port Forward{RESET}")
        print(f"{GREEN} 4.{CYAN} Set Forward Port Forward{RESET}")
        print(f"{GREEN} 5.{CYAN} Reconfigure SELinux{RESET}")
        print(f"{GREEN} 6.{CYAN} Enable ADB Root{RESET}")
        print(f"{GREEN} 7.{CYAN} Kill ADB Server{RESET}")
        print(f"{GREEN} 8.{CYAN} Start ADB Server{RESET}")
        print(f"{GREEN} 9.{CYAN} Reboot Device{RESET}")
        print(f"{GREEN}10.{CYAN} Check PID for Port{RESET}")

        print(f"{PURPLE} Tool Launchers & Menus:{RESET}")
        print(f"{GREEN}11.{CYAN} Launch Burp Suite{RESET}")
        print(f"{GREEN}12.{CYAN} Mitmproxy Menu{RESET}")
        print(f"{GREEN}13.{CYAN} Frida Menu{RESET}")
        print(f"{GREEN}14.{CYAN} Import Mitmproxy CA Cert{RESET}")

        print(f"{PURPLE} System:{RESET}")
        print(f"{GREEN}15.{CYAN} Exit{RESET}")
        print("-" * 30)

        choice = input(f"{YELLOW}Select an option: {RESET}").strip()

        action_taken = True # Flag to control the pause
        if choice == '1':
            set_emulator_proxy()
        elif choice == '2':
            reset_global_proxy()
        elif choice == '3':
            set_reverse_port()
        elif choice == '4':
            set_forward_port()
        elif choice == '5':
            reconfigure_selinux()
        elif choice == '6':
            enable_adb_root()
        elif choice == '7':
            manage_adb_server("kill")
        elif choice == '8':
            manage_adb_server("start")
        elif choice == '9':
            reboot_emulator()
        elif choice == '10':
             check_port_pid()
        elif choice == '11':
            start_burp()
        elif choice == '12':
            mitmproxy_menu()
            action_taken = False # Submenu handles its own flow/pause
        elif choice == '13':
            frida_menu()
            action_taken = False # Submenu handles its own flow/pause
        elif choice == '14':
            import_mitmproxy_cert()
        elif choice == '15':
            print(f"{GREEN}Exiting toolkit... Stay sharp, G.{RESET}")
            break
        else:
            print(f"{RED}Invalid choice, my boy. Try again.{RESET}")
            action_taken = True # Pause on invalid choice

        if action_taken:
            wait_for_enter()

# FINISH ### MAIN MENU ###

# START ### SCRIPT RUNNER ###
if __name__ == "__main__":
    # Create necessary directories if they don't exist
    os.makedirs(LOCAL_FRIDA_DIR, exist_ok=True)
    os.makedirs(FRIDA_SERVER_DIR, exist_ok=True)
    os.makedirs(FRIDA_GADGET_DIR, exist_ok=True)
    os.makedirs(DEFAULT_FRIDA_SCRIPT_DIR, exist_ok=True)
    os.makedirs(CERT_DIR, exist_ok=True)
    # Maybe check for core dependencies like adb?
    main_menu()
# FINISH ### SCRIPT RUNNER ###
