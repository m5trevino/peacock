import os
import subprocess
import time

# Configuration paths and constants
LOCAL_FRIDA_DIR = "/home/flintx/flow/fridafiles"
DEVICE_FRIDA_SERVER_PATH = "/data/local/tmp/frida-server"
DEVICE_FRIDA_GADGET_PATH = "/data/local/tmp/frida-gadget"
FRIDA_PORT = 27042

# Define helper functions

def run_command(command):
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error executing command: {command}\n{result.stderr.strip()}")
    return result.stdout.strip()


def install_frida_tools():
    print("Checking for Frida installation...")
    frida_version = run_command("pip list | grep frida | grep -v frida-tools")
    frida_tools_version = run_command("pip list | grep frida-tools")

    if not frida_version or not frida_tools_version:
        print("Frida or Frida-tools not installed. Installing...")
        run_command("pip install frida frida-tools")
    else:
        print(f"Frida installed: {frida_version}")
        print(f"Frida-tools installed: {frida_tools_version}")


def get_device_architecture():
    arch = run_command("adb shell getprop ro.product.cpu.abi")
    return arch if arch else "unknown"


def push_frida_server():
    device_arch = get_device_architecture()
    print(f"Device architecture detected: {device_arch}")
    
    # Automatically select appropriate frida-server binary
    server_file = None
    for file in os.listdir(LOCAL_FRIDA_DIR):
        if device_arch in file and "frida-server" in file:
            server_file = file
            break

    if not server_file:
        print(f"No suitable frida-server binary found for architecture {device_arch}.")
        return

    print(f"Pushing {server_file} to device...")
    local_path = os.path.join(LOCAL_FRIDA_DIR, server_file)
    run_command(f"adb push {local_path} {DEVICE_FRIDA_SERVER_PATH}")
    run_command(f"adb shell chmod 755 {DEVICE_FRIDA_SERVER_PATH}")
    print("Frida-server pushed and permissions set.")


def start_frida_server():
    print("Starting Frida server on the device...")
    output = run_command(f"adb shell {DEVICE_FRIDA_SERVER_PATH} &")
    time.sleep(2)
    if check_frida_server():
        print("Frida server is now active.")
    else:
        print("Failed to start Frida server.")


def check_frida_server():
    output = run_command(f"adb shell lsof -i :{FRIDA_PORT}")
    return bool(output)


def setup_emulator():
    print("Starting emulator and ensuring ADB connection...")
    run_command("adb start-server")
    time.sleep(3)
    devices = run_command("adb devices")
    if "device" not in devices:
        print("No devices detected. Make sure your emulator or device is connected.")
        return False
    print("Device connected.")
    return True

# Main workflow
def main():
    print("Starting Frida setup...")
    install_frida_tools()

    if not setup_emulator():
        return

    push_frida_server()
    start_frida_server()

    print("Frida setup complete. You can now proceed with pentesting.")

if __name__ == "__main__":
    main()
