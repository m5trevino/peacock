import subprocess
import os
import sys

def check_frida_version():
    try:
        frida_version = subprocess.check_output(['frida', '--version']).decode('utf-8').strip()
        return frida_version
    except subprocess.CalledProcessError:
        print("Frida is not installed or not accessible in the PATH.")
        sys.exit(1)

def get_ip_address():
    try:
        ip_address = subprocess.check_output(['hostname', '-I']).decode('utf-8').strip().split()[0]
        return ip_address
    except subprocess.CalledProcessError:
        print("Failed to retrieve local IP address.")
        sys.exit(1)

def check_frida_server_status():
    try:
        server_status = subprocess.check_output(['adb', 'shell', 'ps', '|', 'grep', 'frida-server']).decode('utf-8').strip()
        if server_status:
            return True
        return False
    except subprocess.CalledProcessError:
        return False

def reverse_proxy(ip, port):
    command = f"adb reverse tcp:{port} tcp:{port}"
    subprocess.run(command, shell=True)

def set_global_proxy():
    print("Setting global HTTP proxy via ADB...")
    subprocess.run("adb root", shell=True)
    subprocess.run("adb remount", shell=True)

def list_running_apps():
    print("Listing running apps with frida-ps -Uia...")
    app_list = subprocess.check_output(['frida-ps', '-Uia']).decode('utf-8').splitlines()
    filtered_apps = [app for app in app_list if 'com.google.' not in app and 'com.android.' not in app]  # Excluding system apps
    return filtered_apps

def select_app(apps):
    print("Select a target app from the list below:")
    for index, app in enumerate(apps, 1):
        print(f"[{index}] {app}")
    
    app_choice = input("Enter the number of the app from the list above: ")
    return apps[int(app_choice) - 1].split()[2]

def start_frida_session(target_app):
    print(f"Running Frida session with the selected app: frida -U -f {target_app}")
    subprocess.run(f"frida -U -f {target_app}", shell=True)

def main():
    print("=======================================================")
    print("Frida Helper Script - Setup and Session Start")
    print("=======================================================")

    # Check Frida Version
    frida_version = check_frida_version()
    print(f"Frida version: {frida_version}")

    # Get IP Address
    ip_address = get_ip_address()
    print(f"Proxy IP: {ip_address}")

    # Proxy Settings
    print("Enter Proxy Port: 8080")
    print(f"Proxy IP: {ip_address}")
    print("Enter the host port to reverse proxy: 8080")
    print("Enter the device port to reverse proxy: 8080")
    reverse_proxy(ip_address, 8080)

    # Setting global proxy
    set_global_proxy()

    # Check if Frida server is running
    if check_frida_server_status():
        print("Frida server is running.")
    else:
        print("Frida server is not running. Starting the server...")
        subprocess.run("adb shell /data/local/tmp/frida-server &", shell=True)

    # List Apps
    apps = list_running_apps()

    # Show List of Apps
    print("=======================================================")
    print("Do you want to see the full list of apps (including system apps)? (y/n): ")
    if input().strip().lower() == 'y':
        print("Showing all apps...")
        print("\n".join(apps))

    # Select App
    target_app = select_app(apps)
    
    # Start Frida Session
    start_frida_session(target_app)

if __name__ == "__main__":
    main()
