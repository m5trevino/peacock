import os
import subprocess
import sys

# Constants
FRIDA_FILES_DIR = "/home/flintx/flow/fridafiles"
EMULATOR_DEST_DIR = "/data/local/tmp"
ADB_COMMAND = "adb"
FRIDA_CHECK_CMD = "frida --version"

# Function to check if Frida is installed locally
def check_frida_installed():
    try:
        subprocess.run(FRIDA_CHECK_CMD.split(), check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print("[+] Frida is installed on the local machine.")
        return True
    except FileNotFoundError:
        print("[!] Frida is not installed on the local machine.")
        return False

# Function to install Frida locally using pip
def install_frida():
    try:
        print("[*] Installing Frida...")
        subprocess.run(["pip3", "install", "frida-tools"], check=True)
        print("[+] Frida has been installed successfully.")
    except Exception as e:
        print(f"[!] Failed to install Frida: {e}")
        exit(1)

# Function to check if ADB is installed
def check_adb():
    try:
        subprocess.run([ADB_COMMAND, "--version"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print("[+] ADB is installed.")
        return True
    except FileNotFoundError:
        print("[!] ADB is not installed or not in PATH.")
        return False

# Function to install ADB using the package manager
def install_adb():
    print("[*] Installing ADB...")
    try:
        subprocess.run(["sudo", "apt", "update"], check=True)
        subprocess.run(["sudo", "apt", "install", "-y", "adb"], check=True)
        print("[+] ADB has been installed successfully.")
    except Exception as e:
        print(f"[!] Failed to install ADB: {e}")
        exit(1)

# Function to list files in the Frida files directory
def list_frida_files():
    print("[*] Listing available Frida files...")
    try:
        files = os.listdir(FRIDA_FILES_DIR)
        if not files:
            print("[!] No files found in the Frida files directory.")
            exit(1)
        for i, file in enumerate(files):
            print(f"{i + 1}. {file}")
        return files
    except FileNotFoundError:
        print(f"[!] Directory {FRIDA_FILES_DIR} does not exist.")
        exit(1)

# Function to push a file to the emulator
def push_file_to_emulator(file_name):
    try:
        file_path = os.path.join(FRIDA_FILES_DIR, file_name)
        print(f"[*] Pushing {file_name} to the emulator...")
        subprocess.run([ADB_COMMAND, "push", file_path, EMULATOR_DEST_DIR], check=True)
        print(f"[+] {file_name} successfully pushed to {EMULATOR_DEST_DIR} on the emulator.")
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to push file to the emulator: {e}")
        exit(1)

# Function to check if Frida is running on the emulator
def check_frida_on_emulator():
    try:
        print("[*] Checking if Frida server is running on the emulator...")
        output = subprocess.run([ADB_COMMAND, "shell", "ps | grep frida-server"], stdout=subprocess.PIPE, text=True)
        if output.stdout:
            print("[+] Frida server is running on the emulator.")
        else:
            print("[!] Frida server is not running on the emulator.")
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to check Frida on the emulator: {e}")
        exit(1)

# Main function
def main():
    print("[*] Starting Frida-Emulator Manager...")

    # Step 1: Check if Frida is installed locally
    if not check_frida_installed():
        install_frida()

    # Step 2: Check if ADB is installed
    if not check_adb():
        while True:
            user_input = input("[?] ADB is not installed. Do you want to install it? (y/n): ").lower()
            if user_input == "y":
                install_adb()
                break
            elif user_input == "n":
                print("[!] ADB is required to proceed. Exiting...")
                sys.exit(1)
            else:
                print("[!] Invalid input. Please enter 'y' or 'n'.")

    # Step 3: List files in the Frida files directory
    files = list_frida_files()

    # Step 4: Ask the user to choose a file to push
    while True:
        try:
            choice = int(input("Enter the number of the file you want to push to the emulator: ")) - 1
            if 0 <= choice < len(files):
                selected_file = files[choice]
                print(f"[+] Selected file: {selected_file}")
                break
            else:
                print("[!] Invalid choice. Please select a valid number.")
        except ValueError:
            print("[!] Invalid input. Please enter a number.")

    # Step 5: Push the selected file to the emulator
    push_file_to_emulator(selected_file)

    # Step 6: Check if Frida is running on the emulator
    check_frida_on_emulator()

    print("[*] Done.")

if __name__ == "__main__":
    main()
