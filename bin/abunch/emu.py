# emu.py

import os
import subprocess

# Paths to Android SDK tools
SDK_TOOLS_DIR = "/home/flintx/Android/Sdk/cmdline-tools/latest/bin"
SDK_EMULATOR_DIR = "/home/flintx/Android/Sdk/emulator"

# List available emulators
def list_emulators():
    try:
        result = subprocess.run(
            [os.path.join(SDK_TOOLS_DIR, "avdmanager"), "list", "avd"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        if result.returncode != 0:
            print(f"Error: {result.stderr}")
            return []
        emulators = []
        current_emulator = {}
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("Name:"):
                if current_emulator:
                    emulators.append(current_emulator)
                current_emulator = {"Name": line.split(":", 1)[1].strip()}
            elif line.startswith("Device:"):
                current_emulator["Device"] = line.split(":", 1)[1].strip()
        if current_emulator:
            emulators.append(current_emulator)
        return emulators
    except Exception as e:
        print(f"Error listing emulators: {e}")
        return []

# Launch the selected emulator
def launch_emulator(emulator_name):
    try:
        print(f"Launching emulator: {emulator_name}")
        subprocess.Popen(
            [os.path.join(SDK_EMULATOR_DIR, "emulator"), "-avd", emulator_name, "-no-snapshot", "-writable-system"]
        )
        os.system(f"xdotool set_desktop_for_window $(xdotool getactivewindow) 2")
    except Exception as e:
        print(f"Error launching emulator: {e}")

# Launch adbmenu.py
def launch_adb_menu():
    try:
        print("Launching ADB Menu...")
        subprocess.Popen(["xfce4-terminal", "--title=adbmenu", "-e", "python3 /home/flintx/flow/adbmenu.py"])
        os.system(f"xdotool set_desktop_for_window $(xdotool getactivewindow) 1")
    except Exception as e:
        print(f"Error launching ADB Menu: {e}")

# Launch fridamenu.py
def launch_frida_menu():
    try:
        print("Launching Frida Menu...")
        subprocess.Popen(["xfce4-terminal", "--title=fridamenu", "-e", "python3 /home/flintx/flow/fridamenu.py"])
    except Exception as e:
        print(f"Error launching Frida Menu: {e}")

def main():
    emulators = list_emulators()
    if not emulators:
        print("No emulators available.")
        return

    print("Available Emulators:")
    for idx, emulator in enumerate(emulators, 1):
        print(f"{idx}. {emulator['Name']}")

    print("Options:")
    print(f"{len(emulators) + 1}. Launch Frida Menu")
    choice = input("Select an emulator or option: ")

    try:
        choice = int(choice)
        if 1 <= choice <= len(emulators):
            emulator_name = emulators[choice - 1]["Name"]
            launch_emulator(emulator_name)
            launch_adb_menu()
        elif choice == len(emulators) + 1:
            launch_frida_menu()
        else:
            print("Invalid choice.")
    except ValueError:
        print("Invalid input.")

if __name__ == "__main__":
    main()

# adbmenu.py

import os
import subprocess
import time

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

# Main ADB Menu
def main_menu():
    rename_terminal("adbmenu")
    while True:
        os.system('clear')
        print("\033[1;32m[ADB Menu]\033[0m")
        print("1. View ADB Settings")
        print("2. Launch Frida Menu")
        print("3. Exit")
        choice = input("Select an option: ")
        if choice == "1":
            print("ADB Settings: Placeholder for now.")
        elif choice == "2":
            launch_frida_menu()
            break
        elif choice == "3":
            print("Exiting...")
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main_menu()
