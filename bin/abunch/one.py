import subprocess

# Define the path to your emulator script
EMU_SCRIPT_PATH = "/home/flintx/bin/emu"

# Fetch available emulators
print("Fetching available emulators...")

try:
    # Run the emu command and capture output
    result = subprocess.run(EMU_SCRIPT_PATH, capture_output=True, text=True, shell=True)

    # Check for errors
    if result.returncode != 0:
        print(f"Error while running emu script: {result.stderr}")
        exit(1)

    # Display the output
    print(result.stdout)

    # Parse the emulator selection process
    emulators = [line for line in result.stdout.splitlines() if line.startswith("Available emulators:")]
    if not emulators:
        print("No emulators found.")
        exit(1)

    # Prompt the user to select an emulator
    selected_emulator = input("Select an emulator: ").strip()

    # Validate input and launch emulator
    emulator_map = {
        "1": "pix22",
        "2": "pix24",
        "3": "pix26",
        "4": "pix28",
        "5": "pix30"
    }

    if selected_emulator in emulator_map:
        emulator_name = emulator_map[selected_emulator]
        print(f"Launching emulator: {emulator_name}")

        # Execute the emulator command
        emulator_command = f'/home/flintx/Android/Sdk/emulator/emulator -avd "{emulator_name}" -no-snapshot -writable-system -gpu swiftshader_indirect'
        subprocess.run(emulator_command, shell=True)
    else:
        print("Invalid selection. Exiting.")

except Exception as e:
    print(f"An error occurred: {e}")
