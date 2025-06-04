#!/bin/bash

# Directory to store the Step 3 modules
MODULE_DIR="/home/flintx/obrida/modules"

# Ensure the modules directory exists
mkdir -p "$MODULE_DIR"

# Array of script names and their respective content
declare -A scripts=(
  ["launch_frida_app_script.sh"]='#!/bin/bash
echo "Launching Frida script for app/package..."
read -p "Enter the package name: " package_name
read -p "Enter the script path: " script_path
frida -U -n "$package_name" -s "$script_path"
'
  ["attach_frida_to_pid.sh"]='#!/bin/bash
echo "Attaching Frida to process by PID..."
read -p "Enter the PID: " pid
frida -U -p "$pid"
'
  ["objection_explore_app.sh"]='#!/bin/bash
echo "Running Objection to explore app..."
read -p "Enter the package name: " package_name
objection --gadget "$package_name" explore
'
  ["bypass_ssl_with_objection.sh"]='#!/bin/bash
echo "Disabling SSL pinning with Objection..."
read -p "Enter the package name: " package_name
objection --gadget "$package_name" sslpinning disable
'
  ["patch_apk_objection.sh"]='#!/bin/bash
echo "Patching APK with Objection..."
read -p "Enter the APK path: " apk_path
objection patchapk -s "$apk_path"
'
  ["start_app_with_frida.sh"]='#!/bin/bash
echo "Starting app and running Frida script..."
read -p "Enter the package name: " package_name
read -p "Enter the activity name: " activity_name
read -p "Enter the script path: " script_path
adb shell am start -n "$package_name/$activity_name"
frida -U -n "$package_name" -s "$script_path"
'
  ["select_frida_script.sh"]='#!/bin/bash
echo "Fetching Frida scripts..."
scripts=(/home/flintx/obrida/frida-scripts/*.js)
echo "Available scripts:"
select script in "${scripts[@]}"; do
    if [[ -n "$script" ]]; then
        echo "Selected script: $script"
        read -p "Enter the process name or PID: " process
        frida -U -n "$process" -s "$script"
        break
    fi
done
'
  ["logcat_stream.sh"]='#!/bin/bash
echo "Starting Logcat for app..."
read -p "Enter the package name: " package_name
adb logcat | grep "$package_name"
'
)

# Loop through each script and create the file
for script_name in "${!scripts[@]}"; do
    script_path="$MODULE_DIR/$script_name"
    echo "Creating $script_path..."
    echo "${scripts[$script_name]}" > "$script_path"
    chmod +x "$script_path"
done

echo "All Step 3 scripts have been created in $MODULE_DIR."
