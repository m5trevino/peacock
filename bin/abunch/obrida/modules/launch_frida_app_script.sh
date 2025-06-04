#!/bin/bash
echo "Launching Frida script for app/package..."
read -p "Enter the package name: " package_name
read -p "Enter the script path: " script_path
frida -U -n "$package_name" -s "$script_path"

