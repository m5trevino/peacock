#!/bin/bash
echo "Disabling SSL pinning with Objection..."
read -p "Enter the package name: " package_name
objection --gadget "$package_name" sslpinning disable

