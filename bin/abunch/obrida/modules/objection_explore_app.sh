#!/bin/bash
echo "Running Objection to explore app..."
read -p "Enter the package name: " package_name
objection --gadget "$package_name" explore

