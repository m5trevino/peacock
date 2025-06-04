#!/bin/bash

# Prompt for port number
read -p "Enter port number to check: " port_number

# Check port usage
adb shell lsof -i :$port_number