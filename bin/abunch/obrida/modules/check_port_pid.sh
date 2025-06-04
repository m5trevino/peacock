#!/bin/bash

# Prompt for port number
read -p "Enter port number to check PID: " port_number

# Check port PID
adb shell netstat -tuln | grep :$port_number