#!/bin/bash
echo "Attaching Frida to process by PID..."
read -p "Enter the PID: " pid
frida -U -p "$pid"

