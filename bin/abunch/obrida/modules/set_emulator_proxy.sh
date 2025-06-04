#!/bin/bash

read -p "Enter Proxy IP (default: 127.0.0.1): " proxy_ip
proxy_ip=${proxy_ip:-127.0.0.1}

read -p "Enter Proxy Port (default: 8080): " proxy_port
proxy_port=${proxy_port:-8080}

adb shell settings put global http_proxy "$proxy_ip:$proxy_port"
echo "[SUCCESS] Proxy set to $proxy_ip:$proxy_port"
