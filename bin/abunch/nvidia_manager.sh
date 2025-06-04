#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}=== NVIDIA Management Script ===${NC}"

# Function to fix package issues
fix_packages() {
    echo -e "${YELLOW}Fixing package management...${NC}"
    sudo dpkg --configure -a
    sudo apt-get update --fix-missing
    sudo apt-get install -f
    echo -e "${GREEN}Package management fixed${NC}"
}

# Function to clean NVIDIA
clean_nvidia() {
    echo -e "${RED}Cleaning NVIDIA installations...${NC}"
    
    # Fix packages first
    fix_packages
    
    # Stop display manager
    echo "Stopping display manager..."
    sudo systemctl stop gdm3
    
    # Remove NVIDIA packages
    echo "Removing NVIDIA packages..."
    sudo apt-get remove --purge '^nvidia-.*' -y
    sudo apt-get remove --purge '^libnvidia-.*' -y
    sudo apt-get remove --purge '^cuda-.*' -y
    sudo apt autoremove -y
    
    # Clean configs
    echo "Cleaning config files..."
    sudo rm -rf /etc/X11/xorg.conf
    sudo rm -rf /etc/modprobe.d/nvidia*
    sudo rm -rf /usr/lib/nvidia*
    sudo rm -rf /var/lib/nvidia*
    
    # Update initramfs
    echo "Updating initramfs..."
    sudo update-initramfs -u
    
    echo -e "${GREEN}NVIDIA cleanup complete!${NC}"
}

# Function to install server driver
install_server_driver() {
    echo -e "${YELLOW}Installing NVIDIA server driver...${NC}"
    
    # Fix packages first
    fix_packages
    
    sudo apt update
    sudo apt install -y nvidia-driver-525-server
    echo -e "${GREEN}Server driver installation complete!${NC}"
}

# Main menu
while true; do
    echo -e "\n${YELLOW}Choose an option:${NC}"
    echo "1) Fix package management"
    echo "2) Clean NVIDIA"
    echo "3) Install server driver"
    echo "4) Clean and install server driver"
    echo "5) Check NVIDIA status"
    echo "6) Exit"
    
    read -p "Enter choice (1-6): " choice
    
    case $choice in
        1)
            fix_packages
            ;;
        2)
            clean_nvidia
            ;;
        3)
            install_server_driver
            ;;
        4)
            clean_nvidia
            install_server_driver
            ;;
        5)
            echo -e "${YELLOW}Checking NVIDIA status...${NC}"
            nvidia-smi
            ;;
        6)
            echo -e "${GREEN}Exiting...${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid choice${NC}"
            ;;
    esac
done
