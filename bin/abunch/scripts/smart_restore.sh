#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

SNAPSHOT_DIR="/opt/system_snapshots/20250331_165631"

echo -e "${YELLOW}=== Smart System Restore ===${NC}"

# Function to restore system configs only
restore_configs() {
    echo -e "${YELLOW}Restoring system configs...${NC}"
    
    # Stop services
    sudo systemctl stop gdm3 nginx fcgiwrap

    # Restore only system configs
    echo "Restoring nginx configs..."
    sudo cp -r "${SNAPSHOT_DIR}/etc/nginx/"* /etc/nginx/
    
    echo "Restoring systemd configs..."
    sudo cp -r "${SNAPSHOT_DIR}/etc/systemd/"* /etc/systemd/system/

    # Fix GRUB
    echo "Restoring clean GRUB config..."
    sudo tee /etc/default/grub << 'GRUBCONFIG'
GRUB_DEFAULT=0
GRUB_TIMEOUT_STYLE=menu
GRUB_TIMEOUT=5
GRUB_DISTRIBUTOR=`lsb_release -i -s 2> /dev/null || echo Debian`
GRUB_CMDLINE_LINUX_DEFAULT="quiet splash"
GRUB_CMDLINE_LINUX=""
GRUB_GFXMODE=1920x1080
GRUBCONFIG

    sudo update-grub
}

# Function to verify services
verify_services() {
    echo -e "${YELLOW}Verifying services...${NC}"
    
    sudo systemctl daemon-reload
    sudo systemctl restart nginx
    sudo systemctl restart fcgiwrap
}

# Main menu
while true; do
    echo -e "\n${YELLOW}Choose an option:${NC}"
    echo "1) Restore system configs only (keeps your changes)"
    echo "2) Check current system status"
    echo "3) Verify NVIDIA status"
    echo "4) Exit"
    
    read -p "Enter choice (1-4): " choice
    
    case $choice in
        1)
            restore_configs
            verify_services
            echo -e "${GREEN}System configs restored!${NC}"
            echo -e "${YELLOW}Reboot recommended. Run 'sudo reboot' when ready.${NC}"
            ;;
        2)
            echo -e "${YELLOW}Checking system status...${NC}"
            systemctl status nginx
            systemctl status fcgiwrap
            systemctl status gdm3
            ;;
        3)
            echo -e "${YELLOW}Checking NVIDIA status...${NC}"
            nvidia-smi
            ;;
        4)
            echo -e "${GREEN}Exiting...${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid choice${NC}"
            ;;
    esac
done
