#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}=== GRUB Fixer Script ===${NC}"

# Backup original grub config
echo -e "${YELLOW}Backing up current GRUB config...${NC}"
sudo cp /etc/default/grub /etc/default/grub.backup

# Update GRUB config
echo -e "${YELLOW}Updating GRUB config...${NC}"
sudo tee /etc/default/grub << 'GRUBCONFIG'
# If you change this file, run 'update-grub' afterwards to update
# /boot/grub/grub.cfg.
GRUB_DEFAULT=0
GRUB_TIMEOUT_STYLE=menu
GRUB_TIMEOUT=5
GRUB_DISTRIBUTOR=`lsb_release -i -s 2> /dev/null || echo Debian`
GRUB_CMDLINE_LINUX_DEFAULT="quiet splash"
GRUB_CMDLINE_LINUX=""

# The resolution used on graphical terminal
GRUB_GFXMODE=1920x1080

# Uncomment to disable graphical terminal
#GRUB_TERMINAL=console
GRUBCONFIG

# Update GRUB
echo -e "${YELLOW}Applying changes...${NC}"
sudo update-grub

echo -e "${GREEN}GRUB config updated!${NC}"
echo -e "${YELLOW}Original config backed up to /etc/default/grub.backup${NC}"
echo -e "${YELLOW}Run 'sudo reboot' to test changes${NC}"
