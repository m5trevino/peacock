#!/bin/bash

# Colors for output
CYAN='\033[96m'
GREEN='\033[32m'
RESET='\033[0m'
RED='\033[31m'

# User to set as owner
USER="flintx"
GROUP="flintx"

# Function to update permissions and ownership
update_permissions() {
    local target="$1"

    echo -e "${CYAN}Setting ownership to $USER:$GROUP for $target...${RESET}"
    sudo chown -R "$USER:$GROUP" "$target"

    echo -e "${CYAN}Setting write and execute permissions for the owner and group...${RESET}"
    sudo chmod -R ug+rwX "$target"

    # Ensure others have appropriate read/execute permissions
    echo -e "${CYAN}Setting read/execute permissions for others...${RESET}"
    sudo chmod -R o+rX "$target"

    # Set default ACL for future files/directories
    echo -e "${CYAN}Setting default ACLs for new files and directories...${RESET}"
    sudo setfacl -R -m d:u:"$USER":rwx -m d:g:"$GROUP":rwx "$target"

    echo -e "${GREEN}Permissions and ownership updated successfully for $target.${RESET}"
}

# Prompt for input
read -rp "Enter the directory path you want to modify: " TARGET

# Validate input
if [ ! -e "$TARGET" ]; then
    echo -e "${RED}Error: Path $TARGET does not exist.${RESET}"
    exit 1
fi

# Update permissions and ownership
update_permissions "$TARGET"
