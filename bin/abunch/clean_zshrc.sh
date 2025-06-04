#!/bin/bash

# Define the path to .zshrc
ZSHRC_FILE="$HOME/.zshrc"

# Create a backup of .zshrc
cp "$ZSHRC_FILE" "${ZSHRC_FILE}.backup"

# Remove unnecessary lines related to Bash-specific configuration
sed -i '/if \[ -f ~\/.bash_aliases \]; then/,+2d' "$ZSHRC_FILE"
sed -i '/# Add an "alert" alias/d' "$ZSHRC_FILE"
sed -i '/eval "\$alias_command"/d' "$ZSHRC_FILE"
sed -i '/# Some more `ls` aliases/d' "$ZSHRC_FILE"

# Append common Zsh-specific aliases if not already added
if ! grep -q 'plugins=(git zsh-autosuggestions zsh-syntax-highlighting)' "$ZSHRC_FILE"; then
    echo "plugins=(git zsh-autosuggestions zsh-syntax-highlighting)" >> "$ZSHRC_FILE"
fi

# Reload .zshrc
source "$ZSHRC_FILE"

echo "Your .zshrc has been cleaned and updated. Backup saved as .zshrc.backup"
