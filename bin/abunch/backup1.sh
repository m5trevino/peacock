#!/bin/bash

# Define the destination backup path
BACKUP_DIR="/mnt/my_ntfs/1224backup"

# Ensure the backup directory exists
mkdir -p "$BACKUP_DIR"

# Backup shell configuration files
tar -czvf "$BACKUP_DIR/dotfiles_backup.tar.gz" ~/.bashrc ~/.bash_profile ~/.bash_aliases ~/.zshrc ~/.zprofile ~/.zsh_aliases ~/.profile ~/.inputrc ~/.dir_colors

# Backup custom scripts
tar -czvf "$BACKUP_DIR/scripts_backup.tar.gz" ~/bin/ ~/scripts/

# Backup system-wide config files (carefully)
sudo tar -czvf "$BACKUP_DIR/etc_backup.tar.gz" /etc/

# Backup custom commands and system scripts
sudo tar -czvf "$BACKUP_DIR/custom_commands_backup.tar.gz" /usr/local/bin/ /usr/local/sbin/

# Backup crontab jobs
crontab -l > "$BACKUP_DIR/crontab_backup.txt"

# Backup installed APT packages list
dpkg --get-selections > "$BACKUP_DIR/package_list.txt"

# Backup installed Snap apps
snap list > "$BACKUP_DIR/snap_apps.list"

# Backup Python packages (Pip)
pip freeze > "$BACKUP_DIR/pip_requirements.txt"

# Optionally, check disk space and confirm backup
df -h "$BACKUP_DIR"
echo "Backup process completed successfully!"
