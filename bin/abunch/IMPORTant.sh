#!/bin/bash

# Define the destination backup path
BACKUP_DIR="/mnt/my_ntfs/1224backup/IMPORTant"

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

# Backup additional directories you mentioned
tar -czvf "$BACKUP_DIR/riker_backup.tar.gz" /home/flintx/riker
tar -czvf "$BACKUP_DIR/APKs_backup.tar.gz" /home/flintx/APKs
tar -czvf "$BACKUP_DIR/scripts_backup.tar.gz" /home/flintx/scripts
tar -czvf "$BACKUP_DIR/Zsh_backup.tar.gz" /home/flintx/.zshrc
tar -czvf "$BACKUP_DIR/usr_local_bin_backup.tar.gz" /usr/local/bin
tar -czvf "$BACKUP_DIR/8821au_backup.tar.gz" /home/flintx/8821au-20210708
tar -czvf "$BACKUP_DIR/aircrack_ng_backup.tar.gz" /home/flintx/aircrack-ng-1.7
tar -czvf "$BACKUP_DIR/android_studio_backup.tar.gz" /home/flintx/android-studio
tar -czvf "$BACKUP_DIR/apache_genie_backup.tar.gz" /home/flintx/apache-genie
tar -czvf "$BACKUP_DIR/Archive_org_Downloader_backup.tar.gz" /home/flintx/Archive.org-Downloader
tar -czvf "$BACKUP_DIR/bloodwine_backup.tar.gz" /home/flintx/bloodwine
tar -czvf "$BACKUP_DIR/burp_backup.tar.gz" /home/flintx/burp
tar -czvf "$BACKUP_DIR/cmds_backup.tar.gz" /home/flintx/cmds
tar -czvf "$BACKUP_DIR/flow_backup.tar.gz" /home/flintx/flow
tar -czvf "$BACKUP_DIR/frida_githubs_backup.tar.gz" /home/flintx/frida-githubs
tar -czvf "$BACKUP_DIR/gallothyname_backup.tar.gz" /home/flintx/gallothyname
tar -czvf "$BACKUP_DIR/multiclip_backup.tar.gz" /home/flintx/multiclip
tar -czvf "$BACKUP_DIR/obrida_backup.tar.gz" /home/flintx/obrida
tar -czvf "$BACKUP_DIR/pymacrorecord_backup.tar.gz" /home/flintx/pymacrorecord
tar -czvf "$BACKUP_DIR/rottenlimits_backup.tar.gz" /home/flintx/rottenlimits
tar -czvf "$BACKUP_DIR/sasha_backup.tar.gz" /home/flintx/sasha
tar -czvf "$BACKUP_DIR/scriptbackupgit_backup.tar.gz" /home/flintx/scriptbackupgit
tar -czvf "$BACKUP_DIR/trainfrida1_backup.tar.gz" /home/flintx/trainfrida1
tar -czvf "$BACKUP_DIR/trans_backup.tar.gz" /home/flintx/trans
tar -czvf "$BACKUP_DIR/transfer_backup.tar.gz" /home/flintx/transfer
tar -czvf "$BACKUP_DIR/tts_backup.tar.gz" /home/flintx/tts
tar -czvf "$BACKUP_DIR/websites_backup.tar.gz" /home/flintx/websites
tar -czvf "$BACKUP_DIR/sitemaps_backup.tar.gz" /home/flintx/sitemaps
tar -czvf "$BACKUP_DIR/themes_backup.tar.gz" /home/flintx/.themes
tar -czvf "$BACKUP_DIR/icons_backup.tar.gz" /home/flintx/.icons
tar -czvf "$BACKUP_DIR/Desktop_backup.tar.gz" /home/flintx/Desktop
tar -czvf "$BACKUP_DIR/MasterPDFEditor_backup.tar.gz" /home/flintx/MasterPDFEditor_AppImage_4
tar -czvf "$BACKUP_DIR/merge_sitemaps_backup.tar.gz" /home/flintx/sitemaps/merge-sitemaps.py
tar -czvf "$BACKUP_DIR/aircrack_ng_archive_backup.tar.gz" /home/flintx/aircrack-ng-1.7.tar.gz

# Backup additional files from the Downloads folder
tar -czvf "$BACKUP_DIR/Downloads_backup.tar.gz" /home/flintx/Downloads/

# Optionally, check disk space and confirm backup
df -h "$BACKUP_DIR"
echo "Backup process completed successfully!"
