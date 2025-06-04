#!/bin/bash

# Define the source directory and destination backup path
SOURCE_DIR="/media/flintx/7eb08ac4-d6a0-d01d-500f-4f15b41813c2"
BACKUP_DIR="/mnt/my_ntfs/1224backup/IMPORTant"

# Ensure the backup directory exists
mkdir -p "$BACKUP_DIR"

# Perform the backup using rsync
rsync -av --progress --ignore-existing "$SOURCE_DIR" "$BACKUP_DIR"

# Optionally, check disk space and confirm backup
df -h "$BACKUP_DIR"
echo "Backup of $SOURCE_DIR completed successfully!"
