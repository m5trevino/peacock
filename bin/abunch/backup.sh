#!/bin/bash
####################################
#
# Backup to NFS mount script.
#
####################################
    
# What to backup. 
backup_files="/mnt/home /mnt/var/spool/mail /mnt/etc /mnt/root /mnt/boot /mnt/opt /mnt/usr /mnt/tmp"
# Where to backup to.
dest="/mnt/mnt/1224backup/"
    
# Create archive filename.
day=$(date +%A)
hostname=$(hostname -s)
archive_file="$hostname-$day.tgz"
    
# Print start status message.
echo "Backing up $backup_files to $dest/$archive_file"
date
echo
    
# Backup the files using tar.
tar czf $dest/$archive_file $backup_files
    
# Print end status message.
echo
echo "Backup finished"
date
    
# Long listing of files in $dest to check file sizes.
ls -lh $dest