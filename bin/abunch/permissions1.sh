#!/bin/bash

# Ask user for the directory
echo "Enter the directory path you want to modify:"
read directory

# Check if the directory exists
if [ ! -d "$directory" ]; then
  echo "Error: The directory $directory does not exist."
  exit 1
fi

# Ask user for the permission settings
echo "Setting write and execute permissions for the owner and group..."
chmod ug+wx "$directory"

# Show what was done
echo
echo "Permissions updated for directory: $directory"
echo "Explanation of the flags used:"
echo " - 'u+wx': Adds write (w) and execute (x) permissions to the user (owner)"
echo " - 'g+wx': Adds write (w) and execute (x) permissions to the group"

# Display the updated permissions
echo
echo "Current permissions of the directory:"
ls -ld "$directory"
echo
echo "Permissions breakdown:"
ls -ld "$directory" | awk '{print $1}'
