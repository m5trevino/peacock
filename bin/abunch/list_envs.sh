#!/bin/bash

# Directory where your environments are stored
env_dir="/home/flintx"

# Function to list installed apps in a given environment
list_apps() {
    env_path="$env_dir/$1"
    if [ -d "$env_path/bin" ]; then
        echo "Installed packages in $1:"
        # List executables in the 'bin' directory, assuming they are apps
        ls -1 "$env_path/bin"
    else
        echo "No 'bin' directory found for $1. Skipping..."
    fi
}

# List all directories under /home/flintx that look like environments
echo "Available environments under $env_dir:"
environments=$(ls -d $env_dir/*/ | grep -E 'poetry-env|pentest-env|virtual-env')

if [ -z "$environments" ]; then
    echo "No environments found in $env_dir."
    exit 1
fi

# List the environments and their major apps
for env in $environments; do
    env_name=$(basename "$env")
    echo "Checking $env_name..."
    list_apps "$env_name"
    echo "--------------------------------"
done

# Prompt user to choose an environment to activate
echo "Which environment would you like to activate? Enter the name (e.g., 'poetry-env'):"
read selected_env

if [[ -d "$env_dir/$selected_env" ]]; then
    echo "Activating $selected_env..."
    source "$env_dir/$selected_env/bin/activate"
else
    echo "Environment $selected_env not found!"
    exit 1
fi
