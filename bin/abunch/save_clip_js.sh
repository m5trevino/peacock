#!/bin/bash

# Directory where JS files will be stored
SCRIPT_DIR="$HOME/frida_scripts"

# Create the directory if it doesn't exist
mkdir -p "$SCRIPT_DIR"

# Function to get clipboard content based on OS
get_clipboard_content() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        pbpaste
    elif command -v xclip >/dev/null 2>&1; then
        # Linux with xclip installed
        xclip -selection clipboard -o
    elif command -v xsel >/dev/null 2>&1; then
        # Linux with xsel installed
        xsel --clipboard --output
    else
        echo "Error: Install 'xclip' or 'xsel' to use this script on Linux." >&2
        exit 1
    fi
}

# Get the clipboard content
CLIP_CONTENT=$(get_clipboard_content)

# Check if clipboard is empty
if [[ -z "$CLIP_CONTENT" ]]; then
    echo "Error: Clipboard is empty."
    exit 1
fi

# Find the highest existing number in the directory
# Assuming files are named as 001.js, 002.js, etc.
LAST_NUM=$(ls "$SCRIPT_DIR"/*.js 2>/dev/null | \
           grep -oE '[0-9]{3}\.js$' | \
           grep -oE '^[0-9]{3}' | \
           sort -nr | \
           head -n1)

# Determine the next number
if [[ -z "$LAST_NUM" ]]; then
    NEXT_NUM=1
else
    NEXT_NUM=$((10#$LAST_NUM + 1))
fi

# Format the number with leading zeros (e.g., 001)
printf -v FORMATTED_NUM "%03d" "$NEXT_NUM"

# Define the new file name
NEW_FILE="$SCRIPT_DIR/$FORMATTED_NUM.js"

# Save the clipboard content to the new file
echo "$CLIP_CONTENT" > "$NEW_FILE"

echo "Saved clipboard content to $NEW_FILE"
