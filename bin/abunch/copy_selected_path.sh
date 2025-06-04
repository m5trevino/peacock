#!/bin/bash
# Get the currently selected file in Nautilus
selected_file=$(xdotool getwindowfocus getwindowname)

# If the selected file is found, get its path and copy to clipboard
if [ ! -z "$selected_file" ]; then
    file_path=$(realpath "$selected_file")
    echo -n "$file_path" | xclip -selection clipboard
    notify-send "Copied Path" "$file_path"
else
    notify-send "No file selected!"
fi
