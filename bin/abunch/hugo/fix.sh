#!/bin/bash

# Define directories and constants
THEMES_DIR="/home/flintx/hugothemes"
PREPARED_THEMES_DIR="/home/flintx/prepared-themes"
THEME_SETUP_FILE="/mnt/data/combined_readmes.txt"
LOG_FILE="/home/flintx/theme-preparation.log"

# Create necessary directories
mkdir -p "$PREPARED_THEMES_DIR"

# Function to prepare a theme
prepare_theme() {
    local theme_name="$1"
    local theme_path="$THEMES_DIR/$theme_name"
    local prepared_path="$PREPARED_THEMES_DIR/$theme_name"

    echo "Preparing theme: $theme_name" | tee -a "$LOG_FILE"

    if [[ ! -d "$theme_path" ]]; then
        echo "ERROR: Theme directory $theme_path does not exist." | tee -a "$LOG_FILE"
        return 1
    fi

    # Copy the theme to the prepared directory
    cp -r "$theme_path" "$prepared_path"

    # Check and apply setup instructions
    if grep -q "$theme_name" "$THEME_SETUP_FILE"; then
        echo "Applying setup instructions for $theme_name" | tee -a "$LOG_FILE"
        instructions=$(grep -A 10 "$theme_name" "$THEME_SETUP_FILE")
        echo "$instructions" > "$prepared_path/setup_instructions.txt"

        # Execute any specific setup commands found in the instructions
        if echo "$instructions" | grep -q "git submodule"; then
            (cd "$prepared_path" && eval "$(echo "$instructions" | grep 'git submodule')")
        fi
    else
        echo "No specific setup instructions found for $theme_name" | tee -a "$LOG_FILE"
    fi

    # Validate the theme by checking for required files
    required_files=("layouts/_default/baseof.html" "layouts/_default/single.html" "layouts/_default/list.html")
    for file in "${required_files[@]}"; do
        if [[ ! -f "$prepared_path/$file" ]]; then
            echo "WARNING: Missing required file $file in $theme_name. Adding fallback." | tee -a "$LOG_FILE"
            mkdir -p "$prepared_path/$(dirname "$file")"
            cat << EOF > "$prepared_path/$file"
<!DOCTYPE html>
<html>
<head>
    <title>{{ .Title }}</title>
</head>
<body>
    {{ block "main" . }}{{ end }}
</body>
</html>
EOF
        fi
    done

    echo "Theme $theme_name prepared successfully." | tee -a "$LOG_FILE"
}

# Select 30 themes to prepare
themes_to_prepare=( $(ls "$THEMES_DIR" | head -n 30) )

for theme in "${themes_to_prepare[@]}"; do
    prepare_theme "$theme"
done

# Final message
echo "All themes have been prepared. Check $PREPARED_THEMES_DIR for the results." | tee -a "$LOG_FILE"
