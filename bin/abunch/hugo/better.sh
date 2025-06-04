#!/bin/bash

# Define directories
THEMES_DIR="/home/flintx/hugothemes"
SITE_DIR="/home/flintx/websites"

# Array of all theme names
THEME_LIST=(
  "alpha-church"
  "typo"
  "hugo-coder"
  "hugo-spectre-pixel-theme"
  "tella"
  "hugo-theme-notrack"
  "hugo-theme-terminalcv"
  "hugo-travelify-theme"
  "coming-soon"
  "hugo-theme-console"
  "huey"
  "hugo-split-theme"
  "hugo-theme-iris"
  "minimal-marketing"
  "beautifulhugo"
  # Add all remaining theme names here
)

# Function to prepare a theme
prepare_theme() {
  local THEME_NAME="$1"
  local THEME_PATH="$THEMES_DIR/$THEME_NAME"
  local SITE_PATH="$SITE_DIR/$THEME_NAME-site"

  # Check if the theme exists
  if [ ! -d "$THEME_PATH" ]; then
    echo "ERROR: Theme directory $THEME_PATH not found. Make sure the theme is cloned."
    return 1
  fi

  # Step 1: Create a new Hugo site for the theme
  if [ -d "$SITE_PATH" ]; then
    echo "Removing existing site directory: $SITE_PATH"
    rm -rf "$SITE_PATH"
  fi

  hugo new site "$SITE_PATH"

  # Step 2: Link the theme to the site
  mkdir -p "$SITE_PATH/themes"
  ln -s "$THEME_PATH" "$SITE_PATH/themes/$THEME_NAME"

  # Step 3: Copy exampleSite configuration
  if [ -d "$THEME_PATH/exampleSite" ]; then
    echo "Copying exampleSite content to the root of the Hugo site."
    cp -r "$THEME_PATH/exampleSite/"* "$SITE_PATH/"
    sed -i '/themesDir =/d' "$SITE_PATH/config.toml"
  else
    echo "WARNING: exampleSite not found for theme $THEME_NAME."
  fi

  # Step 4: Verify and prepare additional configurations
  CONFIG_FILE="$SITE_PATH/config.toml"
  if [ -f "$CONFIG_FILE" ]; then
    echo "Customizing config.toml for $THEME_NAME"
    case "$THEME_NAME" in
      "alpha-church")
        echo -e "\n# Additional settings for Alpha Church\nGoogleAnalytics = \"\"\ncustomCSS = [\"/css/my.css\"]" >> "$CONFIG_FILE"
        ;;
      "typo")
        echo -e "\n# Additional settings for Typo\n[module]\n[[module.imports]]\npath = \"github.com/tomfran/typo\"" >> "$CONFIG_FILE"
        sed -i '/theme = /d' "$CONFIG_FILE"
        ;;
      "hugo-coder")
        echo -e "\n# Additional settings for Hugo Coder\nbaseURL = 'https://example.org/'\nGoogleAnalytics = \"G-XXXXXXXXXX\"" >> "$CONFIG_FILE"
        ;;
      "hugo-spectre-pixel-theme")
        echo -e "\n# Additional settings for Hugo Spectre Pixel Theme\ntitle = 'Spectre Pixel Portfolio'\n" >> "$CONFIG_FILE"
        cp "$THEME_PATH/exampleSite/config.toml" "$CONFIG_FILE" 2>/dev/null || echo "WARNING: Default config not copied for $THEME_NAME."
        ;;
      "tella")
        echo -e "\n# Additional settings for Tella\ntitle = 'Tella Company Theme'\nGoogleAnalytics = \"\"" >> "$CONFIG_FILE"
        ;;
      "hugo-theme-notrack")
        echo -e "\n# Additional settings for Notrack\nauthor = 'FlintX'\nbaseURL = 'https://notrack.example.com/'\n" >> "$CONFIG_FILE"
        ;;
      "hugo-theme-terminalcv")
        echo -e "\n# Additional settings for TerminalCV\nstartx = true\nexit = true\n" >> "$CONFIG_FILE"
        ;;
      "hugo-travelify-theme")
        echo -e "\n# Additional settings for Travelify\ndisqusShortname = ''\nGoogleAnalytics = ''\n" >> "$CONFIG_FILE"
        ;;
      "coming-soon")
        echo -e "\n# Additional settings for Coming Soon\ntitle = 'Coming Soon'\n" >> "$CONFIG_FILE"
        ;;
      "hugo-theme-console")
        echo -e "\n# Additional settings for Console Theme\ntitle = 'Console Theme'\n" >> "$CONFIG_FILE"
        ;;
      "huey")
        echo -e "\n# Additional settings for Huey Theme\nfontawesomeToken = \"YOUR_TOKEN_HERE\"\n" >> "$CONFIG_FILE"
        ;;
      "hugo-split-theme")
        echo -e "\n# Additional settings for Split Theme\ntitle = 'Split Theme'\n" >> "$CONFIG_FILE"
        ;;
      "hugo-theme-iris")
        echo -e "\n# Additional settings for Hugo Iris\nparams:\n  homeSubtitle = \"Welcome to Iris\"\n  enableSharingButtons = true\n" >> "$CONFIG_FILE"
        ;;
      "minimal-marketing")
        echo -e "\n# Additional settings for Minimal Marketing\nbaseURL = 'https://minimalmarketing.com/'\n" >> "$CONFIG_FILE"
        ;;
      "beautifulhugo")
        echo -e "\n# Additional settings for Beautiful Hugo\nGoogleAnalytics = 'UA-XXXXXX-X'\ndescription = 'A beautiful site powered by Hugo'\n" >> "$CONFIG_FILE"
        ;;
      # Add cases for additional themes here
    esac
  else
    echo "ERROR: config.toml not found in $SITE_PATH"
    return 1
  fi

  # Step 5: Test build the site
  hugo -D -s "$SITE_PATH"
  if [ $? -ne 0 ]; then
    echo "ERROR: Hugo build failed for $THEME_NAME. Check the logs above."
    return 1
  fi

  echo "Theme $THEME_NAME has been prepared and tested successfully. Site is located at $SITE_PATH/public."
}

# Loop through all themes
for THEME_NAME in "${THEME_LIST[@]}"; do
  echo "Preparing theme: $THEME_NAME"
  prepare_theme "$THEME_NAME"
done
