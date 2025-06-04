#!/bin/bash

# Define sites and themes
declare -A sites
sites=(
  ["4front.42web.io"]="ananke"
  ["4front.site"]="victoria"
  ["blog.4front.site"]="minimo"
  ["matthewtrevino.4front.site"]="hyde"
  ["matttrevino.4front.site"]="anatole"
  ["news.4front.site"]="hello-friend"
  ["portfolio.4front.site"]="hermit"
  ["resources.4front.site"]="personal-web"
  ["shop.4front.site"]="victoria"
  ["tabula.4front.site"]="toha"
  ["getdome.ct.ws"]="anatole"
  ["getdome.pro"]="minimo"
  ["logdog.getdome.pro"]="minimo"
  ["matt.getdome.pro"]="anatole"
  ["matthew.getdome.pro"]="anatole"
  ["resume.getdome.pro"]="hyde"
  ["shop.getdome.pro"]="hermit"
  ["trevino.getdome.pro"]="personal-web"
  ["blog.trevino.today"]="victoria"
  ["matthew.trevino.today"]="hello-friend"
  ["news.trevino.today"]="hello-friend"
  ["portfolio.trevino.today"]="hyde"
  ["resume.trevino.today"]="hermit"
  ["trevino-today.great-site.net"]="hello-friend"
  ["trevino.today"]="anatole"
)

# Directory for websites
BASE_DIR="/home/flintx/websites"
mkdir -p $BASE_DIR

# Install themes, create content, and build each site
for site in "${!sites[@]}"; do
  theme=${sites[$site]}
  echo "Creating site for $site using $theme theme..."
  
  SITE_DIR="$BASE_DIR/$site"
  
  # Create the site
  sudo hugo new site $SITE_DIR --force
  
  # Initialize Git and add theme
  cd $SITE_DIR
  sudo git init
  sudo git submodule add https://github.com/gohugoio/hugoThemes.git themes/$theme
  
  # Update config.toml
  sudo bash -c "cat > $SITE_DIR/config.toml" <<EOF
baseURL = "https://$site"
languageCode = "en-us"
title = "$site"
theme = "$theme"
EOF
  
  # Add dummy content
  sudo hugo new content/index.md
  
  # Build static site
  sudo hugo --minify
  
  echo "Site for $site created successfully!"
done

echo "All sites are ready in $BASE_DIR."
