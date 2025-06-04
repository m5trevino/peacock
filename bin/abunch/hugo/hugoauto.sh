#!/bin/bash

# Define domains and themes
declare -A domains
domains=(
    ["4front.42web.io"]="ananke"
    ["4front.site"]="hyde"
    ["blog.4front.site"]="minimo"
    ["matthewtrevino.4front.site"]="hello-friend"
    ["matttrevino.4front.site"]="anatole"
    ["news.4front.site"]="beautifulhugo"
    ["portfolio.4front.site"]="hermit"
    ["resources.4front.site"]="personal-web"
    ["shop.4front.site"]="victoria"
    ["tabula.4front.site"]="toha"
    ["getdome.ct.ws"]="ananke"
    ["getdome.pro"]="hyde"
    ["logdog.getdome.pro"]="minimo"
    ["matt.getdome.pro"]="hello-friend"
    ["matthew.getdome.pro"]="anatole"
    ["resume.getdome.pro"]="beautifulhugo"
    ["shop.getdome.pro"]="hermit"
    ["trevino.getdome.pro"]="personal-web"
    ["blog.trevino.today"]="victoria"
    ["matthew.trevino.today"]="toha"
    ["news.trevino.today"]="ananke"
    ["portfolio.trevino.today"]="hyde"
    ["resume.trevino.today"]="minimo"
    ["trevino-today.great-site.net"]="hello-friend"
    ["trevino.today"]="anatole"
)

# Base directory for sites
BASE_DIR="/home/flintx/websites"

# Loop through domains
for domain in "${!domains[@]}"; do
    theme="${domains[$domain]}"
    site_dir="$BASE_DIR/$domain"

    echo "Creating site for $domain using $theme theme..."

    # Create the site
    sudo hugo new site "$site_dir" --force

    # Add the theme
    cd "$site_dir"
    sudo git init
    sudo git submodule add "https://github.com/gohugoio/hugoThemes.git" "themes/$theme"
    
    # Update config.toml
    echo "baseURL = \"http://$domain/\"" > config.toml
    echo "languageCode = \"en-us\"" >> config.toml
    echo "title = \"$domain\"" >> config.toml
    echo "theme = \"$theme\"" >> config.toml

    # Add personalized content
    mkdir -p content
    cat <<EOT > content/index.md
---
title: "Welcome to $domain"
date: $(date +%Y-%m-%d)
draft: false
---

## Welcome to $domain!

This website is a showcase of Matthew Trevino's expertise, created with Hugo and the $theme theme.
Here, you'll find insights into Matthew's skills, projects, and professional journey.
EOT

    # Generate site
    sudo hugo --minify

    echo "Site for $domain created successfully!"
done

echo "All sites created and ready for deployment!"
