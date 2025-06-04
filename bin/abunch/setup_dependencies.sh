#!/bin/bash

# Install nginx and FastCGI wrapper
sudo apt update
sudo apt install -y nginx fcgiwrap

# Create directories
sudo mkdir -p /var/www/cyber-runner
sudo mkdir -p /var/www/cyber-runner/logs

# Set permissions
sudo chown -R www-data:www-data /var/www/cyber-runner
sudo chmod 755 /var/www/cyber-runner

# Create basic auth for logs
sudo apt install apache2-utils
sudo htpasswd -c /etc/nginx/.htpasswd admin  # It'll prompt for password

# Enable the site
sudo ln -s /etc/nginx/sites-available/cyber-runner /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default  # Remove default site

# Test and restart nginx
sudo nginx -t
sudo systemctl restart nginx
sudo systemctl enable nginx
