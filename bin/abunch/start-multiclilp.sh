#!/usr/bin/bash

echo "Running start-multiclip.sh as $(whoami)" >> /tmp/multiclip-debug.log
echo "Environment variables:" >> /tmp/multiclip-debug.log
env >> /tmp/multiclip-debug.log

# Activate the virtual environment
source /home/flintx/virtual-env/bin/activate >> /tmp/multiclip-debug.log 2>&1

# Start the Multiclip application
python /home/flintx/multiclip/multiclip.py >> /tmp/multiclip-debug.log 2>&1
