#!/bin/bash

# Debugging log file
exec > /tmp/start-multiclip.log 2>&1
set -x

# Ensure the DISPLAY and XDG_RUNTIME_DIR are set
export DISPLAY=:0
export XDG_RUNTIME_DIR=/run/user/1000

# Activate the virtual environment
source /home/flintx/virtual-env/bin/activate

# Run the Python script
python3 /home/flintx/multiclip/multiclip.py
