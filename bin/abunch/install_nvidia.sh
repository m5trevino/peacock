      
#!/bin/bash

#echo "Stopping display manager..."
#sudo systemctl stop display-manager # Use generic command

# Wait 2 seconds
$sleep 2

echo "Starting NVIDIA installation using system default CC (now linked to gcc-12)..."
cd ~  # Make sure we're in your home directory

# Run the installer (using STABLE 535 driver) - NO explicit CC flags needed now
sudo ./NVIDIA-Linux-x86_64-535.154.05.run \
    --dkms \
    --no-cc-version-check \
    --ui=none \
    --no-questions

# Check if install worked
if [ $? -eq 0 ]; then
    echo "Install successful! Rebooting in 5 seconds..."
    sleep 5
    # We might NOT need to switch cc back if gcc-12 IS the intended default for your OS version + kernel combo
    sudo reboot
else
    echo "Install failed. Check /var/log/nvidia-installer.log"
    echo "Attempting to restart display manager..."
    sudo systemctl start display-manager || echo "Failed to restart display manager."
    # Clean up the link if it failed and you want to revert
    # sudo rm /usr/bin/cc
fi

    