#!/bin/bash

# Display local machine IP address
echo "Local Machine IP Address:"
hostname -I | awk '{print $1}'