#!/bin/bash

echo "Updating and upgrading system..."
sudo apt update && sudo apt upgrade -y

echo "Installing system dependencies..."
sudo apt install -y python3 python3-pip python3-venv python3-dev build-essential libsndfile1 espeak-ng sox ffmpeg cmake git wget curl unzip

echo "Installing CUDA dependencies (optional, if you have an NVIDIA GPU)..."
if lspci | grep -i nvidia; then
    echo "NVIDIA GPU detected. Installing CUDA and cuDNN..."
    sudo apt install -y nvidia-cuda-toolkit nvidia-driver-525
    echo "CUDA installed."
else
    echo "No NVIDIA GPU detected. Skipping CUDA installation."
fi

echo "Cloning Piper repository..."
git clone https://github.com/rhasspy/piper.git
cd piper || exit

echo "Setting up virtual environment..."
python3 -m venv venv
source venv/bin/activate

echo "Installing Python dependencies..."
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
pip install torch torchvision torchaudio

echo "Compiling monotonic align (for VITS)..."
cd src/python/piper_train/vits/monotonic_align || exit
python setup.py build_ext --inplace
cd ../../../../..

echo "Setup complete!"
echo "To activate the virtual environment in the future, run: source venv/bin/activate"
