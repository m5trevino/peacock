#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}Installing Alacritty dependencies...${NC}"

# Install rust and cargo
if ! command -v cargo &> /dev/null; then
    echo -e "${YELLOW}Installing Rust...${NC}"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    source $HOME/.cargo/env
fi

# Install dependencies
echo -e "${YELLOW}Installing required packages...${NC}"
sudo apt update
sudo apt install -y \
    cmake \
    pkg-config \
    libfreetype6-dev \
    libfontconfig1-dev \
    libxcb-xfixes0-dev \
    libxkbcommon-dev \
    python3 \
    scdoc

# Clone Alacritty
echo -e "${YELLOW}Cloning Alacritty...${NC}"
git clone https://github.com/alacritty/alacritty.git
cd alacritty

# Build and install
echo -e "${YELLOW}Building Alacritty (this might take a few minutes)...${NC}"
cargo build --release

# Install binary
echo -e "${YELLOW}Installing Alacritty...${NC}"
sudo cp target/release/alacritty /usr/local/bin/

# Install desktop entry
echo -e "${YELLOW}Setting up desktop entry...${NC}"
sudo cp extra/logo/alacritty-term.svg /usr/share/pixmaps/Alacritty.svg
sudo desktop-file-install extra/linux/Alacritty.desktop
sudo update-desktop-database

# Install man pages
echo -e "${YELLOW}Installing manual pages...${NC}"
sudo mkdir -p /usr/local/share/man/man1
sudo mkdir -p /usr/local/share/man/man5
scdoc < extra/man/alacritty.1.scd | gzip -c | sudo tee /usr/local/share/man/man1/alacritty.1.gz > /dev/null
scdoc < extra/man/alacritty-msg.1.scd | gzip -c | sudo tee /usr/local/share/man/man1/alacritty-msg.1.gz > /dev/null
scdoc < extra/man/alacritty.5.scd | gzip -c | sudo tee /usr/local/share/man/man5/alacritty.5.gz > /dev/null

# Install shell completions
echo -e "${YELLOW}Installing shell completions...${NC}"
mkdir -p ${ZDOTDIR:-~}/.zsh_functions
cp extra/completions/_alacritty ${ZDOTDIR:-~}/.zsh_functions/_alacritty

echo -e "${GREEN}Alacritty installation complete!${NC}"
echo -e "${YELLOW}You may need to log out and back in for all changes to take effect.${NC}"
