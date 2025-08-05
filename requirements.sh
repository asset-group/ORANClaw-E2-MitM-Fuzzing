#!/bin/bash

set -e  # Exit on error

echo "📦 Installing system dependencies..."
# Add Docker's official GPG key:
sudo apt-get install -y ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

# Add the repository to Apt sources:
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt update

sudo apt install -y \
  python3-pip \
  python3-venv \
  iproute2 \
  tshark \
  libsctp-dev \
  gcc \
  make \
  libffi-dev \
  libssl-dev \
  python3-dev

# Virtual environment setup
VENV_PATH="$HOME/.venvs/oran-env"
if [ ! -d "$VENV_PATH" ]; then
  echo "🐍 Creating Python virtual environment at $VENV_PATH..."
  python3 -m venv "$VENV_PATH"
fi

echo "🔗 Activating virtual environment..."
source "$VENV_PATH/bin/activate"

# Upgrade pip
echo "⬆️  Upgrading pip..."
pip install --upgrade pip

# Install Python dependencies
echo "📥 Installing Python packages..."
pip install \
  docker \
  asn1tools \
  scapy \
  colorama \
  netifaces \
  pysctp \
  colorlog
sudo chmod +x /usr/bin/dumpcap
echo "✅ Environment setup complete!"
echo "👉 To activate the environment later, run: source $VENV_PATH/bin/activate"
