#!/bin/bash

# Install Python 3.9
apt-get update
apt-get install -y python3.9 python3-pip libpcap-dev

# Install required Python packages
pip install colorama numpy pandas scikit-learn joblib

# Offer options to the user
echo "Please select one of the following options:"
echo "1. Setup for router"
echo "2. Setup for PC"

# Read the user's choice
read choice

# Install additional packages based on the user's choice
if [ $choice -eq 1 ]; then
    apt-get install -y hostapd isc-dhcp-server
    pip install netifaces
    echo "hostapd and isc-dhcp-server packages have been successfully installed."
fi

# Build and install PcapPlusPlus
cd PcapPlusPlus-22.11/
./configure-linux.sh --default
make clean
make
make install

# Process completed
echo "Required packages have been successfully downloaded and installed."
