#!/bin/bash

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "Python3 is not installed. Please install Python3 first."
    exit 1
fi

# Check if pip is installed
if ! command -v pip3 &> /dev/null; then
    echo "pip is not installed. Installing pip..."
    sudo apt-get update -y && sudo apt-get install python3-pip -y
    if [ $? -ne 0 ]; then
        echo "Failed to install pip. Exiting."
        exit 1
    fi
fi

# Install libraries
# List of libraries to install
libraries=(
    "pyfiglet"
    "scapy"
)

echo "Installing libraries for ZeroTrace Dependencies:"

for library in "${libraries[@]}"; do
    echo "Installing library: $library"
    pip3 install "$library"
    if [ $? -ne 0 ]; then
        echo "Failed to install $library. Please try again."
        exit 1
    fi
done

echo "All specified libraries installed successfully."

#These are built into Python, no need to install:
#concurrent (specifically concurrent.futures for ThreadPoolExecutor)
#csv
#ipaddress
#socket
#sys
#datetime
#urllib.parse (contains urlparse)
                                 