# Zero-TRace

## Disclaimer
This project is for **educational purposes only**. ZeroTrace is intended for authorized network analysis and security testing. **Unauthorized use** on networks, systems, or devices without permission is illegal and may lead to legal consequences. Use responsibly.



## Introduction
**ZeroTRace** is a Python-based utility designed for:
- **Network Security Professionals**
- **IT Administrators**
- **Cybersecurity Enthusiasts**



## Features

### 1. Port Scanning
- Scan IP addresses or domains to identify open ports.
- Export scan results to a **CSV file**.
- Utilizes multithreading for efficiency.

### 2. Network Packet Sniffing
- Analyze real-time network traffic.
- Apply filters for specific protocols or IP addresses.
- Save captured packets to **log .txt** and **.cap files** for offline analysis.

Zero TRace is lightweight, efficient, and easy to use.



## Installation
Setting up ZeroTrace is straightforward:

1. **Clone the Repository**:
   ```
   git clone https://github.com/Z3r0-T0-Radiant/Zero-TRace.git
   cd Zero-TRace
   ```
   
2. **Run the Installation Script**:
   ```
   sudo chmod +x zeroTRace_install_dependencies.sh
   ```
3. **Installation Process**:
   ```
   sudo ./zeroTRace_install_dependencies.sh
   ```
   - Checks for Python and pip.
   - Installs required libraries: `pyfiglet`, `scapy`, and others.
   - Confirms successful setup.

Now, ZeroTrace is ready to use!

## How to Run

Run the following code:
```
sudo python3 zeroTRace.py
```


## How to Use

### Main Menu Options

#### 1. Port Scanning
- Enter the target IP or domain.
- Specify an output file.
- Analyze over **65,536 ports** with multithreading.
- Export results to a CSV file.

#### 2. Network Packet Sniffing
- Choose a network interface.
- Set filters for protocols or IPs.
- Monitor traffic in real-time.
- Save captured packets in **.cap** and **log.txt** formats.



## Real-Life Applications
ZeroTrace is ideal for:
- **Penetration Testing**: Identify potential vulnerabilities.
- **Troubleshooting**: Diagnose and resolve network connectivity issues.
- **Education**: Learn about network traffic and cybersecurity as a beginner.



