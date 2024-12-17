# Zero-TRace

## Disclaimer
This project is for **educational purposes only**. ZeroTrace is intended for authorized network analysis and security testing. **Unauthorized use** on networks, systems, or devices without permission is illegal and may lead to legal consequences. Use responsibly.

![Zero Trace LOGO](https://github.com/user-attachments/assets/16d07104-b8d8-40d5-914c-e6a6fbe952fa)


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
   
   ![image](https://github.com/user-attachments/assets/00805344-c0d0-41a7-adac-afb41f2f2b05)
   
2. **Run the Installation Script**:
   ```
   sudo chmod +x zeroTRace_install_dependencies.sh
   ```
   
   ![image](https://github.com/user-attachments/assets/77b64789-6f23-4b8d-ae61-498de031336e)

3. **Installation Process**:
   ```
   sudo ./zeroTRace_install_dependencies.sh
   ```
   - Checks for Python and pip.
   - Installs required libraries: `pyfiglet`, `scapy`, and others.
   - Confirms successful setup.
     
   ![image](https://github.com/user-attachments/assets/0b292114-816e-46e2-bb53-ab1f2c4bf85c)

Now, ZeroTrace is ready to use!

## How to Run

Run the following code:
```
sudo python3 zeroTRace.py
```
![image](https://github.com/user-attachments/assets/b756ac09-0a25-48cf-bf5b-3388dd84720f)


## How to Use

### Main Menu Options

#### 1. Port Scanning
- Enter the target IP or domain.
- Specify an output file.
- Analyze over **65,536 ports** with multithreading.
- Export results to a CSV file.

![image](https://github.com/user-attachments/assets/6d3e8a7c-8e9d-4b28-b4ae-931683c8fb22)

#### 2. Network Packet Sniffing
- Choose a network interface.
- Set filters for protocols or IPs.
- Monitor traffic in real-time.
- Save captured packets in **.cap** and **log.txt** formats.

![image](https://github.com/user-attachments/assets/3fe33b5a-7d35-48b9-9749-648e363f97dc)

## Real-Life Applications
ZeroTrace is ideal for:
- **Penetration Testing**: Identify potential vulnerabilities.
- **Troubleshooting**: Diagnose and resolve network connectivity issues.
- **Education**: Learn about network traffic and cybersecurity as a beginner.



