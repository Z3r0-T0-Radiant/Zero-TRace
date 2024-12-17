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
   
2. **Run the Installation Script**:
   ```
   sudo chmod +x zeroTRace_install_dependencies.sh
   ```
   ![image](https://github.com/user-attachments/assets/9c18470d-99bc-462c-b1fb-366148eeddcc)
3. **Installation Process**:
   ```
   sudo ./zeroTRace_install_dependencies.sh
   ```
   - Checks for Python and pip.
   - Installs required libraries: `pyfiglet`, `scapy`, and others.
   - Confirms successful setup.
     
     ![image](https://github.com/user-attachments/assets/26c7085d-399b-4b98-96c2-96e6f473ea4d)
     
Now, ZeroTrace is ready to use!

## How to Run

Run the following code:
```
sudo python3 zeroTRace.py
```
![image](https://github.com/user-attachments/assets/623bc98c-76ee-4d80-a069-e0d497c202db)

## How to Use

### Main Menu Options

#### 1. Port Scanning
- Enter the target IP or domain.
- Specify an output file.
- Analyze over **65,536 ports** with multithreading.
- Export results to a CSV file.

![image](https://github.com/user-attachments/assets/edc40b70-0d8d-47bf-aa9b-a81e2e06214e)
#### 2. Network Packet Sniffing
- Choose a network interface.
- Set filters for protocols or IPs.
- Monitor traffic in real-time.
- Save captured packets in **.cap** and **log.txt** formats.

![image](https://github.com/user-attachments/assets/10524522-438e-4746-8f0c-a3b4004fe1da)
![image](https://github.com/user-attachments/assets/363a19fc-af7c-4fba-a169-da4c27f40b3c)

## Real-Life Applications
ZeroTrace is ideal for:
- **Penetration Testing**: Identify potential vulnerabilities.
- **Troubleshooting**: Diagnose and resolve network connectivity issues.
- **Education**: Learn about network traffic and cybersecurity as a beginner.



