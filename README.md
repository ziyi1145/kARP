# kARP
An ARP-internet spoofing software for MacOS designed for easy use
# Karp-Arp Spoofing tool

A Python script for performing ARP cache poisoning attacks for educational and authorized testing purposes.

## ⚠️ Legal and Ethical Warning

**This tool is for educational purposes only. Unauthorized use of this tool may:**
- Violate local, state, and federal laws
- Constitute computer fraud and abuse
- Result in criminal charges and civil liability
- Violate terms of service agreements

**Only use this tool on:**
- Networks you own
- Networks you have explicit written permission to test
- Lab environments specifically designed for security testing

## Prerequisites

### Required Dependencies
- Python 3.x
- Scapy library

### Installation
```bash
# Install Scapy
pip install scapy

# Or on some systems:
pip3 install scapy
```

### Running as Root
This script requires root/administrator privileges to create raw sockets:
```bash
# On Linux/macOS
sudo python3 arp_attack.py -t TARGET_IP -g GATEWAY_IP

# On Windows (run as Administrator)
python arp_attack.py -t TARGET_IP -g GATEWAY_IP
```

## Usage

### Basic Syntax
```bash
python3 arp_attack.py -t TARGET_IP -g GATEWAY_IP [-i INTERFACE]
```

### Required Parameters
- `-t, --target`: Target IP address to attack
- `-g, --gateway`: Gateway/router IP address

### Optional Parameters
- `-i, --interface`: Network interface to use (e.g., eth0, wlan0, en0)

### Examples

**Attack a specific target:**
```bash
sudo python3 arp_attack.py -t 192.168.1.100 -g 192.168.1.1
```

**Specify network interface:**
```bash
sudo python3 arp_attack.py -t 192.168.1.100 -g 192.168.1.1 -i wlan0
```

## How It Works

### ARP Poisoning Process
1. **MAC Resolution**: Resolves MAC addresses for both target and gateway
2. **ARP Spoofing**: Sends forged ARP replies to:
   - Tell the target that the attacker's MAC is the gateway's MAC
   - Tell the gateway that the attacker's MAC is the target's MAC
3. **Man-in-the-Middle**: All traffic between target and gateway flows through the attacker

### Features
- **Automatic MAC resolution**: Automatically finds MAC addresses
- **Clean exit**: Press Ctrl+C to stop and automatically restore ARP tables
- **Interface selection**: Support for specifying network interface
- **Real-time feedback**: Shows packet count during attack

## Detection and Prevention

### How to Detect ARP Spoofing
- Monitor ARP tables for inconsistencies
- Use ARP monitoring tools like `arpwatch`
- Look for duplicate IP addresses in ARP cache
- Monitor network for unusual traffic patterns

### How to Prevent ARP Spoofing
- Use static ARP entries
- Implement ARP spoofing detection software
- Use network segmentation
- Enable port security on switches
- Use encrypted protocols (HTTPS, SSH, VPN)

## Legal Disclaimer

This software is provided for educational purposes only. The author is not responsible for any misuse or damage caused by this program. Use this tool only on networks you own or have explicit permission to test.

## Common Issues

### "Operation not permitted"
- Run the script with root/administrator privileges

### "No such device" 
- Check that the specified interface exists
- Use `ifconfig` or `ip addr` to list available interfaces

### "Could not resolve MAC address"
- Verify target and gateway are on the same network
- Check network connectivity
- Ensure devices are powered on and connected

## Advanced Usage

### For Educational Networks
Use this tool in controlled lab environments to understand:
- Network security vulnerabilities
- Man-in-the-middle attack techniques
- Importance of encrypted communications
- Network monitoring and detection methods

## Contributing

This is an educational tool. Improvements and suggestions are welcome for educational purposes only.

## License

This tool is provided for educational purposes. Users are responsible for ensuring they have proper authorization before use. This project has a MIT liscence, feel free to download (but for educational purposes only!)

# Network Guide: Understanding Target IP and Gateway IP for ARP Attacks

## What is a Target IP?

The **Target IP** is the IP address of the device you want to intercept traffic from. This could be:

- **A specific computer** on the network (e.g., 192.168.1.100)
- **A smartphone** or mobile device
- **A server** or network appliance
- **Any device** whose network traffic you want to monitor/intercept

### How to Find Target IPs:
```bash
# Scan your local network to discover devices
nmap -sn 192.168.1.0/24

# Check ARP table to see connected devices
arp -a

# Use network scanning tools like:
# - netdiscover
# - angry IP scanner
# - Advanced IP Scanner
```

## What is a Gateway IP?

The **Gateway IP** (also called Router IP) is the IP address of your network's router that connects your local network to the internet. This is typically:

- **The main router** on your network
- **The default gateway** for all devices
- Usually ends with **.1** or **.254** in home networks

### Common Gateway IP Addresses:
- 192.168.1.1 (most common)
- 192.168.0.1
- 192.168.1.254
- 192.168.0.254
- 10.0.0.1
- 10.0.0.254

### How to Find Your Gateway IP:
```bash
# On Windows:
ipconfig
# Look for "Default Gateway"

# On macOS/Linux:
netstat -nr | grep default
# or
route -n get default
# or
ip route show default

# Quick command that works on most systems:
netstat -rn | grep '^0.0.0.0' | awk '{print $2}'
```

## Real-World Example

In a typical home network:
- **Gateway IP**: 192.168.1.1 (your router)
- **Target IP**: 192.168.1.100 (a computer on your network)

## How ARP Poisoning Works

1. **Normal Network**: Computer (192.168.1.100) ↔ Router (192.168.1.1)
2. **During Attack**: Computer → Attacker → Router → Internet
3. **All traffic** between the target and internet flows through your machine

## Important Notes

### For Testing Purposes:
- Use your own computer as the target first
- Test on virtual machines or lab networks
- Never attack devices without explicit permission

### Finding Devices on Your Network:
```bash
# Quick network scan (replace with your network range)
for ip in {1..254}; do ping -c 1 192.168.1.$ip | grep "bytes from"; done

# More advanced scanning:
nmap -sP 192.168.1.0/24
```

### Safety First:
- Always test on networks you own or have permission to test
- Start with your own devices to understand the tool
- Use virtual machines for practice

## Example Commands

```bash
# Attack your own computer (replace with actual IPs)
sudo python3 arp_attack.py -t 192.168.1.100 -g 192.168.1.1

# Attack with specific interface (like Wi-Fi)
sudo python3 arp_attack.py -t 192.168.1.100 -g 192.168.1.1 -i en0
```

Remember: This tool is for educational purposes only. Always get proper authorization before testing on any network.

