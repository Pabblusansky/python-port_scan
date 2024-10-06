from scapy.all import ICMP, IP, TCP, sr1
import sys
import socket
from datetime import datetime
import json
import logging

# Logging implementing
logging.basicConfig(filename='port_scanner.log', level=logging.INFO)
#Open Ports array
open_ports = []
# Function to load ports from JSON file
def load_ports(filename):
    with open(filename, 'r') as f:
        ports_dict = json.load(f)
    return {int(key): value for key, value in ports_dict.items()}
#Loading JSON 
ports = load_ports('ports.json')
#Scan port
def scan_port(ip, port): 
    syn_packet = IP(dst=ip)/TCP(dport=port, flags="S")
    response = sr1(syn_packet, timeout=1, verbose=0)
    if response:
        if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            print(f"Port {port} ({ports.get(port, 'Unknown')}) is open")
            open_ports.append(port)
        elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14:  # RST+ACK
            print(f"Port {port} ({ports.get(port, 'Unknown')}) is closed")
    else:
        print(f"Port {port} ({ports.get(port, 'Unknown')}) is filtered or no response")
    logging.info(f"Scanned port {port}: {'open' if port in open_ports else 'closed'}") # Logging the results
#Scan ports from a list of ports
def scan_ports(ip):
    try:
        print(f"Starting scan on {ip}")
        start_time = datetime.now()
        for port in ports:
            scan_port(ip, port)
        end_time = datetime.now()
        print(f"Scan finished in {end_time - start_time}")
        print(f"Scanned {len(ports)} ports: {len(open_ports)} open, {len(ports) - len(open_ports)} closed")
        if open_ports:
            print("\nOpen ports:")
            for port in open_ports:
                print(f"{port} ({ports.get(port, 'Unknown')})")
        else:
            print("No open ports found.")
    except Exception as e:
        print(f"Error occured: {e}")
#Scan specific ports
def scan_specific_port(ip, port):
    print(f"Scanning specific port ({port}) on {ip}")
    start_time = datetime.now()
    scan_port(ip, port)
    end_time = datetime.now()
    print(f"Scan finished in {end_time - start_time}")

if __name__ == "__main__":
    target_ip = input("Enter Target IP: ")
    choice = input("Do you want to (1) scan a specific port or (2) scan all ports? Enter 1 or 2: ")
    if choice == '1':
        port = int(input("Enter the port number you want to scan: "))
        scan_specific_port(target_ip, port)
    elif choice == '2':
        scan_ports(target_ip)
    else:
        print("Invalid choice. Please enter 1 or 2.")
    input("Press Enter to exit...")
    