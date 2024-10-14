from scapy.all import ICMP, IP, TCP, sr1, send
import sys
#import socket
from datetime import datetime
import json
import logging
import ipaddress
import threading

# Logging implementing
logging.basicConfig(
    filename='port_scanner.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
#Open Ports array
open_ports = []
#Stop scan threading event
stop_scan = threading.Event()
# Lock for thread-safe access to open_ports
open_ports_lock = threading.Lock()
# Function to load ports from JSON file
def load_ports(filename):
    with open(filename, 'r') as f:
        ports_dict = json.load(f)
    return {int(key): value for key, value in ports_dict.items()}
#Loading JSON 
ports = load_ports('ports.json')
#Scan port function (TCP/Stealth)
def scan_port(ip, port, stealth=False):
    if stop_scan.is_set():
        return False
    try:
        syn_packet = IP(dst=ip)/TCP(dport=port, flags="S")
        response = sr1(syn_packet, timeout=1, verbose=0)
        if response:
            if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
                with open_ports_lock:
                    print(f"Port {port} ({ports.get(port, 'Unknown')}) is open")
                    open_ports.append(port)
                if stealth:
                    rst_packet = IP(dst=ip) / TCP(dport=port, flags="R")
                    send(rst_packet, verbose=0)
            elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14:  # RST+ACK
                print(f"Port {port} ({ports.get(port, 'Unknown')}) is closed")
        else:
            print(f"Port {port} ({ports.get(port, 'Unknown')}) is filtered or no response")
        logging.info(f"Scanned port {port}: {'open' if port in open_ports else 'closed'}") # Logging the results
    except KeyboardInterrupt:
        stop_scan.set()
        raise
    except Exception as e:
        print(f"Error occurred while scanning port {port}: {e}")
#Scan ports from a list of ports function
def scan_ports(ip, stealth=False):
    global open_ports
    open_ports = []
    stop_scan.clear()
    logging.info(f"\n=== Starting new scan on {ip} ===")
    print(f"Starting scan on {ip}")
    start_time = datetime.now()
    try:
        # Thread scanning ports
        threads = []
        for port in ports:
            if stop_scan.is_set():
                break
            thread = threading.Thread(target=scan_port, args=(ip, port, stealth))
            threads.append(thread)
            thread.start()
        for thread in threads:
            thread.join()
        if not stop_scan.is_set():
            end_time = datetime.now()
            print(f"Scan finished in {end_time - start_time}")
            print(f"Scanned {len(ports)} ports: {len(open_ports)} open, {len(ports) - len(open_ports)} closed")
            if open_ports:
                print("\nOpen ports:")
                for port in open_ports:
                    print(f"{port} ({ports.get(port, 'Unknown')})")
            else:
                print("No open ports found.")
    except KeyboardInterrupt:
        stop_scan.set()
        print(f"\nScan aborted.")
    except Exception as e:
        print(f"Error occured: {e}")
        logging.error(f"Error occurred: {e}")
# Scan specific ports function
def scan_specific_port(ip, port):
    logging.info(f"\n=== Starting new scan on {ip} ===")
    print(f"Scanning specific port ({port}) on {ip}")
    start_time = datetime.now()
    scan_port(ip, port)
    end_time = datetime.now()
    print(f"Scan finished in {end_time - start_time}")
# IP validation function
def get_target_ip():
    while True:
        target_ip = input("Enter target IP: ")
        try:
            ipaddress.ip_address(target_ip)  # IP check
            return target_ip
        except ValueError:
            print("Invalid IP address. Please enter a valid IPv4 address.")
def main_menu():
    while True:
        # Using get ip function
        target_ip = get_target_ip()
        print("\nChoose an action:")
        print("1. Scan a specific port(TCP)")
        print("2. Scan all common ports(TCP)")
        print("3.Scan all commmon ports(TCP Stealth/SYN scan)")
        print("4. Exit")
        
        choice = input("Enter your choice (1/2/3): ").strip()
        if choice == '1':
            while True:
                try:
                    port = int(input("Enter the port number you want to scan (1-65535): "))
                    if 1 <= port <= 65535:
                        scan_specific_port(target_ip, port)
                        break
                    else:
                        print("Port number must be between 1 and 65535.")
                except ValueError:
                    print("Please enter a valid number.")

        elif choice == '2':
            scan_ports(target_ip, stealth=False)
        elif choice == '3':
            scan_ports(target_ip, stealth=True)
        elif choice == '4':
            print("Exiting...")
            break  
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")
        #repeating the scan
        repeat = input("Do you want to scan another address? (y/n): ").strip().lower()
        if repeat != 'y':
            print("Goodbye!")
            break
if __name__ == "__main__":
    main_menu()