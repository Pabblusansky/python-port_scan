# Python Port Scanner
Python Simple Port Scanner
Port Scanner is a simple and efficient thread-based port scanning application written in Python using the powerful Scapy library. It allows users to quickly check port availability on target IP addresses.
# Dependencies
1.Scapy<br/>
2.npcap
# Functions
Scanning one or all ports on a given valid IP address.<br/>
Detect open and closed ports and display information about each port.<br/>
Supports external configuration file to store port information (in JSON format).<br/>
Thread based port scan for a fast scanning speed<br/>
TCP Stealth(SYN) Scan of all ports from the JSON file<br/>
Logging the results in a txt file.<br/>
# Installation
1.Clone the repository:
```bash
git clone https://github.com/Pabblusansky/python-port_scan
```
OR Download it using Code->Download ZIP<br/>
2.Install the required dependencies:
```bash
pip install scapy 
```
3.Install npcap from the official site: https://npcap.com

4.Start the scanner using cmd:
```bash
python main.py
```
## Contributing
Pull requests are welcome. For major changes/ideas, please open an issue first.
# License
This project is licensed under the MIT License. See the LICENSE file for more information.
