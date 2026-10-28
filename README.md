# Network Intrusion Detection System (NIDS)

## Overview
A beginner-friendly Network Intrusion Detection System built with Python and Scapy as part of my CodeAlpha Cyber Security Internship.

The program monitors TCP packets on a selected network interface and raises alerts for traffic patterns that may indicate a port scan or SYN flood.

## Features
- Monitors TCP traffic on a selected network interface.
- Detects possible port scans based on distinct TCP destination ports.
- Detects possible SYN floods based on repeated initial SYN packets.
- Displays timestamps, source and destination IP addresses, and alert details.
- Includes simulated tests for both detection rules.

## Requirements
- Python 3
- Scapy
- Linux environment with permission to capture network traffic

## Usage

Start monitoring on the default interface:

```bash
sudo python3 nids.py
```

Choose a different interface:

```bash
sudo python3 nids.py --interface eth1
```

Display available options:

```bash
python3 nids.py --help
```

Stop monitoring with `Ctrl+C`.

## Testing

Run the simulated detection tests:

```bash
python3 test_nids.py
```

The tests simulate packets in memory; they do not send attack traffic across the network. They check that the program raises alerts for the configured port-scan and SYN-flood patterns.

## Detection Thresholds
- Port scan: 10 distinct TCP destination ports within 10 seconds.
- SYN flood: 30 initial TCP SYN packets within 5 seconds.

These are simple lab thresholds for demonstration, not universal indicators of an attack.

## Limitations
- This is an educational prototype, not a production-grade IDS.
- It analyzes TCP SYN traffic and does not detect every type of intrusion.
- Legitimate traffic can trigger false positives.
- Detection is limited to traffic visible on the selected interface.
- The SYN-flood rule counts packets from a source to a destination; it does not establish that a real denial-of-service attack is occurring.

## Disclaimer
Use this tool only on systems and networks you own or have explicit permission to monitor.

## Author
Abdurrahmon Idris
