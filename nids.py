#!/usr/bin/env python3

from collections import defaultdict, deque
from datetime import datetime
from scapy.all import sniff, IP, TCP
import argparse
import time

# Lab detection thresholds
PORT_SCAN_PORTS = 10
PORT_SCAN_WINDOW = 10

SYN_FLOOD_PACKETS = 30
SYN_FLOOD_WINDOW = 5

# Store recent activity for each source IP
port_activity = defaultdict(deque)
syn_activity = defaultdict(deque)

# Avoid printing the same alert on every packet
alerted_scans = set()
alerted_floods = set()


def log_alert(alert_type, source, destination, details):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(
        f"\n[ALERT] {timestamp} | {alert_type}\n"
        f"        Source: {source}\n"
        f"        Destination: {destination}\n"
        f"        Details: {details}",
        flush=True
    )


def analyze_packet(packet):
    if IP not in packet or TCP not in packet:
        return

    source = packet[IP].src
    destination = packet[IP].dst
    destination_port = packet[TCP].dport
    flags = int(packet[TCP].flags)
    now = time.monotonic()

    # A SYN packet has SYN set and ACK unset.
    is_initial_syn = (flags & 0x02) and not (flags & 0x10)

    if not is_initial_syn:
        return

    # Detection 1: many distinct destination ports
    scan_key = (source, destination)
    scan_events = port_activity[scan_key]
    scan_events.append((now, destination_port))

    while scan_events and now - scan_events[0][0] > PORT_SCAN_WINDOW:
        scan_events.popleft()

    unique_ports = {port for _, port in scan_events}

    if len(unique_ports) >= PORT_SCAN_PORTS and scan_key not in alerted_scans:
        log_alert(
            "POSSIBLE PORT SCAN",
            source,
            destination,
            f"{len(unique_ports)} different TCP destination ports "
            f"within {PORT_SCAN_WINDOW} seconds"
        )
        alerted_scans.add(scan_key)

    # Detection 2: many initial SYN packets to one destination
    flood_key = (source, destination)
    flood_events = syn_activity[flood_key]
    flood_events.append(now)

    while flood_events and now - flood_events[0] > SYN_FLOOD_WINDOW:
        flood_events.popleft()

    if (
        len(flood_events) >= SYN_FLOOD_PACKETS
        and flood_key not in alerted_floods
    ):
        log_alert(
            "POSSIBLE SYN FLOOD",
            source,
            destination,
            f"{len(flood_events)} initial SYN packets "
            f"within {SYN_FLOOD_WINDOW} seconds"
        )
        alerted_floods.add(flood_key)


def main():
    parser = argparse.ArgumentParser(
        description="Beginner Network Intrusion Detection System"
    )
    parser.add_argument(
        "-i", "--interface",
        default="eth1",
        help="Network interface to monitor (default: eth1)"
    )
    args = parser.parse_args()

    print("=" * 55)
    print(" CodeAlpha - Network Intrusion Detection System")
    print("=" * 55)
    print(f"Interface: {args.interface}")
    print("Monitoring TCP SYN packets...")
    print("Press Ctrl+C to stop.")
    print()

    try:
        sniff(
            iface=args.interface,
            filter="tcp",
            prn=analyze_packet,
            store=False
        )
    except KeyboardInterrupt:
        print("\n[INFO] Monitoring stopped by user.")
    except Exception as error:
        print(f"\n[ERROR] {error}")
        print("Check the interface name and packet-capture permissions.")


if __name__ == "__main__":
    main()
