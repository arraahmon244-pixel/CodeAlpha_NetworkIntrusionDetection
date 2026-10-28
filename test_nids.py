from scapy.all import IP, TCP
from nids import analyze_packet, port_activity, syn_activity

# Reset detection state so each test starts clean.
port_activity.clear()
syn_activity.clear()

import nids
nids.alerted_scans.clear()
nids.alerted_floods.clear()

print("TEST 1: Simulated port scan")

for port in range(20, 30):
    packet = IP(src="192.0.2.10", dst="192.0.2.20") / TCP(
        sport=40000 + port, dport=port, flags="S"
    )
    analyze_packet(packet)

print("\nTEST 2: Simulated SYN flood")

port_activity.clear()
syn_activity.clear()
nids.alerted_scans.clear()
nids.alerted_floods.clear()

for _ in range(30):
    packet = IP(src="192.0.2.30", dst="192.0.2.40") / TCP(
        sport=45000, dport=80, flags="S"
    )
    analyze_packet(packet)

print("\nTests finished.")
