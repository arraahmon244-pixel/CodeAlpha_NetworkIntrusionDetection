# Network Intrusion Detection System — Security Test Report

## 1. Objective
To build and test a Python-based Network Intrusion Detection System (NIDS) that identifies suspicious TCP SYN traffic patterns.

## 2. Tools Used
- Kali Linux
- Python 3
- Scapy
- Terminal-based testing

## 3. Detection Rules
**Possible port scan:** An alert is generated when one source IP sends initial TCP SYN packets to 10 or more distinct destination ports on the same destination IP within 10 seconds.

**Possible SYN flood:** An alert is generated when one source IP sends 30 or more initial TCP SYN packets to the same destination IP within 5 seconds.

## 4. Test Results

| Test | Expected result | Actual result |
|---|---|---|
| Simulated port scan | Port-scan alert | Passed |
| Simulated SYN flood | SYN-flood alert | Passed |
| Python syntax check | No syntax errors | Passed |

## 5. Limitations
- The detection rules use simple thresholds and may produce false positives.
- The tests simulate packets in memory rather than sending traffic across a network.
- The program only analyzes TCP SYN traffic visible on the selected interface.
- Alerts indicate suspicious patterns, not confirmed attacks.

## 6. Conclusion
The prototype successfully triggered both configured detection rules during simulated testing. Further work could include more detection rules, structured logging, configurable thresholds, and testing in an authorized lab network.

## 7. Safety
Testing should be limited to systems and networks owned by the tester or explicitly authorized for monitoring.
