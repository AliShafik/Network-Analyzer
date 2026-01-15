# PySniff - Network Protocol Analyzer

A lightweight network sniffer and traffic analyzer built in Python. I developed this tool to explore packet structures at the protocol level and to implement basic Intrusion Detection System (IDS) logic, specifically focusing on ARP spoofing and credential exposure in unencrypted traffic.

## Features
* **Protocol Dissection:** Captures and decodes IP, TCP, UDP, and ICMP headers in real-time.
* **Credential Flagging:** Automatically scans unencrypted HTTP POST requests for sensitive keywords (e.g., `password`, `login`, `user`).
* **ARP Spoofing Detection:** Compares sender MAC addresses against network lookups to identify potential Man-in-the-Middle (MitM) attacks.
* **Traffic Statistics:** Aggregates bandwidth usage per IP address to identify the top consumers on the network.

## Getting Started

### Prerequisites
* Python 3.x
* [Scapy](https://scapy.net/) library

```bash
pip install scapy