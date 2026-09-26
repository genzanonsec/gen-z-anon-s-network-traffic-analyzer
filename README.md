# Python Network Traffic Analyzer

A Python-based network traffic analyzer built on Ubuntu using Scapy.

This project captures TCP and UDP traffic from a local network interface, organizes packets into network conversations, identifies common services, tracks traffic volume, and generates a timestamped analysis report.

## Features

- Real-time TCP and UDP packet capture
- Bidirectional connection tracking
- Common service identification
- Packet counting
- Sent and received byte tracking
- Traffic volume analysis
- Basic anomaly notices
- Timestamped report generation
- Graceful shutdown with Ctrl+C

## Services Identified

The analyzer currently recognizes:

- HTTPS
- QUIC / HTTP3
- DNS
- NTP
- mDNS
- SSDP
- NetBIOS
- IPP / Printing
- SSH
- HTTP

Connections that do not match the current service list are labeled as `Unknown`.

## Technologies

- Python 3
- Scapy
- Ubuntu Linux
- TCP/IP
- UDP
- Network packet analysis

## How It Works

The analyzer uses Scapy to capture packets from a selected network interface.

For each TCP or UDP packet, it extracts:

- Source IP address
- Destination IP address
- Source port
- Destination port
- Protocol
- Packet size

The program then groups traffic into connections and tracks packet counts and data transferred in each direction.

At the end of a capture, the program generates a timestamped traffic report.

## Example

```text
============================================================
                  TRAFFIC ANALYZER
============================================================
Interface: wlo1
Local IP: 192.168.x.x
Capturing traffic...
Press CTRL+C to stop.
============================================================
Packets captured: 500
