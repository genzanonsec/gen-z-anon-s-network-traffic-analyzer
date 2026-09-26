from scapy.all import sniff, IP, TCP, UDP, get_if_addr
from collections import defaultdict
import signal
import sys
from datetime import datetime
INTERFACE = "wlo1"
LOCAL_IP = get_if_addr(INTERFACE)

connections = defaultdict(lambda: {
    "protocol": "",
    "service": "",
    "packets": 0,
    "sent": 0,
    "received": 0
})

packet_count = 0


def identify_service(protocol, src_port, dst_port):

    ports = {src_port, dst_port}

    if 443 in ports:
        if protocol == "TCP":
            return "HTTPS"
        else:
            return "QUIC/HTTP3"

    if 53 in ports:
        return "DNS"

    if 123 in ports:
        return "NTP"

    if 5353 in ports:
        return "MDNS"

    if 1900 in ports:
        return "SSDP"

    if 137 in ports:
        return "NetBIOS"

    if 631 in ports:
        return "IPP/Printing"

    if 22 in ports:
        return "SSH"

    if 80 in ports:
        return "HTTP"

    return "Unknown"


def packet_handler(packet):

    global packet_count

    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    if packet.haslayer(TCP):

        protocol = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

    elif packet.haslayer(UDP):

        protocol = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    else:
        return

    endpoint1 = (src_ip, src_port)
    endpoint2 = (dst_ip, dst_port)

    connection = tuple(sorted([endpoint1, endpoint2]))
    key = (protocol, connection)

    service = identify_service(
        protocol,
        src_port,
        dst_port
    )

    packet_size = len(packet)

    connections[key]["protocol"] = protocol
    connections[key]["service"] = service
    connections[key]["packets"] += 1

    if src_ip == LOCAL_IP:
        connections[key]["sent"] += packet_size
    else:
        connections[key]["received"] += packet_size

    packet_count += 1

    print(
        f"\rPackets captured: {packet_count}",
        end="",
        flush=True
    )

def show_summary():

    report = []

    capture_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    report.append("=" * 75)
    report.append("                         TRAFFIC ANALYZER REPORT")
    report.append("=" * 75)
    report.append(f"Capture time: {capture_time}")
    report.append(f"Interface:    {INTERFACE}")
    report.append(f"Local IP:     {LOCAL_IP}")
    report.append(f"Packets:      {packet_count}")
    report.append("")
    report.append("CONNECTION SUMMARY")
    report.append("=" * 75)

    if not connections:

        report.append("No TCP/UDP connections were captured.")

    else:

        for key, data in connections.items():

            protocol, connection = key
            endpoint1, endpoint2 = connection

            total = data["sent"] + data["received"]

            report.append("")

            report.append(
                f"[{data['service']}] "
                f"{endpoint1[0]}:{endpoint1[1]}"
                f" <-> "
                f"{endpoint2[0]}:{endpoint2[1]}"
            )

            report.append(f"Protocol:  {protocol}")
            report.append(f"Packets:   {data['packets']}")
            report.append(f"Sent:      {data['sent']} bytes")
            report.append(f"Received:  {data['received']} bytes")
            report.append(f"Total:     {total} bytes")

            if data["service"] == "Unknown":
                report.append("[NOTICE] Unknown service/port detected.")

            if data["packets"] > 100:
                report.append("[NOTICE] High-volume connection.")

    report.append("")
    report.append("=" * 75)
    report.append("Capture stopped.")
    report.append("=" * 75)

    report_text = "\n".join(report)

    print("\n")
    print(report_text)

    with open("traffic_report.txt", "w") as file:
        file.write(report_text)

    print("\nReport saved to: traffic_report.txt")
def stop_program(signal_number, frame):

    show_summary()
    sys.exit(0)


signal.signal(signal.SIGINT, stop_program)


print("=" * 60)
print("                  TRAFFIC ANALYZER")
print("=" * 60)
print(f"Interface: {INTERFACE}")
print(f"Local IP:  {LOCAL_IP}")
print("Capturing traffic...")
print("Press CTRL+C to stop.")
print("=" * 60)

sniff(
    iface=INTERFACE,
    prn=packet_handler,
    store=False
)
