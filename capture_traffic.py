from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
from datetime import datetime
import time


print("=" * 70)
print("        LIVE NETWORK FLOW MONITOR")
print("=" * 70)


# Stores information about each network flow
flows = {}


def packet_callback(packet):

    # Ignore packets that don't contain IP
    if not packet.haslayer(IP):
        return

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst
    protocol = packet[IP].proto
    packet_size = len(packet)

    # Identify protocol
    if packet.haslayer(TCP):
        protocol_name = "TCP"

        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport

    elif packet.haslayer(UDP):
        protocol_name = "UDP"

        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

    else:
        protocol_name = str(protocol)

        source_port = 0
        destination_port = 0


    # Create a flow ID
    flow_id = (
        source_ip,
        destination_ip,
        source_port,
        destination_port,
        protocol_name
    )


    # Create new flow
    if flow_id not in flows:

        flows[flow_id] = {

            "start_time": time.time(),

            "last_time": time.time(),

            "forward_packets": 0,

            "backward_packets": 0,

            "forward_bytes": 0,

            "backward_bytes": 0,

            "packet_sizes": [],

            "syn_count": 0,

            "rst_count": 0
        }


    flow = flows[flow_id]


    # Update timing
    flow["last_time"] = time.time()


    # For now, packets matching the original direction
    # are counted as forward packets.
    flow["forward_packets"] += 1
    flow["forward_bytes"] += packet_size


    flow["packet_sizes"].append(packet_size)


    # TCP flags
    if packet.haslayer(TCP):

        flags = packet[TCP].flags

        if flags & 0x02:
            flow["syn_count"] += 1

        if flags & 0x04:
            flow["rst_count"] += 1


    # Calculate flow duration
    duration = flow["last_time"] - flow["start_time"]


    # Avoid division by zero
    if duration <= 0:
        duration = 0.000001


    bytes_per_second = flow["forward_bytes"] / duration

    packets_per_second = flow["forward_packets"] / duration


    print("\n" + "-" * 70)

    print("LIVE FLOW")

    print("-" * 70)

    print("Time        :", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    print("Source      :", source_ip)

    print("Destination :", destination_ip)

    print("Protocol    :", protocol_name)

    print("Source Port :", source_port)

    print("Dest Port   :", destination_port)

    print("Duration    :", round(duration, 4), "seconds")

    print("Packets     :", flow["forward_packets"])

    print("Bytes       :", flow["forward_bytes"])

    print("Bytes/sec   :", round(bytes_per_second, 2))

    print("Packets/sec :", round(packets_per_second, 2))

    print("SYN Count   :", flow["syn_count"])

    print("RST Count   :", flow["rst_count"])


print("\nStarting live network monitoring...")

print("Open a website or use the internet to generate traffic.")

print("Press CTRL + C to stop.\n")


sniff(
    prn=packet_callback,
    store=False
)