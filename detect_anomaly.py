from scapy.all import rdpcap, IP
from collections import defaultdict

# Parameters
TIME_WINDOW = 10        # seconds
PACKET_THRESHOLD = 100  # packets

# Load PCAP file
packets = rdpcap("smallFlows.pcap")
print("Total packets loaded:", len(packets))

# Dictionary to store packet counts
packet_counts = defaultdict(int)

# Process packets
for pkt in packets:
    if IP in pkt:
        src_ip = pkt[IP].src
        timestamp = pkt.time

        # Convert timestamp to time window
        window = int(timestamp // TIME_WINDOW)

        # Count packets per IP per window
        packet_counts[(src_ip, window)] += 1

# Print sample results
print("\nSample packet counts per IP per time window:")

sample_count = 0
for (ip, window), count in packet_counts.items():
    print(f"IP: {ip}, Time window: {window}, Packets: {count}")
    sample_count += 1
    if sample_count == 5:
        break


# Detect anomalies
print("\nAnomaly Detection Alerts:")
anomaly_count = 0

with open("alerts.log", "w") as log_file:
    for (ip, window), count in packet_counts.items():
        if count > PACKET_THRESHOLD:
            alert_message = (
                f"ALERT: Anomalous traffic detected | "
                f"Source IP: {ip}, "
                f"Time Window: {window * TIME_WINDOW}-{(window + 1) * TIME_WINDOW} sec, "
                f"Packet Count: {count}"
            )

            print(alert_message)
            log_file.write(alert_message + "\n")
            anomaly_count += 1

print(f"\nTotal anomalies detected: {anomaly_count}")
