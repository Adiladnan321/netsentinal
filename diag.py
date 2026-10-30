from scapy.utils import rdpcap
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP
from scapy.layers.dns import DNS, DNSQR
from collections import defaultdict
import math

def entropy(s):
    if not s: return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((v/n)*math.log2(v/n) for v in freq.values())

packets = rdpcap("2020-11-13-traffic-analysis-exercise.pcap")
print(f"Total packets: {len(packets)}")

proto_counts = defaultdict(int)
flag_samples = []
dns_queries = []
src_ips = defaultdict(int)
syn_count = 0
syn_ack_count = 0

for pkt in packets:
    if pkt.haslayer(ARP):
        proto_counts["ARP"] += 1
    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR) and pkt[DNS].qr == 0:
        proto_counts["DNS"] += 1
        q = pkt[DNSQR].qname
        if isinstance(q, bytes):
            q = q.decode("utf-8", errors="replace")
        q = q.rstrip(".")
        labels = q.split(".")
        longest = max(labels, key=len)
        dns_queries.append((q, len(longest), round(entropy(longest), 2)))
    elif pkt.haslayer(TCP):
        proto_counts["TCP"] += 1
        flags = pkt.sprintf("%TCP.flags%")
        if len(flag_samples) < 6:
            flag_samples.append(repr(flags))
        if "S" in flags and "A" not in flags:
            syn_count += 1
        if "S" in flags and "A" in flags:
            syn_ack_count += 1
    elif pkt.haslayer(UDP):
        proto_counts["UDP"] += 1
    elif pkt.haslayer(ICMP):
        proto_counts["ICMP"] += 1

    if pkt.haslayer(IP):
        src_ips[pkt[IP].src] += 1

print("\n--- Protocol distribution ---")
for k, v in sorted(proto_counts.items(), key=lambda x: -x[1]):
    print(f"  {k}: {v}")

print(f"\n--- TCP handshake stats ---")
print(f"  SYN: {syn_count}   SYN-ACK: {syn_ack_count}")
print(f"  SYN/SYN-ACK ratio: {syn_count / max(syn_ack_count,1):.2f}")

print(f"\n--- Sample TCP flags (raw repr) ---")
for f in flag_samples:
    print(f"  {f}")

print(f"\n--- Top source IPs ---")
for ip, c in sorted(src_ips.items(), key=lambda x: -x[1])[:8]:
    print(f"  {ip}: {c} packets")

print(f"\n--- Top suspicious DNS queries (by label length) ---")
dns_queries.sort(key=lambda x: -x[1])
for q, llen, ent in dns_queries[:15]:
    print(f"  label_len={llen:3d}  entropy={ent:.2f}  {q}")
