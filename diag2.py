"""
Targeted diagnostic: checks whether Scapy is actually decoding IP/TCP/DNS
layers from the PCAP after the link-type fix, and runs the detectors directly
to confirm thresholds are being reached.
"""
import sys
import time
sys.path.insert(0, ".")

# ---- Force Ethernet registration before any rdpcap call ----
from scapy.config import conf
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS, DNSQR
from scapy.packet import Raw
from scapy.utils import rdpcap

print("=== Layer registration check ===")
try:
    in_conf = 1 in conf.l2types
    print(f"  1 in conf.l2types: {in_conf}")
except Exception as e:
    print(f"  check failed: {e}")
    try:
        conf.l2types.register(1, Ether)
        print("  Registered Ether as type 1 via .register()")
    except Exception as e2:
        print(f"  register also failed: {e2}")

print("\n=== Loading PCAP ===")
packets = rdpcap("2020-11-13-traffic-analysis-exercise.pcap")
print(f"  Loaded {len(packets)} packets")

# Inspect first 10 packets
print("\n=== First 10 packet types ===")
for i, pkt in enumerate(packets[:10]):
    layers = [l.__name__ for l in pkt.layers()]
    print(f"  [{i}] {type(pkt).__name__:12s}  layers={layers}")

# Count by top-level type
from collections import defaultdict
type_counts = defaultdict(int)
ip_count = 0
tcp_syn = 0
raw_count = 0
dns_q = 0
dns_suspicious = 0
import math

def entropy(s):
    if not s: return 0.0
    freq = {}
    for c in s: freq[c] = freq.get(c,0)+1
    n = len(s)
    return -sum((v/n)*math.log2(v/n) for v in freq.values())

for pkt in packets:
    top = type(pkt).__name__
    type_counts[top] += 1
    if isinstance(pkt, Raw):
        raw_count += 1
    if pkt.haslayer(IP):
        ip_count += 1
    if pkt.haslayer(TCP):
        flags = pkt.sprintf("%TCP.flags%")
        if "S" in flags and "A" not in flags:
            tcp_syn += 1
    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
        if pkt[DNS].qr == 0:
            dns_q += 1
            q = pkt[DNSQR].qname
            if isinstance(q, bytes): q = q.decode("utf-8", errors="replace")
            q = q.rstrip(".")
            labels = q.split(".")
            longest = max(labels, key=len)
            if len(longest) >= 32 or entropy(longest) >= 3.4:
                dns_suspicious += 1
                if dns_suspicious <= 3:
                    print(f"\n  [SUSPICIOUS DNS] {q}  label_len={len(longest)}  entropy={entropy(longest):.2f}")

print(f"\n=== Packet type distribution ===")
for t, c in sorted(type_counts.items(), key=lambda x: -x[1]):
    print(f"  {t}: {c}")

print(f"\n=== Layer detection results ===")
print(f"  Raw (undecoded) packets : {raw_count}")
print(f"  IP packets              : {ip_count}")
print(f"  TCP SYN packets         : {tcp_syn}")
print(f"  DNS queries             : {dns_q}")
print(f"  Suspicious DNS queries  : {dns_suspicious}  (len>=32 or entropy>=3.4)")

# Run detectors directly
print("\n=== Direct detector test ===")
from detectors.port_scan import PortScanDetector
from detectors.syn_flood import SynFloodDetector
from detectors.dns_tunnel import DnsTunnelDetector

ps = PortScanDetector(threshold=15, window=10.0)
sf = SynFloodDetector(ratio_threshold=2.3, min_syns=10, window=10.0)
dt = DnsTunnelDetector(label_len_threshold=32, entropy_threshold=3.4)

ps_hits = sf_hits = dt_hits = 0
for pkt in packets:
    r = ps.process(pkt)
    if r: ps_hits += 1; print(f"  PORT_SCAN: {r.src_ip}  ports={r.details.get('unique_ports')}")
    r = sf.process(pkt)
    if r: sf_hits += 1; print(f"  SYN_FLOOD: {r.src_ip}  ratio={r.details.get('ratio')}")
    r = dt.process(pkt)
    if r: dt_hits += 1; print(f"  DNS_TUNNEL: {r.src_ip}  query={r.details.get('query','')[:60]}")

print(f"\nTotal detector fires: PORT_SCAN={ps_hits}  SYN_FLOOD={sf_hits}  DNS_TUNNEL={dt_hits}")
