"""
Per-flow feature vector extraction for NetSentinel AI.

Aggregates raw Scapy packets into feature vectors using a sliding time window,
one FlowRecord per source IP. These vectors feed both the ML anomaly engine
and the rule-based detectors.
"""
from __future__ import annotations

import math
import time
from collections import defaultdict, deque
from typing import Dict, List, Optional

from models import FlowFeatures

FLOW_WINDOW_SECONDS = 10   # default sliding window width


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _shannon_entropy(data: bytes) -> float:
    """Compute Shannon entropy (bits per symbol) of a byte sequence."""
    if not data:
        return 0.0
    freq: Dict[int, int] = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    n = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / n
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


# ---------------------------------------------------------------------------
# FlowRecord
# ---------------------------------------------------------------------------

class FlowRecord:
    """
    Maintains rolling packet-level statistics for a single source IP
    within a configurable sliding time window.
    """

    def __init__(self, window_seconds: float = FLOW_WINDOW_SECONDS):
        self.window = window_seconds
        self._packets: deque = deque()          # (timestamp, payload_len)
        self._syn_count = 0
        self._syn_ack_count = 0
        self._icmp_count = 0
        self._dst_ports: set = set()
        self._payload_samples: deque = deque(maxlen=64)  # cap memory

    def add_packet(
        self,
        pkt_time: float,
        proto: str,
        dst_port: Optional[int],
        flags: Optional[str],
        payload: bytes,
    ) -> None:
        self._packets.append((pkt_time, len(payload)))

        if dst_port is not None:
            self._dst_ports.add(dst_port)

        if proto == "TCP" and flags:
            has_s = "S" in flags
            has_a = "A" in flags
            if has_s and not has_a:
                self._syn_count += 1
            elif has_s and has_a:
                self._syn_ack_count += 1

        if proto == "ICMP":
            self._icmp_count += 1

        if payload:
            self._payload_samples.append(payload[:64])   # first 64 bytes is enough for entropy

        self._evict(pkt_time)

    def _evict(self, now: float) -> None:
        cutoff = now - self.window
        while self._packets and self._packets[0][0] < cutoff:
            self._packets.popleft()

    def to_features(self, src_ip: str, now: float) -> FlowFeatures:
        self._evict(now)

        n = len(self._packets)
        if n == 0:
            return FlowFeatures(src_ip=src_ip, timestamp=now)

        elapsed = max(
            self._packets[-1][0] - self._packets[0][0],
            1.0,   # avoid division by zero for bursty single-second windows
        )
        pkt_rate = n / elapsed
        total_bytes = sum(b for _, b in self._packets)
        avg_payload = total_bytes / n

        combined = b"".join(self._payload_samples)
        entropy = _shannon_entropy(combined[:512])

        syn_ack_ratio = (
            self._syn_count / self._syn_ack_count
            if self._syn_ack_count > 0
            else float(self._syn_count) if self._syn_count > 0 else 1.0
        )
        icmp_ratio = self._icmp_count / n

        return FlowFeatures(
            src_ip=src_ip,
            timestamp=now,
            pkt_rate=round(pkt_rate, 3),
            byte_entropy=round(entropy, 3),
            unique_dst_ports=len(self._dst_ports),
            syn_ack_ratio=round(syn_ack_ratio, 3),
            avg_payload_len=round(avg_payload, 2),
            icmp_ratio=round(icmp_ratio, 3),
        )


# ---------------------------------------------------------------------------
# FeatureExtractor
# ---------------------------------------------------------------------------

class FeatureExtractor:
    """
    Maintains one FlowRecord per source IP and exposes feature vectors
    for the anomaly engine and detectors.
    """

    def __init__(self, window_seconds: float = FLOW_WINDOW_SECONDS):
        self.window = window_seconds
        self._flows: Dict[str, FlowRecord] = defaultdict(
            lambda: FlowRecord(window_seconds)
        )
        self.last_ts: Optional[float] = None

    def update(self, pkt) -> Optional[FlowFeatures]:
        """
        Process a raw Scapy packet. Updates the flow record for its source IP
        and returns an updated FlowFeatures vector, or None for non-IP packets.
        """
        try:
            from scapy.layers.inet import IP, TCP, UDP, ICMP

            if not pkt.haslayer(IP):
                return None

            src_ip: str = pkt[IP].src
            proto = "OTHER"
            dst_port: Optional[int] = None
            flags: Optional[str] = None
            payload = b""

            if pkt.haslayer(TCP):
                proto = "TCP"
                dst_port = pkt[TCP].dport
                flags = pkt.sprintf("%TCP.flags%")
                payload = bytes(pkt[TCP].payload)
            elif pkt.haslayer(UDP):
                proto = "UDP"
                dst_port = pkt[UDP].dport
                payload = bytes(pkt[UDP].payload)
            elif pkt.haslayer(ICMP):
                proto = "ICMP"
                payload = bytes(pkt[ICMP].payload)

            pkt_time = float(pkt.time)
            self.last_ts = pkt_time
            self._flows[src_ip].add_packet(pkt_time, proto, dst_port, flags, payload)
            return self._flows[src_ip].to_features(src_ip, pkt_time)

        except Exception:
            return None

    def get_all_features(self) -> Dict[str, FlowFeatures]:
        """Snapshot of all active flows."""
        now = self.last_ts if self.last_ts is not None else time.time()
        return {ip: flow.to_features(ip, now) for ip, flow in self._flows.items()}

    def get_top_talkers(self, n: int = 8) -> List[FlowFeatures]:
        """Return the top N source IPs ranked by packet rate."""
        features = list(self.get_all_features().values())
        return sorted(features, key=lambda f: f.pkt_rate, reverse=True)[:n]
