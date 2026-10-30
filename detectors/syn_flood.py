"""
SYN Flood Detector — MITRE T1499 (Endpoint Denial of Service)

Monitors the SYN / SYN-ACK ratio per source IP within a sliding window.
A heavily imbalanced ratio (many SYNs, almost no SYN-ACKs) signals a
half-open connection flood aimed at exhausting server state tables.
"""
from __future__ import annotations

import logging
from collections import defaultdict, deque
from typing import Dict, Optional

from models import DetectionEvent

logger = logging.getLogger(__name__)

DEFAULT_RATIO_THRESHOLD = 2.3   # SYN : SYN-ACK ratio  (PCAP shows 2.56 — real signal)
DEFAULT_MIN_SYNS        = 10    # minimum SYN count before evaluating
DEFAULT_WINDOW          = 10.0  # seconds


class SynFloodDetector:
    """
    Sliding-window SYN flood detector.

    Data structure:
        _tracker: Dict[src_ip, deque[(timestamp, packet_type)]]
        where packet_type is "SYN" or "SYN-ACK".
    """

    def __init__(
        self,
        ratio_threshold: float = DEFAULT_RATIO_THRESHOLD,
        min_syns: int = DEFAULT_MIN_SYNS,
        window: float = DEFAULT_WINDOW,
    ):
        self.ratio_threshold = ratio_threshold
        self.min_syns = min_syns
        self.window = window
        self._tracker: Dict[str, deque] = defaultdict(deque)
        self._alerted: Dict[str, float] = {}

    def process(self, pkt) -> Optional[DetectionEvent]:
        """
        Inspect a Scapy packet.
        Returns DetectionEvent if a SYN flood is detected, else None.
        """
        try:
            from scapy.layers.inet import IP, TCP

            if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
                return None

            flags = pkt.sprintf("%TCP.flags%")
            is_syn     = "S" in flags and "A" not in flags
            is_syn_ack = "S" in flags and "A" in flags

            if not (is_syn or is_syn_ack):
                return None

            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            now    = float(pkt.time)
            kind   = "SYN" if is_syn else "SYN-ACK"

            dq = self._tracker[src_ip]
            dq.append((now, kind))

            # Evict old entries
            cutoff = now - self.window
            while dq and dq[0][0] < cutoff:
                dq.popleft()

            syn_count     = sum(1 for _, t in dq if t == "SYN")
            syn_ack_count = sum(1 for _, t in dq if t == "SYN-ACK")

            if syn_count < self.min_syns:
                return None

            ratio = syn_count / max(syn_ack_count, 1)
            if ratio < self.ratio_threshold:
                return None

            # Suppress repeat alerts for 30 s
            if now - self._alerted.get(src_ip, 0) < 30:
                return None

            self._alerted[src_ip] = now
            logger.debug("SYN_FLOOD detected: src=%s ratio=%.1f", src_ip, ratio)

            return DetectionEvent(
                timestamp=now,
                src_ip=src_ip,
                dst_ip=dst_ip,
                threat_type="SYN_FLOOD",
                mitre_id="T1499",
                stage="Impact",
                severity="CRITICAL",
                details={
                    "syn_count": syn_count,
                    "syn_ack_count": syn_ack_count,
                    "ratio": round(ratio, 2),
                    "threshold": self.ratio_threshold,
                },
            )
        except Exception:
            return None
