"""
DNS Exfiltration / Tunneling Detector — MITRE T1048
(Exfiltration Over Alternative Protocol)

Flags DNS queries that exhibit characteristics of C2 tunneling:
  1. Long subdomain labels (encoded payloads make labels very long)
  2. High Shannon entropy of the longest label (random-looking = encoded data)

Real tools like iodine, dnscat2, and DNSExfiltrator all produce
queries with labels far exceeding normal domain name patterns.
"""
from __future__ import annotations

import logging
import math
from typing import Dict, Optional

from models import DetectionEvent

logger = logging.getLogger(__name__)

DEFAULT_LABEL_LEN_THRESHOLD = 32    # characters in the longest DNS label
                                    # Windows GUIDs are 36 chars — intentionally caught
DEFAULT_ENTROPY_THRESHOLD   = 3.4   # bits; normal words ≈2-3, GUIDs/encoded ≈3.5-4+


def _longest_label(qname: str) -> str:
    """Return the longest dot-separated label in a domain name."""
    labels = qname.rstrip(".").split(".")
    return max(labels, key=len) if labels else ""


def _label_entropy(label: str) -> float:
    """Shannon entropy (bits) of a single DNS label string."""
    if not label:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in label:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(label)
    entropy = 0.0
    for count in freq.values():
        p = count / n
        entropy -= p * math.log2(p)
    return entropy


class DnsTunnelDetector:
    """
    Heuristic DNS tunneling detector based on label length and entropy.
    """

    def __init__(
        self,
        label_len_threshold: int = DEFAULT_LABEL_LEN_THRESHOLD,
        entropy_threshold: float = DEFAULT_ENTROPY_THRESHOLD,
    ):
        self.label_len_threshold = label_len_threshold
        self.entropy_threshold   = entropy_threshold
        self._alerted: Dict[str, float] = {}   # qname → last alert time

    def process(self, pkt) -> Optional[DetectionEvent]:
        """
        Inspect a Scapy packet.
        Returns DetectionEvent if DNS tunneling is suspected, else None.
        """
        try:
            from scapy.layers.dns import DNS, DNSQR
            from scapy.layers.inet import IP

            if not (pkt.haslayer(DNS) and pkt.haslayer(DNSQR)):
                return None

            # Only inspect queries (qr=0), not responses
            if pkt[DNS].qr != 0:
                return None

            raw = pkt[DNSQR].qname
            qname = (
                raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else str(raw)
            ).rstrip(".")

            src_ip = pkt[IP].src if pkt.haslayer(IP) else "unknown"
            now    = float(pkt.time)

            label      = _longest_label(qname)
            label_len  = len(label)
            entropy    = _label_entropy(label)

            triggered = (
                label_len >= self.label_len_threshold
                or entropy >= self.entropy_threshold
            )

            if not triggered:
                return None

            # Suppress repeat alerts for the same query within 30 s
            if now - self._alerted.get(qname, 0) < 30:
                return None

            self._alerted[qname] = now
            logger.debug(
                "DNS_TUNNEL suspected: src=%s qname=%s label_len=%d entropy=%.2f",
                src_ip, qname, label_len, entropy,
            )

            return DetectionEvent(
                timestamp=now,
                src_ip=src_ip,
                dst_ip="DNS",
                threat_type="DNS_TUNNEL",
                mitre_id="T1048",
                stage="Exfiltration",
                severity="WARNING",
                details={
                    "query":       qname,
                    "label_len":   label_len,
                    "entropy":     round(entropy, 3),
                    "len_thresh":  self.label_len_threshold,
                    "entr_thresh": self.entropy_threshold,
                },
            )
        except Exception:
            return None
