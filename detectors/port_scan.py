"""
Port Scan Detector — MITRE T1046 (Network Service Discovery)

Tracks SYN packets per source IP using a sliding time window.
Fires a DetectionEvent when a single IP contacts more than `threshold`
unique destination ports within `window_seconds`.

CS concept: defaultdict(deque) as a sliding-window per-key counter.
"""
from __future__ import annotations

import logging
from collections import defaultdict, deque
from typing import Dict, Optional

from models import DetectionEvent

logger = logging.getLogger(__name__)

DEFAULT_THRESHOLD = 15    # unique destination ports
DEFAULT_WINDOW    = 10.0  # seconds


class PortScanDetector:
    """
    Sliding-window port scan detector.

    Data structure:
        _tracker: Dict[src_ip, deque[(timestamp, dst_port)]]
    """

    def __init__(self, threshold: int = DEFAULT_THRESHOLD, window: float = DEFAULT_WINDOW):
        self.threshold = threshold
        self.window = window
        self._tracker: Dict[str, deque] = defaultdict(deque)
        self._alerted: Dict[str, float] = {}   # src_ip → last alert timestamp

    def process(self, pkt) -> Optional[DetectionEvent]:
        """
        Inspect a Scapy packet.
        Returns DetectionEvent if a port scan is confirmed, else None.
        """
        try:
            from scapy.layers.inet import IP, TCP

            if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
                return None

            flags = pkt.sprintf("%TCP.flags%")
            # Only SYN (not SYN-ACK) indicates a new connection attempt
            if "S" not in flags or "A" in flags:
                return None

            src_ip  = pkt[IP].src
            dst_ip  = pkt[IP].dst
            dst_port = pkt[TCP].dport
            now = float(pkt.time)

            dq = self._tracker[src_ip]
            dq.append((now, dst_port))

            # Evict entries older than the window
            cutoff = now - self.window
            while dq and dq[0][0] < cutoff:
                dq.popleft()

            unique_ports = {port for _, port in dq}
            if len(unique_ports) < self.threshold:
                return None

            # Suppress re-alerting within 30 s for same source
            if now - self._alerted.get(src_ip, 0) < 30:
                return None

            self._alerted[src_ip] = now
            logger.debug("PORT_SCAN detected: src=%s ports=%d", src_ip, len(unique_ports))

            return DetectionEvent(
                timestamp=now,
                src_ip=src_ip,
                dst_ip=dst_ip,
                threat_type="PORT_SCAN",
                mitre_id="T1046",
                stage="Reconnaissance",
                severity="WARNING",
                details={
                    "unique_ports": len(unique_ports),
                    "window_s": self.window,
                    "threshold": self.threshold,
                    "sample_ports": sorted(unique_ports)[:10],
                },
            )
        except Exception:
            return None
