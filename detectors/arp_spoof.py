"""
ARP Spoofing Detector — MITRE T1557 (Adversary-in-the-Middle)

Maintains an IP→MAC mapping table (the ARPTable).
Fires a DetectionEvent when an ARP reply claims an IP address that is
already mapped to a *different* MAC — a classic ARP poisoning signal.
"""
from __future__ import annotations

import logging
import time
from typing import Dict, Optional

from models import DetectionEvent

logger = logging.getLogger(__name__)


class ArpSpoofDetector:
    """
    ARPTable-based spoofing detector.

    Data structure:
        _arp_table: Dict[ip_str, mac_str]  — learned from legitimate ARP replies.
    """

    def __init__(self):
        self._arp_table: Dict[str, str] = {}
        self._alerted: Dict[str, float] = {}   # claimed_ip → last alert time

    def process(self, pkt) -> Optional[DetectionEvent]:
        """
        Inspect a Scapy packet.
        Returns DetectionEvent if ARP spoofing is detected, else None.
        """
        try:
            from scapy.layers.l2 import ARP

            if not pkt.haslayer(ARP):
                return None

            arp = pkt[ARP]
            # op=2 is "is-at" (ARP reply) — the only packet that maps IP→MAC
            if arp.op != 2:
                return None

            src_ip  = arp.psrc
            src_mac = arp.hwsrc.lower()
            now = time.time()   # use wall-clock for ARP (no IP layer timestamp)

            if not src_ip or not src_mac:
                return None

            known_mac = self._arp_table.get(src_ip)

            if known_mac is None:
                # First sighting — learn and trust
                self._arp_table[src_ip] = src_mac
                return None

            if known_mac == src_mac:
                return None   # Consistent — no conflict

            # IP→MAC conflict detected
            if now - self._alerted.get(src_ip, 0) < 60:
                return None   # suppress flood of duplicate alerts

            self._alerted[src_ip] = now
            logger.warning(
                "ARP_SPOOF detected: ip=%s known_mac=%s spoofed_mac=%s",
                src_ip, known_mac, src_mac,
            )

            return DetectionEvent(
                timestamp=now,
                src_ip=src_ip,
                dst_ip=arp.pdst,
                threat_type="ARP_SPOOF",
                mitre_id="T1557",
                stage="Credential Access",
                severity="CRITICAL",
                details={
                    "claimed_ip": src_ip,
                    "known_mac":  known_mac,
                    "spoofed_mac": src_mac,
                },
            )
        except Exception:
            return None

    @property
    def arp_table(self) -> Dict[str, str]:
        """Read-only copy of the learned IP→MAC table."""
        return dict(self._arp_table)
