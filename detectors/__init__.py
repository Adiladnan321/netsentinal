"""
Detector sub-package for NetSentinel AI.
Exports all four MITRE-tagged detector classes.
"""
from .port_scan import PortScanDetector
from .syn_flood import SynFloodDetector
from .arp_spoof import ArpSpoofDetector
from .dns_tunnel import DnsTunnelDetector

__all__ = [
    "PortScanDetector",
    "SynFloodDetector",
    "ArpSpoofDetector",
    "DnsTunnelDetector",
]
