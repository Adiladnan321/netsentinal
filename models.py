"""
Shared data models for NetSentinel AI.
All modules import from here to avoid circular dependencies.
"""
from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from typing import Any, Dict, List


# ---------------------------------------------------------------------------
# FlowFeatures
# ---------------------------------------------------------------------------

@dataclass
class FlowFeatures:
    """Feature vector extracted from a per-source-IP network flow."""

    src_ip: str
    timestamp: float

    # --- ML feature dimensions ---
    pkt_rate: float = 0.0          # packets per second in the window
    byte_entropy: float = 0.0      # Shannon entropy of payload bytes (0–8 bits)
    unique_dst_ports: int = 0      # distinct destination ports contacted
    syn_ack_ratio: float = 1.0     # SYN count / max(SYN-ACK count, 1)
    avg_payload_len: float = 0.0   # mean bytes per packet
    icmp_ratio: float = 0.0        # fraction of packets that are ICMP

    # Filled by AnomalyEngine after model is trained
    anomaly_score: float = 0.0     # range [-1, 0]; more negative = more anomalous

    def to_vector(self) -> List[float]:
        """Return a flat numeric list suitable for sklearn."""
        return [
            self.pkt_rate,
            self.byte_entropy,
            float(self.unique_dst_ports),
            self.syn_ack_ratio,
            self.avg_payload_len,
            self.icmp_ratio,
        ]


# ---------------------------------------------------------------------------
# DetectionEvent
# ---------------------------------------------------------------------------

@dataclass
class DetectionEvent:
    """A single threat detection emitted by one of the rule-based detectors."""

    timestamp: float
    src_ip: str
    dst_ip: str
    threat_type: str     # "PORT_SCAN" | "SYN_FLOOD" | "ARP_SPOOF" | "DNS_TUNNEL" | "ICMP_FLOOD"
    mitre_id: str        # MITRE T-code, e.g. "T1046"
    stage: str           # Kill-chain stage: "Reconnaissance", "Impact", etc.
    severity: str        # "INFO" | "WARNING" | "CRITICAL"
    details: Dict[str, Any] = field(default_factory=dict)
    anomaly_score: float = 0.0   # from AnomalyEngine; attached after detection

    @property
    def time_str(self) -> str:
        return datetime.datetime.fromtimestamp(self.timestamp).strftime("%H:%M:%S")


# ---------------------------------------------------------------------------
# AttackChain
# ---------------------------------------------------------------------------

@dataclass
class AttackChain:
    """
    A correlated multi-stage attack campaign from a single source IP,
    produced by the ChainEngine when ≥2 distinct kill-chain stages are detected.
    """

    src_ip: str
    events: List[DetectionEvent]   # ordered by kill-chain phase
    stages: List[str]              # e.g. ["Reconnaissance", "Impact", "Exfiltration"]
    mitre_tags: List[str]          # corresponding T-codes, same order as stages
    confidence: float              # 0–100
    severity: str                  # "WARNING" | "CRITICAL"
    start_time: float
    end_time: float
    ai_brief: str = ""             # populated by ThreatBriefGenerator

    @property
    def duration_str(self) -> str:
        d = self.end_time - self.start_time
        return f"{d:.1f}s"

    @property
    def start_time_str(self) -> str:
        return datetime.datetime.fromtimestamp(self.start_time).strftime("%H:%M:%S")

    @property
    def end_time_str(self) -> str:
        return datetime.datetime.fromtimestamp(self.end_time).strftime("%H:%M:%S")
