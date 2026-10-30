"""
Alert management system for NetSentinel AI.

Responsibilities:
  - Deduplication: suppress repeat alerts from the same (src_ip, threat_type)
    within a configurable cooldown window.
  - Severity classification: INFO / WARNING / CRITICAL with color and icon mappings.
  - Structured logging: appends JSON-line records to a log file for post-analysis.
  - In-memory ring buffers: recent events and chains for the live dashboard.
"""
from __future__ import annotations

import json
import logging
from collections import deque
from pathlib import Path
from typing import Deque, Dict, List, Optional, Tuple

from models import AttackChain, DetectionEvent

logger = logging.getLogger(__name__)

# Suppress duplicate alerts for the same (src_ip, threat_type) within this window
DEDUP_WINDOW_SECONDS = 60.0

# Rich rendering helpers — imported by dashboard.py
SEVERITY_COLORS: Dict[str, str] = {
    "INFO":     "green",
    "WARNING":  "yellow",
    "CRITICAL": "red",
}

SEVERITY_ICONS: Dict[str, str] = {
    "INFO":     "🟢",
    "WARNING":  "🟡",
    "CRITICAL": "🔴",
}


class AlertManager:
    """
    Central alert hub for NetSentinel AI.

    Usage:
        manager = AlertManager(log_file="netsentinel.log")
        fired = manager.fire(detection_event)    # returns True if not suppressed
        manager.fire_chain(attack_chain)
    """

    def __init__(
        self,
        log_file: Optional[str] = "netsentinel.log",
        max_recent_events: int = 100,
        max_recent_chains: int = 20,
        dedup_window: float = DEDUP_WINDOW_SECONDS,
    ):
        self._log_path = Path(log_file) if log_file else None
        self._recent_events: Deque[DetectionEvent] = deque(maxlen=max_recent_events)
        self._recent_chains: Deque[AttackChain]    = deque(maxlen=max_recent_chains)
        # (src_ip, threat_type) → last-fired timestamp
        self._dedup: Dict[Tuple[str, str], float] = {}
        self._dedup_window = dedup_window
        self._total_alerts = 0
        self._chain_count  = 0

        if self._log_path:
            self._log_path.parent.mkdir(parents=True, exist_ok=True)
            logger.info("Alert log → %s", self._log_path)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def fire(self, event: DetectionEvent) -> bool:
        """
        Register a DetectionEvent.

        Returns True if the alert was accepted and logged.
        Returns False if it was suppressed by the deduplication window.
        """
        key = (event.src_ip, event.threat_type)
        now = event.timestamp
        last = self._dedup.get(key, 0.0)

        if now - last < self._dedup_window:
            return False   # deduplicated — same source + type seen recently

        self._dedup[key] = now
        self._recent_events.append(event)
        self._total_alerts += 1
        self._write_event(event)

        logger.info(
            "[%s] %s | src=%-17s | mitre=%s | stage=%s",
            event.severity,
            event.threat_type,
            event.src_ip,
            event.mitre_id,
            event.stage,
        )
        return True

    def fire_chain(self, chain: AttackChain) -> None:
        """Register a confirmed AttackChain and append it to the log."""
        self._recent_chains.append(chain)
        self._chain_count += 1
        self._write_chain(chain)

        logger.warning(
            "[CHAIN] CONFIRMED | src=%-17s | confidence=%.1f%% | severity=%s | stages=%s",
            chain.src_ip,
            chain.confidence,
            chain.severity,
            " → ".join(chain.stages),
        )

    # ------------------------------------------------------------------
    # Read-only properties used by the dashboard
    # ------------------------------------------------------------------

    @property
    def recent_events(self) -> List[DetectionEvent]:
        return list(self._recent_events)

    @property
    def recent_chains(self) -> List[AttackChain]:
        return list(self._recent_chains)

    @property
    def total_alerts(self) -> int:
        return self._total_alerts

    @property
    def chain_count(self) -> int:
        return self._chain_count

    # ------------------------------------------------------------------
    # Structured JSON logging
    # ------------------------------------------------------------------

    def _write_event(self, event: DetectionEvent) -> None:
        if not self._log_path:
            return
        record = {
            "type":          "DETECTION_EVENT",
            "time":          event.time_str,
            "timestamp":     event.timestamp,
            "src_ip":        event.src_ip,
            "dst_ip":        event.dst_ip,
            "threat_type":   event.threat_type,
            "mitre_id":      event.mitre_id,
            "stage":         event.stage,
            "severity":      event.severity,
            "anomaly_score": event.anomaly_score,
            "details":       event.details,
        }
        self._append(record)

    def _write_chain(self, chain: AttackChain) -> None:
        if not self._log_path:
            return
        record = {
            "type":             "ATTACK_CHAIN",
            "src_ip":           chain.src_ip,
            "stages":           chain.stages,
            "mitre_tags":       chain.mitre_tags,
            "confidence":       chain.confidence,
            "severity":         chain.severity,
            "duration_seconds": round(chain.end_time - chain.start_time, 2),
            "start_time":       chain.start_time_str,
            "end_time":         chain.end_time_str,
            "ai_brief":         chain.ai_brief,
        }
        self._append(record)

    def _append(self, record: dict) -> None:
        try:
            with open(self._log_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record) + "\n")
        except OSError as exc:
            logger.error("Failed to write alert log: %s", exc)
