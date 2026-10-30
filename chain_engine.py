"""
Attack Chain Correlation Engine — NetSentinel AI

THE CORE ARCHITECTURAL DIFFERENTIATOR.

Legacy IDS tools (Snort, Suricata) emit one alert per rule match — isolated
noise. The ChainEngine instead asks: "Are multiple detections from the same
source IP escalating through the MITRE kill chain?"

When ≥ 2 distinct kill-chain stages are observed from a single src_ip within
a configurable time window, the engine fires a correlated AttackChain object —
transforming alert fatigue into a single, high-confidence campaign detection.

This mirrors the causality chain analysis philosophy of Cortex XDR.

Confidence scoring formula:
    base     = (distinct_stages / TOTAL_POSSIBLE_STAGES) × 100
    order_bonus  = +10 if stages appear in canonical kill-chain order
    anomaly_bonus = abs(avg_anomaly_score) × 20  (maps [-1,0] → [0,20])
    confidence = min(100, base + order_bonus + anomaly_bonus)
"""
from __future__ import annotations

import logging
import time
from collections import defaultdict
from typing import Dict, List, Optional

import mitre_mapper
from models import AttackChain, DetectionEvent

logger = logging.getLogger(__name__)

DEFAULT_CHAIN_WINDOW  = 300.0   # 5 minutes: events within this window are correlated
MIN_STAGES_FOR_CHAIN  = 2       # minimum distinct kill-chain stages to fire a chain
TOTAL_POSSIBLE_STAGES = 5       # number of detectors in the engine (denominator for base score)
CHAIN_REFIRE_COOLDOWN = 60.0    # suppress re-firing a chain for the same IP within 60 s


class ChainEngine:
    """
    Correlates individual DetectionEvents into multi-stage AttackChain objects.

    Public API:
        engine.ingest(event)       → Optional[AttackChain]
        engine.get_chains()        → List[AttackChain]   (all confirmed, newest first)
        engine.get_active_chains() → List[AttackChain]   (within last N seconds)
    """

    def __init__(self, chain_window: float = DEFAULT_CHAIN_WINDOW):
        self.chain_window = chain_window
        # src_ip → list of DetectionEvents within the window
        self._events: Dict[str, List[DetectionEvent]] = defaultdict(list)
        # src_ip → timestamp of the last chain fired for that IP
        self._last_fire: Dict[str, float] = {}
        # All confirmed chains (append-only)
        self._chains: List[AttackChain] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def ingest(self, event: DetectionEvent) -> Optional[AttackChain]:
        """
        Ingest a DetectionEvent.

        Returns an AttackChain if one is confirmed by this event, else None.
        The returned chain is also stored internally (accessible via get_chains()).
        """
        src_ip = event.src_ip
        now    = event.timestamp

        self._events[src_ip].append(event)
        self._evict(src_ip, now)

        return self._evaluate(src_ip, now)

    def get_chains(self) -> List[AttackChain]:
        """All confirmed attack chains, most recent first."""
        return sorted(self._chains, key=lambda c: c.end_time, reverse=True)

    def get_active_chains(self, max_age: float = 600.0) -> List[AttackChain]:
        """Chains detected within the last `max_age` seconds."""
        cutoff = time.time() - max_age
        return [c for c in self._chains if c.end_time >= cutoff]

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _evict(self, src_ip: str, now: float) -> None:
        """Drop events older than chain_window for this src_ip."""
        cutoff = now - self.chain_window
        self._events[src_ip] = [
            e for e in self._events[src_ip] if e.timestamp >= cutoff
        ]

    def _evaluate(self, src_ip: str, now: float) -> Optional[AttackChain]:
        """Determine whether a chain should be fired for this src_ip."""
        events = self._events[src_ip]
        if not events:
            return None

        # Collect one representative event per distinct stage (first occurrence)
        stage_rep: Dict[str, DetectionEvent] = {}
        for evt in events:
            if evt.stage not in stage_rep:
                stage_rep[evt.stage] = evt

        if len(stage_rep) < MIN_STAGES_FOR_CHAIN:
            return None

        # Enforce re-fire cooldown
        if now - self._last_fire.get(src_ip, 0) < CHAIN_REFIRE_COOLDOWN:
            return None

        # Sort stages by canonical kill-chain phase order
        ordered_stages = sorted(
            stage_rep.keys(),
            key=lambda s: mitre_mapper.get_phase_order(s),
        )
        ordered_events = [stage_rep[s] for s in ordered_stages]
        mitre_tags     = [e.mitre_id for e in ordered_events]

        # ----- Confidence scoring -----
        n_stages = len(ordered_stages)

        # Base: fraction of possible stages detected
        base_score = (n_stages / TOTAL_POSSIBLE_STAGES) * 100.0

        # Order bonus: +10 if stages appear in canonical kill-chain order
        phase_orders = [mitre_mapper.get_phase_order(s) for s in ordered_stages]
        in_order = all(
            phase_orders[i] <= phase_orders[i + 1]
            for i in range(len(phase_orders) - 1)
        )
        order_bonus = 10.0 if in_order else 0.0

        # Anomaly bonus: average |anomaly_score| across chain events, scaled to [0, 20]
        # anomaly_score ∈ [-1, 0], so abs maps it to [0, 1] → ×20 → [0, 20]
        avg_anomaly   = sum(abs(e.anomaly_score) for e in ordered_events) / n_stages
        anomaly_bonus = avg_anomaly * 20.0

        confidence = round(min(100.0, base_score + order_bonus + anomaly_bonus), 1)

        # Severity: CRITICAL if ≥3 stages or confidence ≥70
        severity = "CRITICAL" if (n_stages >= 3 or confidence >= 70) else "WARNING"

        chain = AttackChain(
            src_ip=src_ip,
            events=ordered_events,
            stages=ordered_stages,
            mitre_tags=mitre_tags,
            confidence=confidence,
            severity=severity,
            start_time=events[0].timestamp,
            end_time=now,
        )

        self._chains.append(chain)
        self._last_fire[src_ip] = now

        logger.warning(
            "[CHAIN] ATTACK CHAIN | src=%-17s | stages=%s | confidence=%.1f%% | severity=%s",
            src_ip,
            " → ".join(ordered_stages),
            confidence,
            severity,
        )
        return chain
