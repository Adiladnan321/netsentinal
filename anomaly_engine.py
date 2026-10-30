"""
ML-based anomaly scoring engine for NetSentinel AI.

Uses scikit-learn's Isolation Forest — an unsupervised algorithm that learns
what "normal" traffic looks like during a warm-up phase, then scores each
incoming flow vector on a continuous scale of [-1, 0].

This replaces hardcoded thresholds with behavioral baselines, mirroring the
approach used in Cortex XDR's behavioral detection engine.
"""
from __future__ import annotations

import logging
import time
from typing import List, Optional

import numpy as np

from models import FlowFeatures

logger = logging.getLogger(__name__)


class AnomalyEngine:
    """
    Isolation Forest wrapper with a two-phase lifecycle:

      Phase 1 — Warm-up:  collect baseline flow feature vectors (no scoring).
      Phase 2 — Active:   score each incoming vector; more negative = more anomalous.

    The warm-up duration is measured in *packet timestamp* time (not wall-clock),
    so it works correctly with high-speed PCAP replay.
    """

    def __init__(self, warmup_seconds: float = 60.0, contamination: float = 0.05):
        """
        Args:
            warmup_seconds:  Duration (in packet time) to collect baseline data.
            contamination:   Expected fraction of anomalies in the baseline data.
                             Lower = model assumes traffic is mostly clean.
        """
        self.warmup_seconds = warmup_seconds
        self.contamination = contamination

        self._baseline: List[List[float]] = []
        self._model = None
        self._trained = False
        self._first_ts: Optional[float] = None
        self._in_warmup = True

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def feed(self, features: FlowFeatures) -> None:
        """
        Ingest a feature vector.

        - During warm-up: accumulates baseline samples.
        - After warm-up threshold is crossed: triggers model training.
        Call this before calling score().
        """
        if self._first_ts is None:
            self._first_ts = features.timestamp

        elapsed = features.timestamp - self._first_ts

        if elapsed < self.warmup_seconds:
            vec = features.to_vector()
            if any(v > 0 for v in vec):    # skip empty / all-zero vectors
                self._baseline.append(vec)
            return

        if self._in_warmup:
            self._in_warmup = False
            self._train()

    def score(self, features: FlowFeatures) -> float:
        """
        Score a feature vector.

        Returns:
            float in [-1, 0]. Closer to -1 = more anomalous.
            Returns 0.0 during warm-up (model not yet trained).
        """
        if not self._trained or self._model is None:
            return 0.0

        vec = np.array([features.to_vector()])
        try:
            raw = self._model.score_samples(vec)[0]
            # score_samples already returns negative values for anomalies;
            # clamp to [-1, 0] for a consistent API contract.
            return float(max(-1.0, min(0.0, raw)))
        except Exception as exc:
            logger.debug("Anomaly scoring error: %s", exc)
            return 0.0

    @property
    def is_trained(self) -> bool:
        return self._trained

    @property
    def in_warmup(self) -> bool:
        return self._in_warmup

    @property
    def warmup_progress(self) -> float:
        """Fraction of warm-up completed (0.0 → 1.0)."""
        if self._first_ts is None:
            return 0.0
        elapsed = time.time() - self._first_ts
        return min(1.0, elapsed / self.warmup_seconds)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _train(self) -> None:
        """Fit the Isolation Forest on collected baseline vectors."""
        n = len(self._baseline)
        if n < 10:
            logger.warning(
                "Only %d baseline samples collected (expected ≥10). "
                "Anomaly scoring may be unreliable — try a longer --warmup or a larger PCAP.",
                n,
            )

        try:
            from sklearn.ensemble import IsolationForest

            self._model = IsolationForest(
                n_estimators=100,
                contamination=self.contamination,
                random_state=42,
                n_jobs=-1,
            )
            X = np.array(self._baseline)
            self._model.fit(X)
            self._trained = True
            logger.info(
                "Isolation Forest trained on %d baseline flow vectors. Anomaly scoring active.",
                n,
            )
        except ImportError:
            logger.error(
                "scikit-learn is not installed — anomaly scoring disabled. "
                "Run: pip install scikit-learn"
            )
        except Exception as exc:
            logger.error("Model training failed: %s", exc)
