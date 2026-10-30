"""
AI-powered threat brief generator for NetSentinel AI.

Sends confirmed AttackChain data to the Google Gemini API and receives a
3-sentence analyst-ready narrative — mirroring PANW's "Precision AI"
narrative generation in their SOC platform.

Falls back gracefully to a template-based brief when:
  - The google-generativeai package is not installed
  - No GEMINI_API_KEY environment variable is set
  - The API call fails (rate limit, network error, etc.)
  - The --no-ai flag is passed

In all fallback cases the system continues to function fully.
"""
from __future__ import annotations

import logging
import os
from typing import Optional

from models import AttackChain

logger = logging.getLogger(__name__)

# Try importing the new Gemini SDK first, fall back to legacy SDK
_SDK_AVAILABLE = False
_SDK_VERSION = None   # "new" or "legacy"
_genai = None

try:
    import google.genai as genai_new
    _SDK_AVAILABLE = True
    _SDK_VERSION = "new"
    _genai = genai_new
except ImportError:
    try:
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", FutureWarning)
            import google.generativeai as genai_legacy
        _SDK_AVAILABLE = True
        _SDK_VERSION = "legacy"
        _genai = genai_legacy
    except ImportError:
        logger.debug(
            "Neither google.genai nor google.generativeai is installed. "
            "AI briefs will use template fallback. "
            "Install with: pip install google-genai"
        )


# ---------------------------------------------------------------------------
# Prompt builder
# ---------------------------------------------------------------------------

def _build_prompt(chain: AttackChain) -> str:
    stage_list = "\n".join(
        f"  Stage {i + 1}: {stage}  [{mitre}]"
        for i, (stage, mitre) in enumerate(zip(chain.stages, chain.mitre_tags))
    )
    event_lines = "\n".join(
        f"  [{e.time_str}] {e.threat_type} — {e.details}"
        for e in chain.events
    )
    return f"""You are a senior SOC analyst reviewing a network threat intelligence report.
A behavioral attack chain sensor detected the following correlated events:

  Source IP:  {chain.src_ip}
  Severity:   {chain.severity}
  Confidence: {chain.confidence:.1f}%
  Duration:   {chain.duration_str}

MITRE ATT&CK Stages Detected:
{stage_list}

Raw Event Timeline:
{event_lines}

Write a concise 3-sentence threat brief covering:
1. What likely happened (describe the attack pattern in plain English)
2. What the attacker's probable goal was
3. Recommended immediate defensive action

Rules: Under 100 words. No bullet points. Be specific about the techniques observed.
Do not include headings or labels like "Sentence 1:"."""


# ---------------------------------------------------------------------------
# Template fallback
# ---------------------------------------------------------------------------

_STAGE_DESCRIPTIONS = {
    "Reconnaissance":   "conducted systematic network reconnaissance including port scanning",
    "Discovery":        "performed active network service discovery",
    "Impact":           "launched a denial-of-service attack against network resources",
    "Credential Access":"attempted adversary-in-the-middle interception via ARP spoofing",
    "Exfiltration":     "exfiltrated data covertly using DNS tunneling",
    "Command and Control": "established covert C2 communication channels",
    "Lateral Movement": "attempted lateral movement across the internal network",
}

_STAGE_GOALS = {
    "Exfiltration":     "covertly extract sensitive data from the network",
    "Impact":           "disrupt service availability and exhaust server resources",
    "Credential Access":"intercept and steal credentials or session tokens",
    "Reconnaissance":   "map exposed services for subsequent exploitation",
}

_STAGE_ACTIONS = {
    "Exfiltration":     "isolate the host immediately and audit all DNS logs for the past 24 hours",
    "Impact":           "block traffic from the source IP at the perimeter firewall and rate-limit ICMP/SYN",
    "Credential Access":"enable Dynamic ARP Inspection (DAI) on all switches and inspect the ARP table network-wide",
    "Reconnaissance":   "block the source IP at the firewall and review exposed service configurations",
}


def _fallback_brief(chain: AttackChain) -> str:
    """Generate a structured threat brief without the Gemini API."""
    actions = [
        _STAGE_DESCRIPTIONS.get(s, f"performed {s.lower()} activity")
        for s in chain.stages
    ]
    action_str = ", then ".join(actions)

    # Use the most impactful stage for goal and recommendation
    goal = "gain persistent access and reconnaissance for a future attack"
    rec  = "isolate the host and escalate to your incident response team"
    for stage in reversed(chain.stages):
        if stage in _STAGE_GOALS:
            goal = _STAGE_GOALS[stage]
            break
    for stage in reversed(chain.stages):
        if stage in _STAGE_ACTIONS:
            rec = _STAGE_ACTIONS[stage]
            break

    mitre_str = ", ".join(chain.mitre_tags)
    return (
        f"Host {chain.src_ip} {action_str}, consistent with a coordinated multi-stage intrusion "
        f"(MITRE: {mitre_str}; confidence {chain.confidence:.0f}%). "
        f"The attacker likely sought to {goal}. "
        f"Recommended action: {rec}."
    )


# ---------------------------------------------------------------------------
# ThreatBriefGenerator
# ---------------------------------------------------------------------------

class ThreatBriefGenerator:
    """
    Generates analyst-ready threat narratives for confirmed AttackChain objects.

    Priority:
      1. Gemini API (if SDK installed + GEMINI_API_KEY set + --no-ai not passed)
      2. Template fallback (always available)
    """

    def __init__(self, api_key: Optional[str] = None, enabled: bool = True):
        self.enabled   = enabled
        self._api_key  = api_key or os.environ.get("GEMINI_API_KEY")
        self._model    = None
        self._use_api  = False

        if not self.enabled:
            logger.info("AI brief generation disabled (--no-ai).")
            return

        if not _SDK_AVAILABLE:
            logger.info("Gemini SDK not installed — using template briefs.")
            return

        if not self._api_key:
            logger.info(
                "No GEMINI_API_KEY found — using template briefs. "
                "Set the environment variable or pass --gemini-key to enable AI briefs."
            )
            return

        try:
            if _SDK_VERSION == "new":
                # google.genai >= 1.0 — client-based API
                self._client = _genai.Client(api_key=self._api_key)
                self._use_api = True
                logger.info("[OK] Gemini AI brief generator ready (google.genai, model: gemini-1.5-flash).")
            else:
                # Legacy google.generativeai (suppressed FutureWarning above)
                _genai.configure(api_key=self._api_key)
                self._model = _genai.GenerativeModel("gemini-1.5-flash")
                self._use_api = True
                logger.info("[OK] Gemini AI brief generator ready (legacy SDK, model: gemini-1.5-flash).")
        except Exception as exc:
            logger.warning("Gemini setup failed (%s) — using template briefs.", exc)

    def generate(self, chain: AttackChain) -> str:
        """
        Generate a threat brief for the given AttackChain.
        Returns an empty string if generation is disabled.
        """
        if not self.enabled:
            return ""

        if self._use_api:
            try:
                prompt = _build_prompt(chain)
                if _SDK_VERSION == "new" and hasattr(self, "_client"):
                    response = self._client.models.generate_content(
                        model="gemini-1.5-flash",
                        contents=prompt,
                    )
                    brief = response.text.strip()
                elif self._model:
                    response = self._model.generate_content(prompt)
                    brief = response.text.strip()
                else:
                    brief = None

                if brief:
                    logger.info("[AI] Threat brief generated for src_ip=%s", chain.src_ip)
                    return brief
            except Exception as exc:
                logger.warning("Gemini API error (%s) — falling back to template.", exc)

        return _fallback_brief(chain)
