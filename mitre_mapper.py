"""
MITRE ATT&CK framework lookup table for NetSentinel AI.

Maps T-codes → tactic metadata and provides canonical kill-chain
phase ordering used by the ChainEngine's confidence scorer.
"""
from __future__ import annotations

from typing import Dict, Optional

# ---------------------------------------------------------------------------
# Kill-chain phase ordering  (lower integer = earlier in the attack)
# ---------------------------------------------------------------------------
_PHASE_ORDER: Dict[str, int] = {
    "Reconnaissance":         1,
    "Resource Development":   2,
    "Initial Access":         3,
    "Execution":              4,
    "Persistence":            5,
    "Privilege Escalation":   6,
    "Defense Evasion":        7,
    "Credential Access":      8,
    "Discovery":              9,
    "Lateral Movement":      10,
    "Collection":            11,
    "Command and Control":   12,
    "Exfiltration":          13,
    "Impact":                14,
}

# ---------------------------------------------------------------------------
# T-code database
# ---------------------------------------------------------------------------
_MITRE_DB: Dict[str, Dict] = {
    "T1046": {
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "phase": "Reconnaissance",
        "description": (
            "Adversaries scan victim systems to discover services, open ports, "
            "and running software to identify targets for exploitation."
        ),
        "url": "https://attack.mitre.org/techniques/T1046/",
    },
    "T1499": {
        "name": "Endpoint Denial of Service",
        "tactic": "Impact",
        "phase": "Impact",
        "description": (
            "Adversaries perform DoS attacks to degrade or block availability "
            "of targeted resources by exhausting system resources."
        ),
        "url": "https://attack.mitre.org/techniques/T1499/",
    },
    "T1557": {
        "name": "Adversary-in-the-Middle",
        "tactic": "Credential Access / Collection",
        "phase": "Credential Access",
        "description": (
            "Adversaries position themselves between two network devices to "
            "intercept and potentially manipulate communications."
        ),
        "url": "https://attack.mitre.org/techniques/T1557/",
    },
    "T1048": {
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "phase": "Exfiltration",
        "description": (
            "Adversaries steal data by encoding it in DNS queries or other "
            "allowed protocols to bypass data-loss prevention controls."
        ),
        "url": "https://attack.mitre.org/techniques/T1048/",
    },
    "T1595": {
        "name": "Active Scanning",
        "tactic": "Reconnaissance",
        "phase": "Reconnaissance",
        "description": "Adversaries actively scan victim infrastructure to gather information.",
        "url": "https://attack.mitre.org/techniques/T1595/",
    },
    "T1498": {
        "name": "Network Denial of Service",
        "tactic": "Impact",
        "phase": "Impact",
        "description": (
            "Adversaries perform network-level DoS attacks to degrade or block "
            "the availability of targeted resources."
        ),
        "url": "https://attack.mitre.org/techniques/T1498/",
    },
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def lookup(mitre_id: str) -> Optional[Dict]:
    """Return metadata dict for a MITRE T-code, or None if not found."""
    return _MITRE_DB.get(mitre_id)


def get_phase_order(stage: str) -> int:
    """
    Return the integer kill-chain order for a stage name.
    Lower = earlier in the attack sequence. Unknown stages get order 99.
    """
    return _PHASE_ORDER.get(stage, 99)


def get_all_phases() -> Dict[str, int]:
    """Return a copy of the full phase-order mapping."""
    return dict(_PHASE_ORDER)
