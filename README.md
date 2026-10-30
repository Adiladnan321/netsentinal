# 🛡️ NetSentinel AI — Behavioral Attack Chain Analyzer

> **Real-time network intrusion detection that thinks like Cortex XDR.**  
> Instead of alerting on isolated packets, NetSentinel correlates anomalies across time, maps them to the MITRE ATT&CK kill chain, scores them with ML, and generates AI-powered threat briefs.

---

## What makes this different from Snort/Suricata

| Traditional IDS | NetSentinel AI |
|---|---|
| Rule fires → one alert per event | Correlates events into **attack campaigns** |
| Hardcoded thresholds | **Isolation Forest** learns your network's baseline |
| Raw alert output | **MITRE ATT&CK** stage mapping + kill-chain sequencing |
| No narrative | **Gemini AI** generates 3-sentence SOC analyst brief |

This is the same architectural leap Cortex XDR made over legacy IDS tools: *causality chain analysis over isolated alert generation*.

---

## Architecture

```
PCAP / Live Interface
        │
        ▼
   capture.py          ←── Scapy sniff / rdpcap wrapper
        │
        ▼
feature_extractor.py   ←── Per-flow feature vectors (10-second sliding window)
        │
        ├──▶ anomaly_engine.py   ←── Isolation Forest (sklearn) — no hardcoded thresholds
        │
        ├──▶ detectors/
        │       ├── port_scan.py    [T1046 Reconnaissance]
        │       ├── syn_flood.py    [T1499 Impact]
        │       ├── arp_spoof.py    [T1557 Credential Access]
        │       └── dns_tunnel.py   [T1048 Exfiltration]
        │
        ▼
  chain_engine.py      ←── ★ THE NOVEL PIECE: correlates events into campaigns
        │
        ├──▶ mitre_mapper.py    ←── T-code lookup + kill-chain phase ordering
        ├──▶ ai_brief.py        ←── Gemini API → threat narrative (w/ fallback)
        └──▶ alerts.py          ←── Dedup + structured JSON logging
                │
                ▼
         dashboard.py          ←── Rich live TUI (4 panels, 2 Hz refresh)
```

---

## Installation

```bash
# Clone and enter the project
cd netsentinel

# Create a virtual environment (recommended)
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # Linux / macOS

# Install dependencies
pip install -r requirements.txt

# Windows users: Npcap is required for live capture
# Download from https://npcap.com — not needed for --pcap mode
```

---

## Quick Start

### Analyse a PCAP file (no admin rights needed)

```bash
python main.py --pcap sample.pcap
```

### Grab a real attack PCAP for demo

Download Emotet or port-scan samples from [malware-traffic-analysis.net](https://malware-traffic-analysis.net) — their multi-stage traffic naturally triggers the chain engine.

```bash
python main.py --pcap 2023-emotet-infection.pcap --warmup 30
```

### Live capture (requires Administrator / sudo + Npcap on Windows)

```bash
python main.py --interface "Wi-Fi"
```

### Disable AI briefs (works without a Gemini key)

```bash
python main.py --pcap attack.pcap --no-ai
```

### Enable AI threat briefs

```bash
# Option A: environment variable
set GEMINI_API_KEY=your_key_here        # Windows
export GEMINI_API_KEY=your_key_here     # Linux / macOS
python main.py --pcap attack.pcap

# Option B: CLI flag
python main.py --pcap attack.pcap --gemini-key your_key_here
```

---

## CLI Reference

```
usage: netsentinel [-h] (--interface IFACE | --pcap FILE)
                   [--threshold N] [--window SECS] [--warmup SECS]
                   [--chain-window SECS] [--log-file PATH]
                   [--no-ai] [--gemini-key KEY] [-v]

Options:
  --pcap FILE          Path to .pcap file (PCAP-first, no admin needed)
  --interface IFACE    Live capture interface (requires admin + Npcap)
  --threshold N        Port scan unique-port threshold (default: 15)
  --window SECS        Detection sliding-window width (default: 10)
  --warmup SECS        ML warm-up period in packet-time seconds (default: 60)
  --chain-window SECS  Attack chain correlation window (default: 300)
  --log-file PATH      Alert log file (default: netsentinel.log)
  --no-ai              Disable AI threat brief generation
  --gemini-key KEY     Gemini API key (or set GEMINI_API_KEY env var)
  -v, --verbose        Enable DEBUG logging
```

---

## Detection Engine

### 1. Port Scan — `T1046 Network Service Discovery`
Tracks SYN packets per source IP in a sliding window using `defaultdict(deque)`. Fires when a single IP contacts more than `--threshold` unique destination ports within `--window` seconds.

### 2. SYN Flood — `T1499 Endpoint Denial of Service`
Monitors SYN / SYN-ACK ratio per source IP. A ratio ≥ 5 with ≥ 20 SYNs signals half-open connection flooding.

### 3. ARP Spoofing — `T1557 Adversary-in-the-Middle`
Maintains an IP→MAC table from ARP replies. An IP claiming a different MAC than previously learned fires an alert.

### 4. DNS Tunneling — `T1048 Exfiltration Over Alternative Protocol`
Flags DNS queries where the longest label exceeds 50 characters **or** the Shannon entropy of that label exceeds 3.5 bits — both hallmarks of iodine/dnscat2-style tunneling.

### 5. ML Anomaly Scoring (Isolation Forest)
All four detectors also receive a continuous anomaly score from the ML engine:
- **Warm-up phase** (first `--warmup` seconds): collects baseline flow feature vectors.
- **Active phase**: scores each flow vector on `[-1, 0]`. Closer to `-1` = more anomalous.
- Anomaly scores feed the chain engine's confidence calculation.

---

## Attack Chain Correlation Engine

The `chain_engine.py` is the architectural centrepiece. When ≥ 2 distinct MITRE kill-chain stages are observed from the same source IP within `--chain-window` seconds, it fires an `AttackChain`:

```
[10:42:01] 192.168.1.55 → PORT_SCAN          Reconnaissance  (T1046)
[10:42:18] 192.168.1.55 → SYN_FLOOD          Impact          (T1499)
[10:43:02] 192.168.1.55 → DNS_TUNNEL         Exfiltration    (T1048)
                                ↓
            ┌─────────────────────────────────────────────────┐
            │  🔗 ATTACK CHAIN DETECTED                       │
            │  src_ip:     192.168.1.55                       │
            │  stages:     Recon → Impact → Exfiltration      │
            │  mitre:      T1046 · T1499 · T1048              │
            │  confidence: 87.3%                              │
            │  severity:   CRITICAL                           │
            └─────────────────────────────────────────────────┘
```

**Confidence formula:**

```
base        = (distinct_stages / 5) × 100
order_bonus = +10 if stages appear in canonical kill-chain order
anomaly_bonus = |avg_anomaly_score| × 20
confidence  = min(100, base + order_bonus + anomaly_bonus)
```

---

## AI Threat Brief (Gemini)

When a chain is confirmed, `ai_brief.py` sends the full chain context to Gemini 1.5 Flash with a SOC analyst prompt. Example output:

> *Host 192.168.1.55 conducted systematic port reconnaissance across 21 ports, followed by a SYN flood against port 80, and subsequently exfiltrated data using DNS tunneling with 60-character encoded subdomains — consistent with a multi-stage APT playbook. The attacker's probable goal was to map exposed services, degrade availability as a distraction, and covertly extract sensitive data via an allowed protocol. Recommended action: isolate host 192.168.1.55 immediately and audit all DNS logs for the past 24 hours.*

If no API key is set, a deterministic template brief is used instead.

---

## Running Tests

```bash
# Run all unit tests (no live network or PCAP needed — uses crafted Scapy packets)
python -m pytest tests/test_detectors.py -v

# Or run directly
python tests/test_detectors.py
```

Tests cover:
- PortScanDetector: threshold, window eviction, non-SYN filtering
- SynFloodDetector: ratio calculation, min_syns guard, balanced traffic
- ArpSpoofDetector: MAC learning, conflict detection, request filtering
- DnsTunnelDetector: length heuristic, entropy heuristic, normal traffic
- ChainEngine: single stage, multi-stage, cross-IP isolation, cooldown suppression, stage ordering

---

## Project Structure

```
netsentinel/
├── main.py               # Entry point, CLI, orchestration
├── capture.py            # Scapy sniff wrapper (live + PCAP)
├── feature_extractor.py  # Per-flow feature vectors (sliding window)
├── anomaly_engine.py     # Isolation Forest ML scorer
├── chain_engine.py       # ★ Attack chain correlation engine
├── mitre_mapper.py       # MITRE T-code lookup + kill-chain ordering
├── ai_brief.py           # Gemini API threat brief (w/ fallback)
├── alerts.py             # AlertManager — dedup, log, severity
├── dashboard.py          # Rich live TUI dashboard
├── models.py             # Shared dataclasses (FlowFeatures, DetectionEvent, AttackChain)
├── detectors/
│   ├── __init__.py
│   ├── port_scan.py      # T1046 — sliding-window SYN tracker
│   ├── syn_flood.py      # T1499 — SYN/SYN-ACK ratio
│   ├── arp_spoof.py      # T1557 — IP→MAC conflict table
│   └── dns_tunnel.py     # T1048 — label length + entropy heuristics
├── tests/
│   └── test_detectors.py # Unit tests (crafted packets, no live capture)
├── requirements.txt
└── README.md
```

---

## Tech Stack

| Library | Purpose |
|---|---|
| `scapy` | Packet capture, dissection, and test packet crafting |
| `rich` | Live terminal dashboard (panels, tables, Live context) |
| `scikit-learn` | Isolation Forest anomaly detection |
| `numpy` | Feature vector operations |
| `google-generativeai` | Gemini AI threat brief generation |

---

## Resume Bullet

> Built **NetSentinel AI**, a real-time behavioral network intrusion detection system in Python using Scapy — implementing a causality chain engine that correlates anomalies across time into MITRE ATT&CK-mapped campaign detections, scored by an Isolation Forest ML model and narrated by a Gemini AI threat brief generator, with a Rich terminal dashboard.

---

## Interview Talking Point

*"Most IDS tools treat each alert in isolation. I built a causality chain engine that correlates behavioral anomalies from multiple detectors across a 5-minute time window into campaign-level detections, maps them to MITRE ATT&CK, weights them with an Isolation Forest anomaly score, and uses an LLM to generate analyst-ready threat briefs — the same architectural loop Cortex XDR uses to reduce SOC alert fatigue."*
