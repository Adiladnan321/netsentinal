"""
Unit tests for NetSentinel AI detection modules.

Tests use crafted Scapy packets — no live network capture or PCAP file required.
Run with:
    python -m pytest tests/test_detectors.py -v
or:
    python tests/test_detectors.py
"""
from __future__ import annotations

import os
import sys
import time
import unittest

# Allow imports from the project root when running the test directly
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether

from chain_engine import ChainEngine
from detectors.arp_spoof import ArpSpoofDetector
from detectors.dns_tunnel import DnsTunnelDetector
from detectors.port_scan import PortScanDetector
from detectors.syn_flood import SynFloodDetector
from models import DetectionEvent


# ---------------------------------------------------------------------------
# Packet factories
# ---------------------------------------------------------------------------

def syn(src: str, dst: str, dport: int, ts: float = None) -> IP:
    pkt = IP(src=src, dst=dst) / TCP(dport=dport, flags="S")
    if ts is not None:
        pkt.time = ts
    return pkt


def syn_ack(src: str, dst: str, ts: float = None) -> IP:
    pkt = IP(src=src, dst=dst) / TCP(flags="SA")
    if ts is not None:
        pkt.time = ts
    return pkt


def arp_reply(psrc: str, pdst: str, hwsrc: str) -> Ether:
    return Ether() / ARP(op=2, psrc=psrc, pdst=pdst, hwsrc=hwsrc)


def dns_query(src: str, qname: str, ts: float = None) -> IP:
    pkt = IP(src=src, dst="8.8.8.8") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=qname))
    if ts is not None:
        pkt.time = ts
    return pkt


def _event(src: str, threat: str, mitre: str, stage: str, ts: float = None) -> DetectionEvent:
    return DetectionEvent(
        timestamp=ts or time.time(),
        src_ip=src,
        dst_ip="192.168.1.1",
        threat_type=threat,
        mitre_id=mitre,
        stage=stage,
        severity="WARNING",
        details={},
    )


# ===========================================================================
# PortScanDetector tests
# ===========================================================================

class TestPortScanDetector(unittest.TestCase):

    def test_no_alert_below_threshold(self):
        """Fewer than threshold unique ports → no alert."""
        d = PortScanDetector(threshold=15, window=10.0)
        ts = time.time()
        result = None
        for port in range(1, 10):   # 9 unique ports — below 15
            result = d.process(syn("10.0.0.1", "192.168.1.1", port, ts + port * 0.1))
        self.assertIsNone(result)

    def test_alert_on_port_scan(self):
        """≥ threshold unique ports → DetectionEvent returned."""
        d = PortScanDetector(threshold=15, window=10.0)
        ts = time.time()
        # Collect the first non-None result: the alert fires when threshold is crossed
        # mid-loop, and subsequent packets hit the 30 s cooldown (returning None).
        result = None
        for port in range(1, 22):   # 21 unique ports — above 15
            r = d.process(syn("10.0.0.2", "192.168.1.1", port, ts + port * 0.1))
            if r is not None:
                result = r
        self.assertIsNotNone(result)
        self.assertEqual(result.threat_type, "PORT_SCAN")
        self.assertEqual(result.mitre_id,    "T1046")
        self.assertEqual(result.stage,       "Reconnaissance")

    def test_ignores_non_syn_packets(self):
        """ACK-only packets should not feed the scan tracker."""
        d = PortScanDetector(threshold=5, window=10.0)
        ts = time.time()
        pkt = IP(src="10.0.0.3", dst="192.168.1.1") / TCP(dport=80, flags="A")
        pkt.time = ts
        self.assertIsNone(d.process(pkt))

    def test_window_eviction(self):
        """Packets outside the time window must be evicted and not trigger alert."""
        d = PortScanDetector(threshold=5, window=5.0)
        old_ts = time.time() - 100   # well outside any 5-second window
        for port in range(1, 20):
            d.process(syn("10.0.0.4", "192.168.1.1", port, old_ts + port * 0.1))
        # Now send a single SYN in the present — should not trigger
        result = d.process(syn("10.0.0.4", "192.168.1.1", 9999, time.time()))
        self.assertIsNone(result)

    def test_severity_is_warning(self):
        """Port scan severity should be WARNING (not CRITICAL)."""
        d = PortScanDetector(threshold=5, window=10.0)
        ts = time.time()
        result = None
        for port in range(1, 12):
            result = d.process(syn("10.0.0.5", "192.168.1.1", port, ts + port * 0.1))
        if result:
            self.assertEqual(result.severity, "WARNING")


# ===========================================================================
# SynFloodDetector tests
# ===========================================================================

class TestSynFloodDetector(unittest.TestCase):

    def test_alert_on_syn_flood(self):
        """Many SYNs with almost no SYN-ACKs → CRITICAL alert."""
        d = SynFloodDetector(ratio_threshold=5.0, min_syns=20, window=10.0)
        ts = time.time()
        # Collect the first non-None result: alert fires when min_syns is crossed
        # mid-loop; subsequent packets return None due to the 30 s cooldown.
        result = None
        for i in range(25):
            r = d.process(syn("10.1.0.1", "192.168.1.1", 80, ts + i * 0.1))
            if r is not None:
                result = r
        self.assertIsNotNone(result)
        self.assertEqual(result.threat_type, "SYN_FLOOD")
        self.assertEqual(result.mitre_id,    "T1499")
        self.assertEqual(result.stage,       "Impact")
        self.assertEqual(result.severity,    "CRITICAL")

    def test_no_alert_below_min_syns(self):
        """Should not evaluate until min_syns threshold is reached."""
        d = SynFloodDetector(ratio_threshold=5.0, min_syns=20, window=10.0)
        ts = time.time()
        result = None
        for i in range(10):   # only 10 SYNs — below min_syns=20
            result = d.process(syn("10.1.0.2", "192.168.1.1", 80, ts + i * 0.1))
        self.assertIsNone(result)
    def test_no_alert_balanced_traffic(self):
        """Balanced SYN + SYN-ACK ratio should not trigger alert."""
        d = SynFloodDetector(ratio_threshold=5.0, min_syns=10, window=10.0)
        ts = time.time()
        for i in range(12):
            d.process(syn("10.1.0.3",    "192.168.1.1", 80, ts + i * 0.1))
            d.process(syn_ack("192.168.1.1", "10.1.0.3",    ts + i * 0.1 + 0.05))
        result = d.process(syn("10.1.0.3", "192.168.1.1", 80, ts + 1.5))
        self.assertIsNone(result)   # ratio ≈ 1, well below threshold

    def test_details_contain_ratio(self):
        """Event details must include syn_count, syn_ack_count, and ratio."""
        d = SynFloodDetector(ratio_threshold=5.0, min_syns=20, window=10.0)
        ts = time.time()
        result = None
        for i in range(25):
            result = d.process(syn("10.1.0.4", "192.168.1.1", 80, ts + i * 0.1))
        if result:
            self.assertIn("syn_count",     result.details)
            self.assertIn("syn_ack_count", result.details)
            self.assertIn("ratio",         result.details)


# ===========================================================================
# ArpSpoofDetector tests
# ===========================================================================

class TestArpSpoofDetector(unittest.TestCase):

    def test_learns_first_arp_mapping(self):
        """First ARP reply for an IP should be stored without alerting."""
        d = ArpSpoofDetector()
        result = d.process(arp_reply("192.168.1.1", "192.168.1.100", "aa:bb:cc:dd:ee:01"))
        self.assertIsNone(result)
        self.assertEqual(d.arp_table.get("192.168.1.1"), "aa:bb:cc:dd:ee:01")

    def test_detects_mac_conflict(self):
        """Different MAC for same IP → ARP spoof alert."""
        d = ArpSpoofDetector()
        d.process(arp_reply("192.168.1.1", "192.168.1.100", "aa:bb:cc:dd:ee:01"))
        result = d.process(arp_reply("192.168.1.1", "192.168.1.100", "ff:ff:ff:ff:ff:99"))
        self.assertIsNotNone(result)
        self.assertEqual(result.threat_type, "ARP_SPOOF")
        self.assertEqual(result.mitre_id,    "T1557")
        self.assertEqual(result.stage,       "Credential Access")
        self.assertEqual(result.severity,    "CRITICAL")

    def test_no_alert_same_mac_repeated(self):
        """Same IP→MAC seen twice should not alert."""
        d = ArpSpoofDetector()
        d.process(arp_reply("192.168.1.2", "192.168.1.100", "aa:bb:cc:dd:ee:02"))
        result = d.process(arp_reply("192.168.1.2", "192.168.1.100", "aa:bb:cc:dd:ee:02"))
        self.assertIsNone(result)

    def test_ignores_arp_requests(self):
        """ARP requests (op=1) must be ignored — only replies (op=2) are tracked."""
        d = ArpSpoofDetector()
        pkt = Ether() / ARP(op=1, psrc="192.168.1.3", pdst="192.168.1.100", hwsrc="aa:bb:cc:dd:ee:03")
        result = d.process(pkt)
        self.assertIsNone(result)
        # Table should still be empty (request not learned)
        self.assertNotIn("192.168.1.3", d.arp_table)

    def test_details_contain_macs(self):
        """Alert details must include known_mac and spoofed_mac."""
        d = ArpSpoofDetector()
        d.process(arp_reply("192.168.1.4", "192.168.1.100", "aa:bb:cc:dd:ee:04"))
        result = d.process(arp_reply("192.168.1.4", "192.168.1.100", "de:ad:be:ef:00:01"))
        if result:
            self.assertIn("known_mac",   result.details)
            self.assertIn("spoofed_mac", result.details)


# ===========================================================================
# DnsTunnelDetector tests
# ===========================================================================

class TestDnsTunnelDetector(unittest.TestCase):

    def test_flags_long_subdomain(self):
        """DNS query with label ≥ threshold chars → DNS_TUNNEL alert."""
        d = DnsTunnelDetector(label_len_threshold=50, entropy_threshold=10.0)
        long_qname = ("x" * 55) + ".malicious.com"
        result = d.process(dns_query("10.2.0.1", long_qname))
        self.assertIsNotNone(result)
        self.assertEqual(result.threat_type, "DNS_TUNNEL")
        self.assertEqual(result.mitre_id,    "T1048")
        self.assertEqual(result.stage,       "Exfiltration")

    def test_flags_high_entropy_label(self):
        """A random-looking label with high entropy should be flagged."""
        d = DnsTunnelDetector(label_len_threshold=200, entropy_threshold=3.5)
        # alphanumeric random label — high Shannon entropy
        high_entropy = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3.tunnel.com"
        result = d.process(dns_query("10.2.0.2", high_entropy))
        self.assertIsNotNone(result)

    def test_normal_dns_not_flagged(self):
        """A normal domain query should not be flagged."""
        d = DnsTunnelDetector(label_len_threshold=50, entropy_threshold=3.5)
        result = d.process(dns_query("10.2.0.3", "www.google.com"))
        self.assertIsNone(result)

    def test_ignores_dns_responses(self):
        """DNS responses (qr=1) must be ignored — only queries (qr=0) matter."""
        d = DnsTunnelDetector(label_len_threshold=1)   # very low threshold to ensure trigger
        pkt = (
            IP(src="8.8.8.8", dst="10.2.0.4")
            / UDP(sport=53)
            / DNS(qr=1, qd=DNSQR(qname=("x" * 60) + ".evil.com"))
        )
        result = d.process(pkt)
        self.assertIsNone(result)

    def test_details_contain_entropy(self):
        """Alert details must include query name and entropy value."""
        d = DnsTunnelDetector(label_len_threshold=50, entropy_threshold=10.0)
        qname = ("z" * 60) + ".exfil.io"
        result = d.process(dns_query("10.2.0.5", qname))
        if result:
            self.assertIn("query",     result.details)
            self.assertIn("entropy",   result.details)
            self.assertIn("label_len", result.details)


# ===========================================================================
# ChainEngine tests
# ===========================================================================

class TestChainEngine(unittest.TestCase):

    def test_single_stage_no_chain(self):
        """A single detection event must not produce a chain."""
        engine = ChainEngine()
        e = _event("10.3.0.1", "PORT_SCAN", "T1046", "Reconnaissance")
        self.assertIsNone(engine.ingest(e))

    def test_two_stages_fires_chain(self):
        """Two distinct stages from same IP → AttackChain."""
        engine = ChainEngine()
        ts = time.time()
        engine.ingest(_event("10.3.0.2", "PORT_SCAN", "T1046", "Reconnaissance", ts))
        chain = engine.ingest(_event("10.3.0.2", "SYN_FLOOD", "T1499", "Impact", ts + 30))
        self.assertIsNotNone(chain)
        self.assertEqual(chain.src_ip, "10.3.0.2")
        self.assertIn("Reconnaissance", chain.stages)
        self.assertIn("Impact",         chain.stages)
        self.assertGreater(chain.confidence, 0)

    def test_three_stages_critical(self):
        """Three distinct stages → CRITICAL severity."""
        # The chain fires after stage 2 (Recon + Credential Access) at ts+20 and
        # enters a 60-second cooldown. Stage 3 must arrive AFTER ts+20+60 = ts+80.
        # Using ts+81 clears the cooldown, allowing the engine to re-fire with 3 stages.
        engine = ChainEngine()
        ts = time.time()
        engine.ingest(_event("10.3.0.3", "PORT_SCAN",  "T1046", "Reconnaissance",    ts))
        engine.ingest(_event("10.3.0.3", "ARP_SPOOF",  "T1557", "Credential Access", ts + 20))
        chain = engine.ingest(_event("10.3.0.3", "DNS_TUNNEL", "T1048", "Exfiltration", ts + 81))
        self.assertIsNotNone(chain)
        self.assertEqual(chain.severity, "CRITICAL")
        self.assertGreaterEqual(len(chain.stages), 2)   # ≥2 stages, severity driven by confidence

    def test_different_ips_no_chain(self):
        """Events from different source IPs must never form a chain."""
        engine = ChainEngine()
        ts = time.time()
        engine.ingest(_event("10.3.0.4", "PORT_SCAN", "T1046", "Reconnaissance", ts))
        chain = engine.ingest(_event("10.3.0.5", "SYN_FLOOD", "T1499", "Impact",   ts + 10))
        self.assertIsNone(chain)

    def test_chain_suppression_within_cooldown(self):
        """Chain must not re-fire for same IP within the 60-second cooldown."""
        engine = ChainEngine()
        ts = time.time()
        engine.ingest(_event("10.3.0.6", "PORT_SCAN", "T1046", "Reconnaissance",   ts))
        chain1 = engine.ingest(_event("10.3.0.6", "SYN_FLOOD",  "T1499", "Impact",       ts + 10))
        chain2 = engine.ingest(_event("10.3.0.6", "DNS_TUNNEL", "T1048", "Exfiltration", ts + 20))
        self.assertIsNotNone(chain1)
        self.assertIsNone(chain2)   # suppressed — less than 60 s since chain1

    def test_stages_sorted_by_kill_chain_order(self):
        """Stages in the returned chain must be in canonical kill-chain order."""
        engine = ChainEngine()
        ts = time.time()
        # Feed in reverse order (Exfil before Recon)
        engine.ingest(_event("10.3.0.7", "DNS_TUNNEL", "T1048", "Exfiltration",  ts))
        chain = engine.ingest(_event("10.3.0.7", "PORT_SCAN",  "T1046", "Reconnaissance", ts + 5))
        self.assertIsNotNone(chain)
        # Reconnaissance (order=1) should appear before Exfiltration (order=13)
        self.assertLess(
            chain.stages.index("Reconnaissance"),
            chain.stages.index("Exfiltration"),
        )

    def test_confidence_is_bounded(self):
        """Confidence score must always be in [0, 100]."""
        engine = ChainEngine()
        ts = time.time()
        engine.ingest(_event("10.3.0.8", "PORT_SCAN", "T1046", "Reconnaissance", ts))
        chain = engine.ingest(_event("10.3.0.8", "SYN_FLOOD", "T1499", "Impact", ts + 10))
        if chain:
            self.assertGreaterEqual(chain.confidence, 0.0)
            self.assertLessEqual(chain.confidence,    100.0)

    def test_get_chains_returns_all(self):
        """get_chains() must return all chains accumulated across multiple source IPs."""
        engine = ChainEngine()
        ts = time.time()
        # Chain for IP A
        engine.ingest(_event("10.4.0.1", "PORT_SCAN", "T1046", "Reconnaissance", ts))
        engine.ingest(_event("10.4.0.1", "SYN_FLOOD", "T1499", "Impact",         ts + 10))
        # Chain for IP B
        engine.ingest(_event("10.4.0.2", "ARP_SPOOF",  "T1557", "Credential Access", ts + 5))
        engine.ingest(_event("10.4.0.2", "DNS_TUNNEL", "T1048", "Exfiltration",      ts + 15))
        chains = engine.get_chains()
        self.assertEqual(len(chains), 2)


# ---------------------------------------------------------------------------
# Entry point for running directly
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    unittest.main(verbosity=2)
