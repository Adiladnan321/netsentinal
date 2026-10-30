"""
NetSentinel AI — Real-time Behavioral Attack Chain Analyzer
Entry point and orchestration layer.

Wires together all components:
  CaptureEngine → FeatureExtractor → AnomalyEngine
                                   → PortScanDetector ┐
                                   → SynFloodDetector  │→ ChainEngine → ThreatBriefGenerator
                                   → ArpSpoofDetector  │             → AlertManager
                                   → DnsTunnelDetector ┘
                                                         → Dashboard

Usage:
  python main.py --pcap sample.pcap
  python main.py --pcap attack.pcap --no-ai --threshold 10
  python main.py --interface eth0 --warmup 120          (requires admin/root)
"""
from __future__ import annotations

import argparse
import logging
import sys
import time
from collections import defaultdict

# ---------------------------------------------------------------------------
# Logging — console handler writes to stderr so it doesn't pollute the TUI
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)-8s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler("netsentinel_debug.log", encoding="utf-8"),
        logging.StreamHandler(sys.stderr),
    ],
)
logger = logging.getLogger("netsentinel.main")

# Pre-import Scapy layers to ensure namespace consistency (prevents haslayer() bugs)
try:
    from scapy.layers.l2 import Ether, ARP
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.dns import DNS, DNSQR
except ImportError:
    pass

# Ensure stdout can handle Unicode (emoji, arrows) on Windows terminals
try:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# ---------------------------------------------------------------------------
# Local imports (after logging is set up so module-level loggers work)
# ---------------------------------------------------------------------------
from ai_brief import ThreatBriefGenerator
from alerts import AlertManager
from anomaly_engine import AnomalyEngine
from capture import CaptureEngine
from chain_engine import ChainEngine
from dashboard import Dashboard
from detectors import ArpSpoofDetector, DnsTunnelDetector, PortScanDetector, SynFloodDetector
from feature_extractor import FeatureExtractor


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="netsentinel",
        description="NetSentinel AI — Behavioral Attack Chain Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --pcap capture.pcap
  python main.py --pcap attack.pcap --no-ai --threshold 10 --log-file out.log
  python main.py --interface eth0 --warmup 120   (requires Administrator / sudo)
        """,
    )

    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--interface", "-i", metavar="IFACE",
                     help="Network interface for live capture (requires admin/root)")
    src.add_argument("--pcap", "-p", metavar="FILE",
                     help="Path to a .pcap file for offline analysis")

    p.add_argument("--threshold",    type=int,   default=15,
                   help="Port scan: unique ports in window before alert (default 15)")
    p.add_argument("--window",       type=float, default=10.0,
                   help="Detection sliding-window width in seconds (default 10)")
    p.add_argument("--warmup",       type=float, default=60.0,
                   help="ML warm-up period in packet-time seconds (default 60)")
    p.add_argument("--chain-window", type=float, default=300.0,
                   help="Chain correlation window in seconds (default 300)")
    p.add_argument("--log-file",     default="netsentinel.log",
                   help="Alert log file path (default: netsentinel.log)")
    p.add_argument("--no-ai",        action="store_true",
                   help="Disable Gemini AI threat brief generation")
    p.add_argument("--gemini-key",   metavar="KEY",
                   help="Gemini API key (or set GEMINI_API_KEY env var)")
    p.add_argument("--verbose", "-v", action="store_true",
                   help="Enable DEBUG-level logging")
    return p.parse_args()


# ---------------------------------------------------------------------------
# Protocol classifier
# ---------------------------------------------------------------------------

def _classify_proto(pkt) -> str:
    """Return a protocol string for dashboard protocol-counts panel."""
    try:
        from scapy.layers.dns import DNS
        from scapy.layers.inet import ICMP, IP, TCP, UDP
        from scapy.layers.l2 import ARP

        if pkt.haslayer(ARP):
            return "ARP"
        if pkt.haslayer(DNS):
            return "DNS"
        if pkt.haslayer(TCP):
            return "TCP"
        if pkt.haslayer(UDP):
            return "UDP"
        if pkt.haslayer(ICMP):
            return "ICMP"
    except Exception:
        pass
    return "OTHER"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    args = _parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    source = args.pcap or args.interface

    # ---- Instantiate all components ----
    feature_extractor  = FeatureExtractor(window_seconds=args.window)
    anomaly_engine     = AnomalyEngine(warmup_seconds=args.warmup)

    port_scan_detector = PortScanDetector(threshold=args.threshold, window=args.window)
    syn_flood_detector = SynFloodDetector(window=args.window)
    arp_spoof_detector = ArpSpoofDetector()
    dns_tunnel_detector = DnsTunnelDetector()

    chain_engine    = ChainEngine(chain_window=args.chain_window)
    alert_manager   = AlertManager(log_file=args.log_file)
    brief_generator = ThreatBriefGenerator(api_key=args.gemini_key, enabled=not args.no_ai)

    capture   = CaptureEngine(interface=args.interface, pcap_file=args.pcap)
    dashboard = Dashboard(source=source)

    # ---- Packet processing callback (called for every packet) ----
    def on_packet(pkt) -> None:
        # Protocol counts
        proto = _classify_proto(pkt)
        dashboard.proto_counts[proto] += 1
        dashboard.packet_count += 1

        # Feature extraction
        features = feature_extractor.update(pkt)

        # ML anomaly engine feed + score
        if features is not None:
            anomaly_engine.feed(features)
            features.anomaly_score = anomaly_engine.score(features)

        # Run all detectors
        candidates = [
            port_scan_detector.process(pkt),
            syn_flood_detector.process(pkt),
            arp_spoof_detector.process(pkt),
            dns_tunnel_detector.process(pkt),
        ]

        for event in candidates:
            if event is None:
                continue
            # Attach the ML anomaly score to the event
            if features is not None:
                event.anomaly_score = features.anomaly_score

            # Fire alert (deduplication inside AlertManager)
            if alert_manager.fire(event):
                dashboard.alert_count += 1
                # Feed chain engine — may produce a correlated AttackChain
                chain = chain_engine.ingest(event)
                if chain is not None:
                    chain.ai_brief = brief_generator.generate(chain)
                    alert_manager.fire_chain(chain)
                    dashboard.chain_count += 1

        # Refresh dashboard state every 50 packets
        if dashboard.packet_count % 50 == 0:
            _sync_dashboard(dashboard, feature_extractor, alert_manager, anomaly_engine)

    # ---- Start everything ----
    logger.info("Starting NetSentinel AI | source=%s", source)
    dashboard.start()
    dashboard.update()

    try:
        capture.start(on_packet)

        # Keep-alive loop — refresh dashboard while capture thread runs
        while capture.is_running:
            _sync_dashboard(dashboard, feature_extractor, alert_manager, anomaly_engine)
            time.sleep(0.5)

        # Final sync after capture ends
        _sync_dashboard(dashboard, feature_extractor, alert_manager, anomaly_engine)
        dashboard.update()

        logger.info(
            "Capture finished | packets=%d | alerts=%d | chains=%d",
            dashboard.packet_count,
            alert_manager.total_alerts,
            alert_manager.chain_count,
        )

        # For PCAP mode: keep the dashboard visible for 10 s so the user can read it
        if args.pcap:
            logger.info("Replay complete — dashboard will close in 10 seconds.")
            time.sleep(10)

    except KeyboardInterrupt:
        logger.info("Interrupted by user (Ctrl+C).")
    finally:
        capture.stop()
        dashboard.stop()
        print(
            f"\n[DONE] NetSentinel AI complete | "
            f"Packets: {dashboard.packet_count:,} | "
            f"Alerts: {alert_manager.total_alerts} | "
            f"Chains: {alert_manager.chain_count} | "
            f"Log: {args.log_file}"
        )


def _sync_dashboard(dashboard, feature_extractor, alert_manager, anomaly_engine) -> None:
    """Push latest state into the dashboard and trigger a render."""
    dashboard.top_features  = feature_extractor.get_top_talkers(n=8)
    dashboard.recent_events = alert_manager.recent_events
    dashboard.recent_chains = alert_manager.recent_chains
    dashboard.in_warmup     = anomaly_engine.in_warmup
    dashboard.warmup_pct    = anomaly_engine.warmup_progress
    dashboard.update()


if __name__ == "__main__":
    main()
