"""
Packet capture engine for NetSentinel AI.
Supports both live interface capture and offline PCAP replay.
Dispatches packets via a callback to keep capture decoupled from processing.
"""
from __future__ import annotations

import logging
import threading
import time
from pathlib import Path
from typing import Callable, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Scapy 2.7 compatibility: force-register Ethernet as link-layer type 1.
# Without this, rdpcap() falls back to Raw for every packet and all
# haslayer(IP/TCP/UDP) checks silently return False.
# ---------------------------------------------------------------------------
def _ensure_eth_registered() -> None:
    try:
        from scapy.config import conf
        from scapy.layers.l2 import Ether
        # DLT_EN10MB = 1 is standard Ethernet; register if missing
        if 1 not in conf.l2types.num2layer:
            conf.l2types.register(1, Ether)
            logger.debug("Registered Ethernet as PCAP link-layer type 1.")
    except Exception as exc:
        logger.debug("Could not register Ethernet link type: %s", exc)


_ensure_eth_registered()


class CaptureEngine:
    """
    Abstracts packet sourcing from both live interfaces and PCAP files.

    Usage:
        engine = CaptureEngine(pcap_file="attack.pcap")
        engine.start(callback=my_packet_handler)
        # engine runs in a background thread
        engine.stop()
    """

    def __init__(
        self,
        interface: Optional[str] = None,
        pcap_file: Optional[str] = None,
    ):
        if interface and pcap_file:
            raise ValueError("Specify either --interface or --pcap, not both.")
        if not interface and not pcap_file:
            raise ValueError("Specify either --interface or --pcap.")

        self.interface = interface
        self.pcap_file = pcap_file
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.packet_count = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self, callback: Callable) -> None:
        """Start capture in a background daemon thread, calling callback(pkt) per packet."""
        self._callback = callback
        if self.pcap_file:
            self._thread = threading.Thread(target=self._replay_pcap, daemon=True, name="pcap-replay")
        else:
            self._thread = threading.Thread(target=self._live_capture, daemon=True, name="live-capture")
        self._thread.start()
        logger.info("CaptureEngine started — source: %s", self.pcap_file or self.interface)

    def stop(self) -> None:
        """Signal the capture thread to stop and wait for it to finish."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)

    @property
    def is_running(self) -> bool:
        """True while the capture thread is alive."""
        return self._thread is not None and self._thread.is_alive()

    # ------------------------------------------------------------------
    # Internal capture modes
    # ------------------------------------------------------------------

    def _replay_pcap(self) -> None:
        """Read packets from a .pcap file and dispatch them at ~10× real speed."""
        try:
            from scapy.utils import rdpcap
        except ImportError:
            logger.error("Scapy is not installed. Run: pip install scapy")
            return

        pcap_path = Path(self.pcap_file)
        if not pcap_path.exists():
            logger.error("PCAP file not found: %s", self.pcap_file)
            return

        logger.info("Loading PCAP: %s", self.pcap_file)
        try:
            packets = rdpcap(str(pcap_path))
        except Exception as exc:
            logger.error("Failed to read PCAP: %s", exc)
            return

        logger.info("Loaded %d packets — beginning replay at 10× speed.", len(packets))

        prev_ts: Optional[float] = None
        for pkt in packets:
            if self._stop_event.is_set():
                break
            ts = float(pkt.time)
            if prev_ts is not None:
                gap = (ts - prev_ts) / 10.0   # 10× speed-up
                if 0 < gap < 0.05:            # cap sleep so UI stays responsive
                    time.sleep(gap)
            prev_ts = ts

            # Safety net: if Scapy decoded the packet as Raw (link-type fallback),
            # try re-interpreting the bytes as an Ethernet frame.
            try:
                from scapy.packet import Raw
                from scapy.layers.l2 import Ether
                if isinstance(pkt, Raw):
                    pkt = Ether(bytes(pkt))
            except Exception:
                pass

            try:
                self._callback(pkt)
            except Exception as exc:
                logger.debug("Callback error on packet %d: %s", self.packet_count, exc)
            self.packet_count += 1

        logger.info("PCAP replay complete — %d packets processed.", self.packet_count)

    def _live_capture(self) -> None:
        """Capture live traffic from a network interface using Scapy sniff()."""
        try:
            from scapy.sendrecv import sniff
        except ImportError:
            logger.error("Scapy is not installed. Run: pip install scapy")
            return

        logger.info("Starting live capture on interface: %s", self.interface)
        try:
            sniff(
                iface=self.interface,
                prn=self._on_live_packet,
                store=False,
                stop_filter=lambda _: self._stop_event.is_set(),
            )
        except PermissionError:
            logger.error(
                "Permission denied on interface '%s'. "
                "Run as Administrator (Windows) or with sudo (Linux/macOS).",
                self.interface,
            )
        except Exception as exc:
            logger.error("Live capture error: %s", exc)

    def _on_live_packet(self, pkt) -> None:
        try:
            self._callback(pkt)
        except Exception as exc:
            logger.debug("Callback error: %s", exc)
        self.packet_count += 1
