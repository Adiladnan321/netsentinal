"""
Rich live terminal dashboard for NetSentinel AI.

Renders a 4-panel TUI that refreshes every 500 ms:

  ┌──────────────────────────────────────────────────────────────────┐
  │  🛡️  NETSENTINEL AI  |  Behavioral Attack Chain Analyzer          │
  │  Source: ...  Uptime: 00:01:23  Packets: 4,512  Alerts: 3        │
  ├──────────────────────────┬───────────────────────────────────────┤
  │   📊 PROTOCOL STATS      │  👁️  TOP TALKERS                       │
  ├──────────────────────────┴───────────────────────────────────────┤
  │   🚨 RECENT ALERTS                                               │
  ├──────────────────────────────────────────────────────────────────┤
  │   🔗 ATTACK CHAINS  +  🤖 AI THREAT BRIEF                        │
  └──────────────────────────────────────────────────────────────────┘
"""
from __future__ import annotations

import time
from collections import defaultdict
from typing import Dict, List, Optional

from rich import box
from rich.align import Align
from rich.columns import Columns
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from alerts import SEVERITY_COLORS, SEVERITY_ICONS
from models import AttackChain, DetectionEvent, FlowFeatures

console = Console()


# ---------------------------------------------------------------------------
# Panel builders
# ---------------------------------------------------------------------------

def _header_panel(
    source: str,
    uptime: float,
    pkt_count: int,
    alert_count: int,
    chain_count: int,
    in_warmup: bool,
    warmup_pct: float,
) -> Panel:
    h, rem = divmod(int(uptime), 3600)
    m, s   = divmod(rem, 60)
    uptime_str = f"{h:02d}:{m:02d}:{s:02d}"

    ml_status = (
        f"[yellow]⏳ ML WARMUP {warmup_pct:.0%}[/]"
        if in_warmup
        else "[bold green]✅ ML ACTIVE[/]"
    )

    txt = Text()
    txt.append("🛡️  NETSENTINEL AI", style="bold white")
    txt.append("  ·  ", style="dim")
    txt.append("Behavioral Attack Chain Analyzer", style="italic cyan")
    txt.append("\n")
    txt.append(f"  Source: ", style="dim")
    txt.append(source, style="bold")
    txt.append(f"   Uptime: {uptime_str}", style="dim")
    txt.append(f"   Packets: {pkt_count:,}", style="bold white")
    txt.append(f"   Alerts: {alert_count}", style="bold yellow")
    txt.append(f"   Chains: {chain_count}", style="bold red")
    txt.append(f"   {ml_status}")

    return Panel(Align.center(txt), border_style="bold blue", box=box.DOUBLE_EDGE, padding=(0, 1))


def _protocol_panel(proto_counts: Dict[str, int]) -> Panel:
    total = sum(proto_counts.values()) or 1
    table = Table(box=box.SIMPLE_HEAD, header_style="bold cyan", expand=True, show_header=True)
    table.add_column("Protocol", style="cyan", width=10)
    table.add_column("Packets",  justify="right", width=9)
    table.add_column("Share",    justify="left")

    proto_order  = ["TCP", "UDP", "DNS", "ICMP", "ARP", "OTHER"]
    proto_colors = {
        "TCP":   "green", "UDP": "blue", "DNS": "cyan",
        "ICMP":  "yellow", "ARP": "magenta", "OTHER": "dim",
    }
    for proto in proto_order:
        count = proto_counts.get(proto, 0)
        pct   = count / total * 100
        bar   = "█" * int(pct / 4) + "░" * max(0, 25 - int(pct / 4))
        color = proto_colors.get(proto, "white")
        table.add_row(
            f"[{color}]{proto}[/]",
            f"{count:,}",
            f"[dim]{bar[:25]}[/] {pct:.1f}%",
        )
    return Panel(table, title="[bold]📊 PROTOCOL STATS[/]", border_style="blue")


def _talkers_panel(features: List[FlowFeatures]) -> Panel:
    table = Table(box=box.SIMPLE_HEAD, header_style="bold cyan", expand=True, show_header=True)
    table.add_column("Source IP",   style="white",  width=17)
    table.add_column("Pkt/s",       justify="right", width=7)
    table.add_column("Ports",       justify="right", width=6)
    table.add_column("Entropy",     justify="right", width=8)
    table.add_column("ML Score",    justify="right", width=9)

    for f in features[:8]:
        sc = f.anomaly_score
        if sc < -0.6:
            score_str = f"[bold red]{sc:.2f}[/]"
        elif sc < -0.3:
            score_str = f"[yellow]{sc:.2f}[/]"
        else:
            score_str = f"[green]{sc:.2f}[/]"

        table.add_row(
            f.src_ip,
            f"{f.pkt_rate:.1f}",
            str(f.unique_dst_ports),
            f"{f.byte_entropy:.2f}",
            score_str,
        )

    return Panel(table, title="[bold]👁️  TOP TALKERS[/]", border_style="blue")


def _alerts_panel(events: List[DetectionEvent]) -> Panel:
    table = Table(box=box.SIMPLE_HEAD, header_style="bold cyan", expand=True, show_header=True)
    table.add_column("Time",    style="dim",    width=9)
    table.add_column("",                        width=2)   # icon
    table.add_column("Type",    style="white",  width=13)
    table.add_column("Source IP",               width=17)
    table.add_column("MITRE",   style="cyan",   width=7)
    table.add_column("Stage",   style="cyan",   width=18)
    table.add_column("Details", style="dim")

    for evt in reversed(events[-14:]):
        color  = SEVERITY_COLORS.get(evt.severity, "white")
        icon   = SEVERITY_ICONS.get(evt.severity, "")
        detail = ", ".join(f"{k}={v}" for k, v in list(evt.details.items())[:2])
        table.add_row(
            evt.time_str,
            icon,
            f"[{color}]{evt.threat_type}[/]",
            evt.src_ip,
            f"[bold]{evt.mitre_id}[/]",
            evt.stage,
            detail[:55],
        )

    return Panel(table, title="[bold]🚨 RECENT ALERTS[/]", border_style="yellow")


def _chains_panel(chains: List[AttackChain]) -> Panel:
    if not chains:
        return Panel(
            Align.center(Text("No attack chains detected yet.", style="dim italic")),
            title="[bold]🔗 ATTACK CHAINS[/]",
            border_style="dim red",
        )

    table = Table(box=box.SIMPLE_HEAD, header_style="bold cyan", expand=True, show_header=True)
    table.add_column("Source IP",  width=17)
    table.add_column("Kill Chain", style="cyan")
    table.add_column("Confidence", justify="right", width=11)
    table.add_column("Severity",   width=11)
    table.add_column("Duration",   width=9)
    table.add_column("Detected",   width=9)

    for chain in chains[:5]:
        stage_str  = " → ".join(chain.stages)
        conf_color = "bold red" if chain.confidence >= 70 else "yellow"
        sev_color  = SEVERITY_COLORS.get(chain.severity, "white")
        sev_icon   = SEVERITY_ICONS.get(chain.severity, "")
        table.add_row(
            f"[bold]{chain.src_ip}[/]",
            stage_str,
            f"[{conf_color}]{chain.confidence:.1f}%[/]",
            f"[{sev_color}]{sev_icon} {chain.severity}[/]",
            chain.duration_str,
            chain.start_time_str,
        )

    # If the most recent chain has an AI brief, render it below the table
    latest = chains[-1]
    if latest.ai_brief:
        brief_panel = Panel(
            Text(latest.ai_brief, style="italic", overflow="fold"),
            title=f"[bold yellow]🤖 AI THREAT BRIEF  —  {latest.src_ip}[/]",
            border_style="yellow",
            padding=(0, 1),
        )
        content = Columns([table, brief_panel], equal=False, expand=True)
    else:
        content = table

    return Panel(content, title="[bold red]🔗 ATTACK CHAINS[/]", border_style="red")


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

class Dashboard:
    """
    Rich Live TUI dashboard.

    Call start() before capture begins, update() on each refresh tick,
    and stop() when capture ends (or on KeyboardInterrupt).
    """

    def __init__(self, source: str):
        self.source       = source
        self._start_time  = time.time()
        self._live: Optional[Live] = None

        # State mutated by main.py
        self.proto_counts:   Dict[str, int]     = defaultdict(int)
        self.top_features:   List[FlowFeatures] = []
        self.recent_events:  List[DetectionEvent] = []
        self.recent_chains:  List[AttackChain]    = []
        self.packet_count:   int   = 0
        self.alert_count:    int   = 0
        self.chain_count:    int   = 0
        self.in_warmup:      bool  = True
        self.warmup_pct:     float = 0.0

    def start(self) -> "Dashboard":
        """Enter the Rich Live context. Must be called before update()."""
        self._live = Live(
            self._build_layout(),
            console=console,
            refresh_per_second=2,
            screen=True,
        )
        self._live.__enter__()
        return self

    def stop(self) -> None:
        """Exit the Rich Live context cleanly."""
        if self._live:
            try:
                self._live.__exit__(None, None, None)
            except Exception:
                pass

    def update(self) -> None:
        """Push a fresh frame to the terminal. Call this at ~2 Hz."""
        if not self._live:
            return
        uptime = time.time() - self._start_time
        layout = self._build_layout(uptime=uptime)
        self._live.update(layout)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _build_layout(self, uptime: float = 0.0) -> Layout:
        layout = Layout()
        layout.split_column(
            Layout(
                _header_panel(
                    self.source, uptime, self.packet_count,
                    self.alert_count, self.chain_count,
                    self.in_warmup, self.warmup_pct,
                ),
                name="header",
                size=4,
            ),
            Layout(name="mid",    size=12),
            Layout(name="alerts", size=16),
            Layout(name="chains"),
        )
        layout["mid"].split_row(
            Layout(_protocol_panel(self.proto_counts), name="proto", ratio=1),
            Layout(_talkers_panel(self.top_features),  name="talkers", ratio=2),
        )
        layout["alerts"].update(_alerts_panel(self.recent_events))
        layout["chains"].update(_chains_panel(self.recent_chains))
        return layout
