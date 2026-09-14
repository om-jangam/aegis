"""Command-line interface.

Aegis began as a desktop console, which meant it could not run on the hosts that
most need a HIDS: headless Linux servers. This module adds a terminal interface
so the same detection engine works over SSH, in a container, or under systemd —
and keeps the GUI as just one of several front-ends.

The GUI is imported lazily, inside the ``console`` command, so a headless
install never needs the UI toolkit present merely to run ``aegis monitor``.

Commands
--------
``aegis monitor``   run detection in the foreground, printing findings
``aegis status``    report platform, firewall backend and privileges
``aegis rules``     list the firewall rules Aegis manages
``aegis block``     contain a remote host
``aegis console``   launch the desktop UI (default)
"""
from __future__ import annotations

import argparse
import json
import logging
import signal
import sys
import threading
from datetime import UTC, datetime

from aegis import __description__, __version__
from aegis.core.models import Finding, Severity

log = logging.getLogger(__name__)

_SEVERITY_LABEL = {
    Severity.CRITICAL: "CRIT",
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: "MED ",
    Severity.LOW: "LOW ",
    Severity.INFO: "INFO",
}

# ANSI colours, used only when stdout is a real terminal.
_SEVERITY_COLOUR = {
    Severity.CRITICAL: "\033[1;37;41m",
    Severity.HIGH: "\033[1;31m",
    Severity.MEDIUM: "\033[1;33m",
    Severity.LOW: "\033[36m",
    Severity.INFO: "\033[90m",
}
_RESET = "\033[0m"


def _use_colour(stream) -> bool:
    return hasattr(stream, "isatty") and stream.isatty()


def _format_finding(finding: Finding, colour: bool) -> str:
    label = _SEVERITY_LABEL.get(finding.severity, "????")
    stamp = datetime.now(tz=UTC).strftime("%H:%M:%S")
    if colour:
        label = f"{_SEVERITY_COLOUR.get(finding.severity, '')}{label}{_RESET}"
    reasons = "; ".join(finding.reasons)
    return (f"{stamp} [{label}] {finding.technique or '-':<6} "
            f"{finding.title} - {finding.entity}\n         {reasons}")


def _finding_as_dict(finding: Finding) -> dict:
    """Render a finding as a flat JSON object for piping into a SIEM."""
    return {
        "timestamp": datetime.now(tz=UTC).isoformat(),
        "rule_id": finding.rule_id,
        "title": finding.title,
        "severity": finding.severity.value,
        "score": finding.score,
        "technique": finding.technique,
        "tactic": finding.tactic,
        "entity": finding.entity,
        "reasons": list(finding.reasons),
        "summary": finding.source_summary,
    }


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #
def cmd_status(args) -> int:
    """Report what Aegis can see and do on this host."""
    from aegis.alerting.notifier import notification_backend
    from aegis.config import DATA_DIR
    from aegis.detection.engine import DetectionEngine
    from aegis.platforms import CURRENT_OS, is_elevated, privilege_hint
    from aegis.response.factory import get_firewall

    backend = get_firewall()
    info = {
        "version": __version__,
        "platform": CURRENT_OS.value,
        "python": sys.version.split()[0],
        "elevated": is_elevated(),
        "firewall_backend": backend.backend_name,
        "response_available": backend.available(),
        "notifications": notification_backend(),
        "detection_rules": DetectionEngine().rule_count,
        "data_dir": str(DATA_DIR),
    }
    if args.json:
        print(json.dumps(info, indent=2))
        return 0

    print(f"Aegis {__version__} - {__description__}")
    print(f"  Platform           {info['platform']} (Python {info['python']})")
    print(f"  Privileges         {'elevated' if info['elevated'] else 'standard user'}")
    print(f"  Firewall backend   {info['firewall_backend']}")
    print(f"  Response           {'available' if info['response_available'] else 'UNAVAILABLE'}")
    print(f"  Notifications      {info['notifications']}")
    print(f"  Detection rules    {info['detection_rules']}")
    print(f"  Data directory     {info['data_dir']}")
    if not info["elevated"]:
        print(f"\n  Note: {privilege_hint()}")
    return 0


def cmd_monitor(args) -> int:
    """Run the detection pipeline in the foreground until interrupted."""
    from aegis.service import SecurityService

    colour = _use_colour(sys.stdout) and not args.json
    service = SecurityService(auto_respond=args.auto_respond)
    seen = threading.Event()

    def on_finding(finding: Finding) -> None:
        if finding.severity < args.min_severity:
            return
        seen.set()
        if args.json:
            print(json.dumps(_finding_as_dict(finding)), flush=True)
        else:
            print(_format_finding(finding, colour), flush=True)

    service.on_finding(on_finding)

    stop = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, lambda *_: stop.set())

    if not args.json:
        mode = "with auto-containment" if args.auto_respond else "detection only"
        print(f"Aegis monitoring started ({mode}). Press Ctrl+C to stop.\n")

    service.start()
    try:
        stop.wait()
    finally:
        if not args.json:
            print("\nStopping...")
        service.close()
    return 0


def cmd_rules(args) -> int:
    """List the firewall rules Aegis manages on this host."""
    from aegis.response.factory import get_firewall

    backend = get_firewall()
    if not backend.available():
        print(f"Firewall backend unavailable: {backend.backend_name}", file=sys.stderr)
        return 1

    rules = backend.list_rules(only_aegis=not args.all)
    if args.json:
        print(json.dumps([{
            "name": r.name, "direction": r.direction.value, "action": r.action.value,
            "enabled": r.enabled, "protocol": r.protocol.value,
            "remote_ip": r.remote_ip, "remote_port": r.remote_port,
        } for r in rules], indent=2))
        return 0

    if not rules:
        print("No Aegis-managed firewall rules.")
        return 0
    print(f"{'STATE':<9}{'DIR':<5}{'ACTION':<8}{'REMOTE':<24}NAME")
    for r in rules:
        state = "enabled" if r.enabled else "disabled"
        remote = f"{r.remote_ip}:{r.remote_port}" if r.remote_port != "any" else r.remote_ip
        print(f"{state:<9}{r.direction.value:<5}{r.action.value:<8}{remote:<24}{r.name}")
    return 0


def cmd_block(args) -> int:
    """Contain a remote host by blocking it in the host firewall."""
    from aegis.platforms import is_elevated, privilege_hint
    from aegis.response.factory import get_firewall

    backend = get_firewall()
    if not backend.available():
        print(f"Firewall backend unavailable: {backend.backend_name}", file=sys.stderr)
        return 1
    if not is_elevated():
        print(f"Refusing to attempt a block without privileges. {privilege_hint()}",
              file=sys.stderr)
        return 1

    result = backend.block_ip(args.ip, note=args.note)
    print(result.message, file=sys.stdout if result.ok else sys.stderr)
    return 0 if result.ok else 1


def cmd_console(args) -> int:
    """Launch the desktop UI."""
    try:
        from aegis.ui.app import run
    except ImportError as exc:
        print(
            f"The desktop console is unavailable: {exc}\n"
            f"Install the UI extra (`pip install aegis-hids[ui]`) or use "
            f"`aegis monitor` for headless operation.",
            file=sys.stderr,
        )
        return 1
    run()
    return 0


# --------------------------------------------------------------------------- #
# Parser
# --------------------------------------------------------------------------- #
def _severity(value: str) -> Severity:
    try:
        return Severity[value.upper()]
    except KeyError:
        raise argparse.ArgumentTypeError(
            f"invalid severity {value!r} (choose from "
            f"{', '.join(s.name.lower() for s in Severity)})"
        ) from None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aegis",
        description=f"Aegis {__version__} - {__description__}",
    )
    parser.add_argument("--version", action="version", version=f"aegis {__version__}")
    sub = parser.add_subparsers(dest="command")

    p_status = sub.add_parser("status", help="report platform, backend and privileges")
    p_status.add_argument("--json", action="store_true", help="machine-readable output")
    p_status.set_defaults(func=cmd_status)

    p_monitor = sub.add_parser("monitor", help="run headless detection in the foreground")
    p_monitor.add_argument("--json", action="store_true",
                           help="emit one JSON object per finding (for a SIEM)")
    p_monitor.add_argument("--min-severity", type=_severity, default=Severity.LOW,
                           metavar="LEVEL",
                           help="suppress findings below this severity "
                                "(info, low, medium, high, critical)")
    p_monitor.add_argument("--auto-respond", action="store_true",
                           help="automatically block hosts behind high-severity findings")
    p_monitor.set_defaults(func=cmd_monitor)

    p_rules = sub.add_parser("rules", help="list managed firewall rules")
    p_rules.add_argument("--all", action="store_true",
                         help="include rules Aegis did not create")
    p_rules.add_argument("--json", action="store_true", help="machine-readable output")
    p_rules.set_defaults(func=cmd_rules)

    p_block = sub.add_parser("block", help="block a remote IP address")
    p_block.add_argument("ip", help="the address to block")
    p_block.add_argument("--note", default="manual", help="reason, recorded in the audit trail")
    p_block.set_defaults(func=cmd_block)

    p_console = sub.add_parser("console", help="launch the desktop UI")
    p_console.set_defaults(func=cmd_console)

    return parser


def main(argv: list[str] | None = None) -> int:
    from aegis.logging_config import setup_logging

    setup_logging()
    parser = build_parser()
    args = parser.parse_args(argv)
    # No subcommand keeps the original behaviour: open the desktop console.
    if not getattr(args, "command", None):
        return cmd_console(args)
    return args.func(args)
