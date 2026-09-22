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
    """Render a finding as a flat JSON object for piping into other tools."""
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
def _forwarding_config(args):
    """The configured forwarding section with command-line overrides applied."""
    from dataclasses import replace

    from aegis.config import settings

    changes: dict = {}
    if getattr(args, "forward_url", None):
        changes.update(server_url=args.forward_url, enabled=True)
    if getattr(args, "forward", False):
        changes["enabled"] = True
    if getattr(args, "forward_batch_size", None):
        changes["batch_size"] = args.forward_batch_size
    if getattr(args, "forward_flush_interval", None):
        changes["flush_interval_seconds"] = args.forward_flush_interval
    if getattr(args, "forward_insecure", False):
        changes["verify_tls"] = False
    return replace(settings.forwarding, **changes)


def _cli_forwarder(args):
    """(forwarder or None, error message or None) for the monitoring commands."""
    from aegis.config import DATA_DIR
    from aegis.forwarding import build_forwarder

    try:
        return build_forwarder(_forwarding_config(args), DATA_DIR,
                               api_key=getattr(args, "forward_api_key", None)), None
    except ValueError as exc:
        return None, str(exc)


def _start_background_security_check(service) -> None:
    """Give forwarded heartbeats a security score without delaying start-up."""
    from aegis.posture import run_posture_checks

    def run() -> None:
        try:
            service.record_posture(run_posture_checks())
        except Exception:  # noqa: BLE001
            log.exception("Background security check failed")

    threading.Thread(target=run, name="security-check", daemon=True).start()


def cmd_status(args) -> int:
    """Report what Aegis can see and do on this host."""
    from aegis.alerting.notifier import notification_backend
    from aegis.config import DATA_DIR, settings
    from aegis.detection.engine import DetectionEngine
    from aegis.forwarding import QUEUE_FILE, EventQueue
    from aegis.platforms import CURRENT_OS, is_elevated, privilege_hint
    from aegis.response.factory import get_firewall

    backend = get_firewall()
    queued = 0
    if (DATA_DIR / QUEUE_FILE).exists():
        queue = EventQueue(DATA_DIR / QUEUE_FILE)
        queued = len(queue)
        queue.close()
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
        "forwarding": {
            "enabled": settings.forwarding.enabled,
            "server_url": settings.forwarding.server_url,
            "queued_events": queued,
        },
    }
    if args.json:
        print(json.dumps(info, indent=2))
        return 0

    forwarding = info["forwarding"]
    forwarding_text = f"on -> {forwarding['server_url']}" if forwarding["enabled"] else "off"
    if queued:
        forwarding_text += f" ({queued} event(s) queued)"
    print(f"Aegis {__version__} - {__description__}")
    print(f"  Platform           {info['platform']} (Python {info['python']})")
    print(f"  Privileges         {'elevated' if info['elevated'] else 'standard user'}")
    print(f"  Firewall backend   {info['firewall_backend']}")
    print(f"  Response           {'available' if info['response_available'] else 'UNAVAILABLE'}")
    print(f"  Notifications      {info['notifications']}")
    print(f"  Detection rules    {info['detection_rules']}")
    print(f"  Forwarding         {forwarding_text}")
    print(f"  Data directory     {info['data_dir']}")
    if not info["elevated"]:
        print(f"\n  Note: {privilege_hint()}")
    return 0


def cmd_monitor(args) -> int:
    """Run the detection pipeline in the foreground until interrupted."""
    from aegis.detection.engine import DetectionEngine
    from aegis.service import SecurityService

    forwarder, error = _cli_forwarder(args)
    if error:
        print(f"Forwarding is misconfigured: {error}", file=sys.stderr)
        return 2

    colour = _use_colour(sys.stdout) and not args.json
    engine = DetectionEngine(sigma_paths=args.sigma)
    service = SecurityService(engine=engine, auto_respond=args.auto_respond,
                              forwarder=forwarder)
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
        detail = f"{engine.rule_count} rules"
        if engine.sigma_report and engine.sigma_report.skipped_count:
            detail += f", {engine.sigma_report.skipped_count} Sigma rules skipped"
        if forwarder is not None:
            detail += f", exporting to SENTINEL-X at {forwarder.sender.url}"
        print(f"Aegis monitoring started ({mode}, {detail}). Press Ctrl+C to stop.\n",
              flush=True)

    service.start()
    if forwarder is not None:
        _start_background_security_check(service)
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


def cmd_sigma(args) -> int:
    """Report how much of a Sigma rule set Aegis can actually evaluate."""
    from aegis.detection.ruleset import BUNDLED_SIGMA_DIR, build_ruleset

    paths = args.paths or []
    rules, report = build_ruleset(
        include_builtin=False,
        include_bundled_sigma=not paths,
        sigma_paths=paths,
        strict_fields=not args.include_unsupported,
    )

    if args.json:
        print(json.dumps({
            "sources": paths or [str(BUNDLED_SIGMA_DIR)],
            "loaded": report.loaded_count,
            "skipped": report.skipped_count,
            "coverage": round(report.coverage, 4),
            "skip_reasons": dict(report.reasons()),
            "rules": [{"id": r.rule_id, "title": r.title,
                       "severity": r.severity.value, "technique": r.technique}
                      for r in report.rules],
        }, indent=2))
        return 0

    print(f"Source: {', '.join(paths) if paths else BUNDLED_SIGMA_DIR}")
    print(report.summary())
    if args.list:
        print()
        for rule in sorted(report.rules, key=lambda r: (-r.severity.rank, r.title)):
            print(f"  {rule.severity.value:<9}{rule.technique or '-':<11}{rule.title}")
    return 0


_CHECK_COLOUR = {"pass": "\033[32m", "warn": "\033[33m", "fail": "\033[1;31m", "skip": "\033[90m"}
_CHECK_ORDER = {"fail": 0, "warn": 1, "pass": 2, "skip": 3}


def cmd_check(args) -> int:
    """Audit this host's security configuration and explain how to fix it."""
    from aegis.posture import CheckStatus, run_posture_checks

    report = run_posture_checks()
    failing = report.failing(args.fail_on) if args.fail_on else []
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
        return 1 if failing else 0

    colour = _use_colour(sys.stdout)
    print(f"Aegis security check ({report.platform})\n")
    ordered = sorted(report.results,
                     key=lambda r: (_CHECK_ORDER[r.status.value], -r.severity.rank))
    for r in ordered:
        label = r.status.value.upper()
        if colour:
            label = f"{_CHECK_COLOUR[r.status.value]}{label}{_RESET}"
        print(f"  [{label}] {r.title}")
        print(f"         {r.summary}")
        for detail in r.details:
            print(f"           - {detail}")
        if r.remediation:
            print(f"         Fix: {r.remediation}")
    print()
    if report.evaluated == 0:
        print("No checks could be evaluated on this host.")
    else:
        print(f"Score {report.score}/100 (grade {report.grade}): "
              f"{report.count(CheckStatus.FAIL)} failed, "
              f"{report.count(CheckStatus.WARN)} warnings, "
              f"{report.count(CheckStatus.PASS)} passed, "
              f"{report.count(CheckStatus.SKIP)} skipped")
    return 1 if failing else 0


def cmd_intel(args) -> int:
    """Manage and query threat-intelligence blocklists."""
    import ipaddress

    from aegis.intel import get_intel, intel_dir, reset_cache
    from aegis.intel.feeds import FEEDS, update_feeds

    action = getattr(args, "intel_command", None) or "status"

    if action == "update":
        known = {f.name for f in FEEDS}
        unknown = sorted(set(args.feed or []) - known)
        if unknown:
            print(f"Unknown feed(s): {', '.join(unknown)}. Available: {', '.join(sorted(known))}",
                  file=sys.stderr)
            return 2
        feeds = [f for f in FEEDS if not args.feed or f.name in args.feed]
        print(f"Downloading {len(feeds)} feed(s) into {intel_dir()}")
        results = update_feeds(intel_dir(), feeds)
        for r in results:
            print(f"  {'ok  ' if r.ok else 'FAIL'} {r.feed.name:<16} {r.message}")
        reset_cache()
        return 0 if any(r.ok for r in results) else 1

    intel = get_intel()

    if action == "lookup":
        try:
            ipaddress.ip_address(args.ip)
        except ValueError:
            print(f"Not an IP address: {args.ip}", file=sys.stderr)
            return 2
        match = intel.match(args.ip)
        if args.json:
            print(json.dumps({"ip": args.ip, "listed": match is not None,
                              "indicator": match.indicator if match else None,
                              "source": match.source if match else None}))
        elif match:
            print(f"{args.ip} is LISTED: matches {match.indicator} in '{match.source}'")
        else:
            print(f"{args.ip} is not listed ({len(intel)} indicators checked).")
        return 0 if match else 1

    info = {"directory": str(intel_dir()), "indicators": len(intel),
            "sources": intel.sources, "rejected_lines": intel.rejected,
            "available_feeds": [f.name for f in FEEDS]}
    if args.json:
        print(json.dumps(info, indent=2))
        return 0
    print(f"Indicator directory  {info['directory']}")
    print(f"Indicators loaded    {info['indicators']}")
    for source, count in sorted(intel.sources.items()):
        print(f"  {source:<24}{count}")
    if not len(intel):
        print("\nNo indicators loaded. Run `aegis intel update` to download free public "
              "blocklists, or put your own lists (one IP or CIDR per line, .txt) in the "
              "directory above.")
    return 0


_LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")


def cmd_serve(args) -> int:
    """Serve the local web dashboard."""
    import secrets
    import webbrowser

    from aegis.api.server import create_server

    if args.host in ("0.0.0.0", "::", ""):
        print("Refusing to listen on every interface. Pass a specific address with --host, "
              "or keep the default and use SSH port forwarding.", file=sys.stderr)
        return 2

    service = None
    if args.monitor:
        from aegis.service import SecurityService

        service = SecurityService(auto_respond=args.auto_respond)
        store = service.store
    else:
        from aegis.storage.database import SQLiteEventStore

        store = SQLiteEventStore()

    def release() -> None:
        if service is not None:
            service.close()
        else:
            store.close()

    token = secrets.token_urlsafe(32)
    try:
        httpd = create_server(args.host, args.port, store=store, token=token, service=service)
    except OSError as exc:
        print(f"Could not listen on {args.host}:{args.port}: {exc}", file=sys.stderr)
        release()
        return 1

    port = httpd.server_address[1]
    shown = f"[{args.host}]" if ":" in args.host else args.host
    url = f"http://{shown}:{port}/#token={token}"
    if args.host not in _LOOPBACK_HOSTS:
        print("WARNING: the dashboard is reachable from other machines over unencrypted HTTP. "
              f"Prefer the default and SSH forwarding: ssh -L {port}:127.0.0.1:{port} <host>",
              file=sys.stderr)
    print(f"Aegis dashboard: {url}")
    print("The link contains a private access token; do not share it.")
    print(f"Mode: {'live monitoring' if service else 'viewing stored data'}. "
          f"Press Ctrl+C to stop.", flush=True)

    if service is not None:
        service.start()
    threading.Thread(target=httpd.serve_forever, name="dashboard", daemon=True).start()
    if not args.no_browser:
        webbrowser.open(url)

    stop = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, lambda *_: stop.set())
    try:
        while not stop.wait(0.5):
            pass
    finally:
        httpd.shutdown()
        httpd.server_close()
        release()
    return 0


def cmd_report(args) -> int:
    """Write a self-contained HTML security report."""
    from pathlib import Path

    from aegis.reporting import build_report
    from aegis.storage.database import SQLiteEventStore

    posture = None
    if not args.no_check:
        from aegis.posture import run_posture_checks

        posture = run_posture_checks()

    store = SQLiteEventStore()
    try:
        document = build_report(store, posture)
    finally:
        store.close()

    path = Path(args.output or f"aegis-report-{datetime.now():%Y%m%d-%H%M}.html")
    try:
        path.write_text(document, encoding="utf-8")
    except OSError as exc:
        print(f"Could not write {path}: {exc}", file=sys.stderr)
        return 1
    print(f"Report written to {path.resolve()}")
    return 0


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
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="log debug detail to the console")
    sub = parser.add_subparsers(dest="command")

    p_status = sub.add_parser("status", help="report platform, backend and privileges")
    p_status.add_argument("--json", action="store_true", help="machine-readable output")
    p_status.set_defaults(func=cmd_status)

    p_monitor = sub.add_parser("monitor", help="run headless detection in the foreground")
    p_monitor.add_argument("--json", action="store_true",
                           help="emit one JSON object per finding (for scripts and log pipelines)")
    p_monitor.add_argument("--min-severity", type=_severity, default=Severity.LOW,
                           metavar="LEVEL",
                           help="suppress findings below this severity "
                                "(info, low, medium, high, critical)")
    p_monitor.add_argument("--auto-respond", action="store_true",
                           help="automatically block hosts behind high-severity findings")
    p_monitor.add_argument("--sigma", action="append", default=None, metavar="PATH",
                           help="extra directory of Sigma rules (repeatable)")
    export = p_monitor.add_argument_group(
        "export to SENTINEL-X (optional; overrides the 'forwarding' config section)")
    export.add_argument("--forward", action="store_true",
                        help="export events using the configured server")
    export.add_argument("--forward-url", metavar="URL",
                        help="SENTINEL-X server URL (https://); implies --forward")
    export.add_argument("--forward-api-key", metavar="KEY",
                        help="ingest token (prefer the AEGIS_FORWARDING_API_KEY variable)")
    export.add_argument("--forward-batch-size", type=int, metavar="N",
                        help="events per request (default 50)")
    export.add_argument("--forward-flush-interval", type=float, metavar="SECONDS",
                        help="seconds between sends (default 10)")
    export.add_argument("--forward-insecure", action="store_true",
                        help="do not verify the server's TLS certificate (testing only)")
    p_monitor.set_defaults(func=cmd_monitor)

    p_sigma = sub.add_parser(
        "sigma", help="report Sigma rule coverage for a rule set",
        description="Load a Sigma rule set and report what Aegis can evaluate, "
                    "and why anything else was skipped. With no path, inspects "
                    "the rules bundled with Aegis.")
    p_sigma.add_argument("paths", nargs="*", help="directories or files of Sigma rules")
    p_sigma.add_argument("--list", action="store_true", help="list every loaded rule")
    p_sigma.add_argument("--include-unsupported", action="store_true",
                         help="also load rules needing telemetry Aegis cannot collect, "
                              "to measure what a richer collector would unlock")
    p_sigma.add_argument("--json", action="store_true", help="machine-readable output")
    p_sigma.set_defaults(func=cmd_sigma)

    p_check = sub.add_parser(
        "check", help="audit this host's security settings and explain fixes",
        description="Run read-only checks on firewall, exposed services, antivirus, "
                    "encryption, remote access and more; print a score and how to fix "
                    "each problem.")
    p_check.add_argument("--json", action="store_true", help="machine-readable output")
    p_check.add_argument("--fail-on", type=_severity, default=None, metavar="LEVEL",
                         help="exit 1 if any check at or above this severity fails "
                              "(for scripts and CI)")
    p_check.set_defaults(func=cmd_check)

    p_intel = sub.add_parser("intel", help="manage threat-intelligence blocklists")
    p_intel.set_defaults(func=cmd_intel, intel_command=None, json=False)
    intel_sub = p_intel.add_subparsers(dest="intel_command")
    p_intel_status = intel_sub.add_parser("status", help="show loaded indicator lists")
    p_intel_status.add_argument("--json", action="store_true", help="machine-readable output")
    p_intel_update = intel_sub.add_parser(
        "update", help="download free public blocklists (the only command that goes online)")
    p_intel_update.add_argument("--feed", action="append", default=None, metavar="NAME",
                                help="only update this feed (repeatable)")
    p_intel_lookup = intel_sub.add_parser(
        "lookup", help="check whether an IP is listed (exit 0 if listed, 1 if not)")
    p_intel_lookup.add_argument("ip")
    p_intel_lookup.add_argument("--json", action="store_true", help="machine-readable output")

    p_serve = sub.add_parser(
        "serve", help="open the web dashboard in your browser",
        description="Serve a local, token-protected web dashboard. Works on any OS and on "
                    "headless servers (reach it with SSH port forwarding).")
    p_serve.add_argument("--host", default="127.0.0.1",
                         help="address to listen on (default 127.0.0.1, this machine only)")
    p_serve.add_argument("--port", type=int, default=8765, help="port (default 8765, 0 = any)")
    p_serve.add_argument("--monitor", action="store_true",
                         help="also run live detection, so the dashboard updates in real time")
    p_serve.add_argument("--auto-respond", action="store_true",
                         help="with --monitor, block hosts behind high-severity findings")
    p_serve.add_argument("--no-browser", action="store_true",
                         help="print the link without opening a browser")
    p_serve.set_defaults(func=cmd_serve)

    p_report = sub.add_parser("report", help="write a shareable HTML security report")
    p_report.add_argument("-o", "--output", metavar="FILE",
                          help="where to write (default aegis-report-<date>.html)")
    p_report.add_argument("--no-check", action="store_true",
                          help="skip the security check and report stored detections only")
    p_report.set_defaults(func=cmd_report)

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
    import logging as _logging

    from aegis.logging_config import setup_logging

    parser = build_parser()
    args = parser.parse_args(argv)
    # Findings are the CLI's output; routine INFO chatter would bury them and
    # corrupt --json consumers' expectations of a clean stream. The rotating log
    # file still records everything at INFO.
    setup_logging(_logging.DEBUG if getattr(args, "verbose", False) else _logging.WARNING)
    # No subcommand keeps the original behaviour: open the desktop console.
    if not getattr(args, "command", None):
        return cmd_console(args)
    return args.func(args)
