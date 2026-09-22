"""Sign-in and account-change monitoring.

Attacks on an endpoint very often start at the front door: guessing a password
over RDP or SSH, then creating an account or granting it administrator rights to
keep the access. None of that shows up in socket or process telemetry, but every
operating system already records it.

Where the records come from
---------------------------
* **Windows** — the Security event log (4625 refused, 4624 accepted, 4720 account
  created, 4728/4732 added to a group, 4740 locked out), read through PowerShell.
  Reading that log needs administrator rights, so without them the collector
  reports itself unavailable rather than pretending everything is quiet.
* **Linux** — ``/var/log/auth.log`` or ``/var/log/secure``, read incrementally
  from the position reached last time; ``journalctl`` when neither file exists.
* **macOS** — not supported: the unified log has no cheap way to be polled, and
  guessing would be worse than saying so.

Only metadata is read: who, from where, by which method, and why a sign-in was
refused. Passwords are never logged by the OS and never touched here.
"""
from __future__ import annotations

import json
import logging
import re
import subprocess
from collections.abc import Iterable
from datetime import datetime, timedelta
from pathlib import Path
from xml.etree import ElementTree

from aegis.collectors.base import Collector
from aegis.config import settings
from aegis.core.accounts import is_admin_group
from aegis.core.events import AuthEvent, EventSource, EventType
from aegis.platforms import is_elevated, is_linux, is_windows
from aegis.response.command import CommandRunner, decode, default_runner

log = logging.getLogger(__name__)

#: Windows Security log records Aegis reads, and what each one means.
WINDOWS_EVENTS = {
    "4625": EventType.AUTH_FAILURE,
    "4624": EventType.AUTH_SUCCESS,
    "4720": EventType.ACCOUNT_CREATED,
    "4728": EventType.ACCOUNT_PRIVILEGED,
    "4732": EventType.ACCOUNT_PRIVILEGED,
    "4740": EventType.ACCOUNT_LOCKED,
}
#: Windows logon types, in words.
LOGON_TYPES = {
    "2": "console", "3": "network", "4": "scheduled task", "5": "service",
    "7": "unlock", "8": "network (cleartext)", "9": "run as", "10": "remote desktop",
    "11": "cached login",
}
#: Windows failure codes worth naming, in words.
FAILURE_REASONS = {
    "0xc000006a": "wrong password", "0xc0000064": "no such account",
    "0xc0000072": "account disabled", "0xc0000234": "account locked out",
    "0xc0000070": "sign-in not allowed from here", "0xc000006f": "outside allowed hours",
    "0xc0000071": "password expired", "0xc0000193": "account expired",
    "0xc000015b": "this sign-in type not allowed",
}
_XML_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
#: Accounts Windows uses for its own housekeeping; their sign-ins are noise.
_MACHINE_ACCOUNTS = ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON",
                     "DWM-1", "DWM-2", "UMFD-0", "UMFD-1")

LINUX_LOGS = ("/var/log/auth.log", "/var/log/secure")
_SSH_FAIL = re.compile(
    r"(?:Failed|Invalid user|error: maximum authentication attempts).*?"
    r"(?:password|publickey)?\s*for\s+(?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\S+)")
_SSH_OK = re.compile(r"Accepted\s+(?P<method>\S+)\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)")
_SUDO_FAIL = re.compile(r"sudo:\s*(?P<user>\S+)\s*:.*authentication failure")
_PAM_FAIL = re.compile(r"authentication failure;.*?ruser=(?P<ruser>\S*).*?user=(?P<user>\S+)")
_USERADD = re.compile(r"(?:useradd|new user)\S*:.*name=(?P<user>[^,\s]+)")
_GROUP_ADD = re.compile(
    r"add\s+'(?P<user>[^']+)'\s+to\s+group\s+'(?P<group>[^']+)'")
_SYSLOG_TIME = re.compile(r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d+)\s+(?P<time>\d\d:\d\d:\d\d)")
# --------------------------------------------------------------------------- #
# Windows
# --------------------------------------------------------------------------- #
def _text(node, name: str) -> str:
    found = node.find(f"e:EventData/e:Data[@Name='{name}']", _XML_NS)
    value = (found.text or "").strip() if found is not None else ""
    return "" if value in ("-", "N/A") else value


def parse_windows_event(xml: str) -> AuthEvent | None:
    """One Security-log record as an :class:`AuthEvent`, or None if it is not one we read."""
    try:
        node = ElementTree.fromstring(xml)
    except ElementTree.ParseError:
        return None
    system = node.find("e:System", _XML_NS)
    if system is None:
        return None
    event_id = (system.findtext("e:EventID", default="", namespaces=_XML_NS) or "").strip()
    kind = WINDOWS_EVENTS.get(event_id)
    if kind is None:
        return None
    created = system.find("e:TimeCreated", _XML_NS)
    stamp = (created.get("SystemTime") if created is not None else "") or ""
    try:
        when = datetime.fromisoformat(stamp.replace("Z", "+00:00")).astimezone().replace(tzinfo=None)
    except ValueError:
        when = datetime.now()

    user = _text(node, "TargetUserName")
    actor = _text(node, "SubjectUserName")
    ip = _text(node, "IpAddress")
    if ip in ("::1", "127.0.0.1"):
        ip = ""
    if kind in (EventType.AUTH_FAILURE, EventType.AUTH_SUCCESS):
        if user.upper() in _MACHINE_ACCOUNTS or user.endswith("$"):
            return None            # the computer signing in to itself
        method = LOGON_TYPES.get(_text(node, "LogonType"), "login")
    else:
        method = "account change"
    reason = FAILURE_REASONS.get(_text(node, "Status").lower(), "") or \
        FAILURE_REASONS.get(_text(node, "SubStatus").lower(), "")
    return AuthEvent(
        type=kind, source=EventSource.AUTH_LOG, timestamp=when,
        user=user, actor=actor if actor != user else "", source_ip=ip, method=method,
        reason=reason, group=_text(node, "TargetDomainName") if kind
        is EventType.ACCOUNT_PRIVILEGED else "",
        record_id=system.findtext("e:EventRecordID", default="", namespaces=_XML_NS) or "",
        raw={"event_id": event_id, "process": _text(node, "ProcessName")})


_WINDOWS_QUERY = (
    "$ErrorActionPreference='Stop';"
    "Get-WinEvent -FilterHashtable @{{LogName='Security';Id=@({ids});"
    "StartTime=[datetime]::Parse('{since}')}} -MaxEvents {limit} -ErrorAction SilentlyContinue"
    " | ForEach-Object {{ $_.ToXml() }}"
)


# --------------------------------------------------------------------------- #
# Linux
# --------------------------------------------------------------------------- #
def _syslog_time(line: str, now: datetime) -> datetime:
    """The timestamp of a syslog line (which carries no year)."""
    match = _SYSLOG_TIME.match(line)
    if not match:
        try:                        # journalctl short-iso, and rsyslog RFC3339
            return datetime.fromisoformat(line.split()[0].replace("Z", "+00:00")) \
                .astimezone().replace(tzinfo=None)
        except (ValueError, IndexError):
            return now
    try:
        when = datetime.strptime(
            f"{match['month']} {match['day']} {match['time']} {now.year}", "%b %d %H:%M:%S %Y")
    except ValueError:
        return now
    if when - now > timedelta(days=1):       # a December line read in January
        when = when.replace(year=now.year - 1)
    return when


def parse_linux_line(line: str, now: datetime | None = None) -> AuthEvent | None:
    """One auth-log line as an :class:`AuthEvent`, or None when it is routine noise."""
    now = now or datetime.now()
    when = _syslog_time(line, now)

    def event(kind: EventType, **fields) -> AuthEvent:
        return AuthEvent(type=kind, source=EventSource.AUTH_LOG, timestamp=when,
                         raw={"line": line.strip()[:400]}, **fields)

    if (match := _SSH_OK.search(line)):
        return event(EventType.AUTH_SUCCESS, user=match["user"], source_ip=match["ip"],
                     method=f"ssh ({match['method']})")
    if "sshd" in line and (match := _SSH_FAIL.search(line)):
        reason = "no such account" if "invalid user" in line.lower() else "wrong password"
        return event(EventType.AUTH_FAILURE, user=match["user"], source_ip=match["ip"],
                     method="ssh", reason=reason)
    if (match := _SUDO_FAIL.search(line)):
        return event(EventType.AUTH_FAILURE, user=match["user"], method="sudo",
                     reason="wrong password")
    if "authentication failure" in line and (match := _PAM_FAIL.search(line)):
        return event(EventType.AUTH_FAILURE, user=match["user"] or match["ruser"],
                     method="login", reason="wrong password")
    if (match := _USERADD.search(line)):
        return event(EventType.ACCOUNT_CREATED, user=match["user"], method="account change")
    if (match := _GROUP_ADD.search(line)) and is_admin_group(match["group"]):
        return event(EventType.ACCOUNT_PRIVILEGED, user=match["user"], group=match["group"],
                     method="account change")
    return None


# --------------------------------------------------------------------------- #
# The collector
# --------------------------------------------------------------------------- #
class AuthCollector(Collector):
    """Emits sign-in attempts and account changes from the platform's own records."""

    name = "auth"
    source = EventSource.AUTH_LOG
    #: Most records read per poll, so a flood cannot swamp the pipeline.
    MAX_RECORDS = 300

    def __init__(self, runner: CommandRunner | None = None, state_path: Path | None = None,
                 log_paths: Iterable[str] = LINUX_LOGS):
        super().__init__()
        self._runner = runner or default_runner
        self._state_path = state_path
        self._log_paths = list(log_paths)
        self._since = datetime.now()
        self._seen_records: set[str] = set()
        self._offsets: dict[str, tuple[int, int]] = {}   # path -> (inode/size marker, offset)
        self._load_state()

    # -- availability ------------------------------------------------------- #
    def available(self) -> bool:
        if not settings.auth_monitoring_enabled:
            return False
        if is_windows():
            if not is_elevated():
                log.info("Sign-in monitoring needs administrator rights (the Windows "
                         "Security log is not readable otherwise).")
                return False
            return True
        if is_linux():
            if any(Path(p).exists() for p in self._log_paths):
                return True
            return self._run(["journalctl", "--version"]) is not None
        log.info("Sign-in monitoring is not supported on this platform.")
        return False

    # -- polling ------------------------------------------------------------ #
    def poll(self) -> Iterable[AuthEvent]:
        try:
            events = self._poll_windows() if is_windows() else self._poll_linux()
        except Exception:  # noqa: BLE001 - a log we cannot read must not stop monitoring
            log.exception("Could not read the sign-in records")
            return []
        self._save_state()
        return events

    def _poll_windows(self) -> list[AuthEvent]:
        since = (self._since - timedelta(seconds=5)).strftime("%Y-%m-%dT%H:%M:%S")
        script = _WINDOWS_QUERY.format(ids=",".join(WINDOWS_EVENTS), since=since,
                                       limit=self.MAX_RECORDS)
        out = self._run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                        timeout=60)
        self._since = datetime.now()
        if out is None:
            return []
        events = []
        for block in re.findall(r"<Event\b.*?</Event>", out, re.DOTALL):
            event = parse_windows_event(block)
            if event is None or event.record_id in self._seen_records:
                continue
            self._seen_records.add(event.record_id)
            events.append(event)
        if len(self._seen_records) > 5000:
            self._seen_records = set(list(self._seen_records)[-2000:])
        return events

    def _poll_linux(self) -> list[AuthEvent]:
        events: list[AuthEvent] = []
        read_any = False
        for path in self._log_paths:
            if Path(path).exists():
                read_any = True
                events.extend(self._read_file(path))
        if not read_any:
            events.extend(self._read_journal())
        return events[-self.MAX_RECORDS:]

    def _read_file(self, path: str) -> list[AuthEvent]:
        """New lines since the last poll; starts from the end on the first read."""
        try:
            stat = Path(path).stat()
        except OSError as exc:
            log.info("Cannot read %s: %s", path, exc)
            return []
        marker, offset = self._offsets.get(path, (0, -1))
        rotated = stat.st_size < offset or marker != int(stat.st_ctime)
        if offset < 0 or rotated:
            offset = 0 if rotated and offset >= 0 else stat.st_size
        events = []
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                fh.seek(offset)
                for line in fh:
                    event = parse_linux_line(line)
                    if event is not None:
                        events.append(event)
                self._offsets[path] = (int(stat.st_ctime), fh.tell())
        except OSError as exc:
            log.info("Cannot read %s: %s", path, exc)
        return events

    def _read_journal(self) -> list[AuthEvent]:
        since = self._since.strftime("%Y-%m-%d %H:%M:%S")
        out = self._run(["journalctl", "--since", since, "--no-pager", "-o", "short-iso",
                         "-n", str(self.MAX_RECORDS), "SYSLOG_FACILITY=10"], timeout=30)
        self._since = datetime.now()
        if not out:
            return []
        return [e for e in (parse_linux_line(line) for line in out.splitlines())
                if e is not None]

    # -- helpers ------------------------------------------------------------ #
    def _run(self, args: list[str], timeout: int = 20) -> str | None:
        try:
            result = self._runner(args, timeout)
        except (OSError, subprocess.SubprocessError):
            return None
        return decode(result.stdout) if result.returncode == 0 else None

    def _load_state(self) -> None:
        """Where each log was read up to, so a restart does not re-read old records."""
        if self._state_path is None:
            return
        try:
            state = json.loads(self._state_path.read_text(encoding="utf-8"))
            self._offsets = {k: tuple(v) for k, v in state.get("offsets", {}).items()}
            self._seen_records = set(state.get("records", []))
        except (OSError, ValueError, TypeError):
            self._offsets, self._seen_records = {}, set()

    def _save_state(self) -> None:
        if self._state_path is None:
            return
        try:
            self._state_path.parent.mkdir(parents=True, exist_ok=True)
            self._state_path.write_text(json.dumps({
                "offsets": {k: list(v) for k, v in self._offsets.items()},
                "records": sorted(self._seen_records)[-2000:],
            }), encoding="utf-8")
        except OSError:
            log.debug("Could not save the sign-in reading position", exc_info=True)
