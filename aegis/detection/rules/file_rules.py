"""File integrity detection rules (MITRE ATT&CK-mapped).

These turn raw "a file changed" telemetry into judgements about *which* changes
matter. A modified file is not itself suspicious — packages update, logs rotate.
What matters is a change to a file that grants execution, grants access, or
destroys data.
"""
from __future__ import annotations

from datetime import timedelta

from aegis.core.events import Event, EventType, FileEvent
from aegis.core.models import Severity
from aegis.detection.base import DetectionContext, DetectionRule

_FILE_EVENTS = (EventType.FILE_CREATED, EventType.FILE_MODIFIED, EventType.FILE_DELETED)


def _normalise(path: str) -> str:
    return (path or "").replace("\\", "/").lower()


class PersistenceLocationChangedRule(DetectionRule):
    rule_id = "FILE-PERSISTENCE"
    title = "Change to an auto-start / scheduled execution location"
    severity = Severity.HIGH
    technique = "T1543"
    tactic = "Persistence"
    description = ("A file changed in a location the operating system executes "
                   "automatically — a service unit, cron entry, launch agent or "
                   "startup folder. This is how an intruder survives a reboot.")
    event_types = _FILE_EVENTS

    _LOCATIONS = (
        "/etc/cron", "/etc/systemd/system", "/.config/systemd/user",
        "/library/launchdaemons", "/library/launchagents",
        "/start menu/programs/startup", "/windows/tasks",
        "/etc/init.d", "/etc/rc.local",
    )

    def evaluate(self, event: Event, context: DetectionContext):
        if not isinstance(event, FileEvent):
            return None
        path = _normalise(event.path)
        location = next((loc for loc in self._LOCATIONS if loc in path), None)
        if not location:
            return None
        return self.make_finding(
            severity=Severity.CRITICAL if event.type == EventType.FILE_CREATED
            else Severity.HIGH,
            score=88 if event.type == EventType.FILE_CREATED else 75,
            reasons=[f"{event.path} was {event.action}",
                     f"Auto-start location: {location}"],
            entity=f"file:{event.path}",
            source_summary=event.summary())


class CredentialFileChangedRule(DetectionRule):
    rule_id = "FILE-CREDENTIAL"
    title = "Change to an authentication or credential file"
    severity = Severity.CRITICAL
    technique = "T1098"
    tactic = "Persistence"
    description = ("A file governing who may log in changed — SSH authorized "
                   "keys, the password or shadow database, or sudo policy. "
                   "Adding a key here is the quietest backdoor there is.")
    event_types = _FILE_EVENTS

    _FILES = ("/.ssh/authorized_keys", "/etc/passwd", "/etc/shadow", "/etc/sudoers",
              "/etc/sudoers.d", "/etc/ssh/sshd_config", "/.ssh/config")

    def evaluate(self, event: Event, context: DetectionContext):
        if not isinstance(event, FileEvent):
            return None
        path = _normalise(event.path)
        target = next((f for f in self._FILES if f in path), None)
        if not target:
            return None
        return self.make_finding(
            score=92,
            reasons=[f"{event.path} was {event.action}",
                     "Controls authentication or privilege"],
            entity=f"file:{event.path}",
            source_summary=event.summary())


class HostsFileChangedRule(DetectionRule):
    rule_id = "FILE-HOSTS"
    title = "Hosts file modified"
    severity = Severity.MEDIUM
    technique = "T1565.001"
    tactic = "Impact"
    description = ("The hosts file was changed. Attackers edit it to redirect "
                   "traffic, or to blackhole security-vendor update domains so "
                   "protection goes stale.")
    event_types = _FILE_EVENTS

    def evaluate(self, event: Event, context: DetectionContext):
        if not isinstance(event, FileEvent):
            return None
        if not _normalise(event.path).endswith("/etc/hosts"):
            return None
        return self.make_finding(
            score=60,
            reasons=[f"{event.path} was {event.action}",
                     "Can redirect or blackhole name resolution"],
            entity=f"file:{event.path}",
            source_summary=event.summary())


class MassFileModificationRule(DetectionRule):
    rule_id = "FILE-MASS-CHANGE"
    title = "Mass file modification (possible ransomware)"
    severity = Severity.CRITICAL
    technique = "T1486"
    tactic = "Impact"
    description = ("An unusual number of watched files changed in a short "
                   "window. Bulk rewriting is what encryption looks like from "
                   "the filesystem's point of view.")
    event_types = (EventType.FILE_MODIFIED,)

    #: Modifications within the window that constitute "mass".
    THRESHOLD = 25
    WINDOW = timedelta(minutes=2)

    def evaluate(self, event: Event, context: DetectionContext):
        if not isinstance(event, FileEvent):
            return None
        cutoff = event.timestamp - self.WINDOW
        recent = [
            e for e in context.recent(EventType.FILE_MODIFIED)
            if isinstance(e, FileEvent) and e.timestamp >= cutoff
        ]
        if len(recent) < self.THRESHOLD:
            return None
        # Report once per burst rather than on every subsequent file, which
        # would bury the analyst in identical criticals.
        if len(recent) > self.THRESHOLD:
            return None
        return self.make_finding(
            score=96,
            reasons=[f"{len(recent)} watched files modified within "
                     f"{int(self.WINDOW.total_seconds() / 60)} minutes",
                     f"Most recent: {event.path}"],
            entity="filesystem:mass-modification",
            source_summary=event.summary())


class SystemBinaryChangedRule(DetectionRule):
    rule_id = "FILE-SYSTEM-BINARY"
    title = "System binary or library modified"
    severity = Severity.CRITICAL
    technique = "T1554"
    tactic = "Persistence"
    description = ("An executable in a system directory changed. Legitimate "
                   "updates do this, but so does a trojanised binary, which is "
                   "among the most durable footholds an intruder can leave.")
    event_types = (EventType.FILE_MODIFIED, EventType.FILE_CREATED)

    _DIRS = ("/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/lib/",
             "/windows/system32/", "/windows/syswow64/")
    _EXECUTABLE_SUFFIXES = (".exe", ".dll", ".so", ".dylib", ".sys")

    def evaluate(self, event: Event, context: DetectionContext):
        if not isinstance(event, FileEvent):
            return None
        path = _normalise(event.path)
        if not any(d in path for d in self._DIRS):
            return None
        # On POSIX a system binary usually has no suffix, so the executable
        # permission bit is the better signal there.
        looks_executable = (path.endswith(self._EXECUTABLE_SUFFIXES)
                            or "x" in (event.mode or ""))
        if not looks_executable:
            return None
        return self.make_finding(
            score=90,
            reasons=[f"{event.path} was {event.action}",
                     "Executable content in a system directory"],
            entity=f"file:{event.path}",
            source_summary=event.summary())


FILE_RULES = [
    PersistenceLocationChangedRule(),
    CredentialFileChangedRule(),
    HostsFileChangedRule(),
    MassFileModificationRule(),
    SystemBinaryChangedRule(),
]
