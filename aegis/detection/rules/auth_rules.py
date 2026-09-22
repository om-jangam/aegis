"""Sign-in and account-change detections.

These read the stream of :class:`~aegis.core.events.AuthEvent` the auth collector
produces. They are deliberately stateful: a single refused sign-in is normal
life (a typo), while many in a minute, or one success at the end of a run of
failures, is the shape of an attack.
"""
from __future__ import annotations

import threading
from datetime import datetime, timedelta

from aegis.core.accounts import is_admin_group
from aegis.core.events import AuthEvent, Event, EventType
from aegis.core.models import Severity
from aegis.detection.base import DetectionContext, DetectionRule

#: Guessing detections only fire once per subject in this window.
COOLDOWN = timedelta(minutes=10)


class _AuthRule(DetectionRule):
    """Shared helpers: recent sign-in events, and one finding per subject."""

    WINDOW = timedelta(minutes=5)

    def __init__(self) -> None:
        self._last_fired: dict[str, datetime] = {}
        self._lock = threading.Lock()

    def _recent(self, context: DetectionContext, kind: EventType,
                since: datetime) -> list[AuthEvent]:
        return [e for e in context.recent(kind)
                if isinstance(e, AuthEvent) and e.timestamp >= since]

    def _first_in_window(self, key: str, when: datetime) -> bool:
        with self._lock:
            last = self._last_fired.get(key)
            if last is not None and when - last < COOLDOWN:
                return False
            self._last_fired[key] = when
            if len(self._last_fired) > 2000:
                self._last_fired = {k: t for k, t in self._last_fired.items()
                                    if when - t < COOLDOWN}
        return True


class PasswordGuessingRule(_AuthRule):
    rule_id = "AUTH-GUESSING"
    title = "Repeated failed sign-ins"
    severity = Severity.HIGH
    technique = "T1110"
    tactic = "Credential Access"
    description = ("Many sign-ins were refused for the same account, or from the same "
                   "machine, in a few minutes: the shape of someone trying passwords "
                   "until one works.")
    event_types = (EventType.AUTH_FAILURE,)
    THRESHOLD = 6

    def evaluate(self, event: Event, context: DetectionContext):
        if not isinstance(event, AuthEvent):
            return None
        since = event.timestamp - self.WINDOW
        failures = self._recent(context, EventType.AUTH_FAILURE, since)
        subject = event.source_ip or event.user
        if not subject:
            return None
        same = [e for e in failures if (e.source_ip or e.user) == subject]
        if len(same) < self.THRESHOLD:
            return None
        if not self._first_in_window(f"guess:{subject}", event.timestamp):
            return None
        users = sorted({e.user for e in same if e.user})
        where = f"from {event.source_ip}" if event.source_ip else "on this computer"
        minutes = int(self.WINDOW.total_seconds() // 60)
        return self.make_finding(
            score=85,
            reasons=[f"{len(same)} refused sign-ins {where} in under {minutes} minutes",
                     f"Accounts tried: {', '.join(users[:6]) or 'unknown'}"
                     + (" and others" if len(users) > 6 else ""),
                     f"Method: {event.method or 'login'}"],
            entity=f"auth:{subject}",
            source_summary=event.summary())


class PasswordSprayRule(_AuthRule):
    rule_id = "AUTH-SPRAY"
    title = "One password tried against many accounts"
    severity = Severity.HIGH
    technique = "T1110.003"
    tactic = "Credential Access"
    description = ("Sign-ins were refused for several different accounts from one place. "
                   "Attackers do this to stay under each account's lockout limit.")
    event_types = (EventType.AUTH_FAILURE,)
    WINDOW = timedelta(minutes=15)
    THRESHOLD = 4

    def evaluate(self, event: Event, context: DetectionContext):
        if not isinstance(event, AuthEvent) or not event.source_ip:
            return None
        since = event.timestamp - self.WINDOW
        same_source = [e for e in self._recent(context, EventType.AUTH_FAILURE, since)
                       if e.source_ip == event.source_ip and e.user]
        users = sorted({e.user for e in same_source})
        if len(users) < self.THRESHOLD:
            return None
        if not self._first_in_window(f"spray:{event.source_ip}", event.timestamp):
            return None
        return self.make_finding(
            score=88,
            reasons=[f"{len(users)} different accounts refused from {event.source_ip} "
                     f"in {int(self.WINDOW.total_seconds() // 60)} minutes",
                     f"Accounts: {', '.join(users[:8])}"
                     + (" and others" if len(users) > 8 else "")],
            entity=f"spray:{event.source_ip}",
            source_summary=event.summary())


class SuccessAfterFailuresRule(_AuthRule):
    rule_id = "AUTH-GUESSED-PASSWORD"
    title = "Sign-in succeeded after repeated failures"
    severity = Severity.CRITICAL
    technique = "T1110"
    tactic = "Credential Access"
    description = ("A sign-in was accepted right after several were refused for the same "
                   "account or from the same machine. That is what a guessed password "
                   "looks like, and it means someone may now be inside.")
    event_types = (EventType.AUTH_SUCCESS,)
    WINDOW = timedelta(minutes=10)
    THRESHOLD = 4

    def evaluate(self, event: Event, context: DetectionContext):
        if not isinstance(event, AuthEvent):
            return None
        since = event.timestamp - self.WINDOW
        failures = [e for e in self._recent(context, EventType.AUTH_FAILURE, since)
                    if (event.user and e.user == event.user)
                    or (event.source_ip and e.source_ip == event.source_ip)]
        if len(failures) < self.THRESHOLD:
            return None
        subject = f"{event.user}@{event.source_ip or 'local'}"
        if not self._first_in_window(f"guessed:{subject}", event.timestamp):
            return None
        return self.make_finding(
            score=95,
            reasons=[f"{len(failures)} refused sign-ins were followed by a successful one",
                     f"Account: {event.user or 'unknown'}"
                     + (f", from {event.source_ip}" if event.source_ip else ""),
                     f"Method: {event.method or 'login'}"],
            entity=f"auth:{subject}",
            source_summary=event.summary())


class NewAccountRule(DetectionRule):
    rule_id = "AUTH-NEW-ACCOUNT"
    title = "New user account created"
    severity = Severity.MEDIUM
    technique = "T1136.001"
    tactic = "Persistence"
    description = ("A new account appeared on this computer. Attackers create one so they "
                   "can come back even after the way they first got in is closed.")
    event_types = (EventType.ACCOUNT_CREATED,)

    def evaluate(self, event: Event, context: DetectionContext):
        if not isinstance(event, AuthEvent):
            return None
        by = f", created by {event.actor}" if event.actor else ""
        return self.make_finding(
            score=55,
            reasons=[f"Account '{event.user}' was created{by}",
                     "Expected if you just added a user; otherwise treat it as an intruder"],
            entity=f"account:{event.user}",
            source_summary=event.summary())


class AdminRightsGrantedRule(DetectionRule):
    rule_id = "AUTH-ADMIN-GRANTED"
    title = "Account given administrator rights"
    severity = Severity.HIGH
    technique = "T1098"
    tactic = "Persistence"
    description = ("An account was added to a group that grants administrator rights. "
                   "This is how an intruder turns a foothold into full control.")
    event_types = (EventType.ACCOUNT_PRIVILEGED,)

    def evaluate(self, event: Event, context: DetectionContext):
        if not isinstance(event, AuthEvent):
            return None
        group = event.group or "an administrator group"
        by = f" by {event.actor}" if event.actor else ""
        return self.make_finding(
            score=80 if is_admin_group(event.group) else 60,
            reasons=[f"'{event.user}' was added to {group}{by}",
                     "Remove the account from the group if you did not do this"],
            entity=f"account:{event.user}",
            source_summary=event.summary())


class AccountLockoutRule(DetectionRule):
    rule_id = "AUTH-LOCKOUT"
    title = "Account locked out"
    severity = Severity.MEDIUM
    technique = "T1110"
    tactic = "Credential Access"
    description = ("Windows locked an account after too many wrong passwords. Either "
                   "someone forgot theirs, or something is guessing.")
    event_types = (EventType.ACCOUNT_LOCKED,)

    def evaluate(self, event: Event, context: DetectionContext):
        if not isinstance(event, AuthEvent):
            return None
        return self.make_finding(
            score=50,
            reasons=[f"Account '{event.user}' was locked out after repeated wrong passwords"
                     + (f", attempts came from {event.source_ip}" if event.source_ip else "")],
            entity=f"account:{event.user}",
            source_summary=event.summary())


AUTH_RULES = [
    PasswordGuessingRule(),
    PasswordSprayRule(),
    SuccessAfterFailuresRule(),
    NewAccountRule(),
    AdminRightsGrantedRule(),
    AccountLockoutRule(),
]
