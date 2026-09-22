"""Runs fixes with the same safeguards every time.

    detect → explain → recommend → confirm → back up → apply → verify → record

The order is fixed here rather than left to each fix:

* nothing changes without ``confirmed=True``, which only a person's explicit
  choice (a dialog button, a typed "y", or ``--yes``) should set;
* changes that need administrator or root rights are refused up front instead
  of failing half-way;
* the current settings are saved *before* anything changes, and a fix that fails
  part-way is rolled back from that backup;
* success is not assumed: the settings are read again afterwards, and the
  outcome says whether the change was verified;
* every attempt, including refusals after confirmation and failures, is kept in
  the remediation history and the audit trail.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum

from aegis.core.models import AuditEvent, Remediation, Severity
from aegis.hardening.base import Change, Fix, HardeningContext, HardeningError
from aegis.hardening.fixes import default_fixes
from aegis.posture.base import CheckResult, CheckStatus, PostureCheck, PostureReport
from aegis.posture.checks import default_checks
from aegis.storage.database import SQLiteEventStore

log = logging.getLogger(__name__)


class Outcome(StrEnum):
    PREVIEW = "preview"                        # what would change; nothing changed
    NEEDS_CONFIRMATION = "needs_confirmation"  # refused: the person has not confirmed
    NEEDS_ADMIN = "needs_admin"                # refused: missing privileges
    NOTHING_TO_DO = "nothing_to_do"            # the setting is already safe
    FIXED = "fixed"                            # applied and verified
    NOT_VERIFIED = "not_verified"              # applied, but a re-read still shows a problem
    FAILED = "failed"                          # could not apply; rolled back where possible
    UNDONE = "undone"                          # a previous fix was reversed


@dataclass
class HardeningResult:
    fix_id: str
    title: str
    outcome: Outcome
    message: str
    changes: list[Change] = field(default_factory=list)
    record_id: int | None = None
    #: The security check's status after the change ("pass", "warn", ...), if re-run.
    check_status: str = ""

    @property
    def ok(self) -> bool:
        return self.outcome in (Outcome.FIXED, Outcome.UNDONE, Outcome.NOTHING_TO_DO,
                                Outcome.PREVIEW)

    def to_dict(self) -> dict:
        return {"fix_id": self.fix_id, "title": self.title, "outcome": self.outcome.value,
                "message": self.message, "changes": [c.to_dict() for c in self.changes],
                "record_id": self.record_id, "check_status": self.check_status}


@dataclass
class Recommendation:
    """A weakness from the security check and what can be done about it."""

    check: CheckResult
    #: Automatic fixes that still have something to change, with their changes.
    fixes: list[tuple[Fix, list[Change]]]
    #: The check's written advice, always available as the manual route.
    guidance: str


class HardeningEngine:
    def __init__(self, store: SQLiteEventStore, ctx: HardeningContext | None = None,
                 fixes: list[Fix] | None = None, checks: list[PostureCheck] | None = None):
        self.store = store
        self.ctx = ctx or HardeningContext()
        self.fixes = [f for f in (fixes if fixes is not None else default_fixes())
                      if f.applies(self.ctx)]
        self._checks = {c.check_id: c for c in
                        (checks if checks is not None else default_checks())}

    # -- recommend ---------------------------------------------------------- #
    def fix(self, fix_id: str) -> Fix | None:
        return next((f for f in self.fixes if f.fix_id == fix_id), None)

    def recommendations(self, report: PostureReport) -> list[Recommendation]:
        """For every failed or warning check: the fixes that apply, and the guidance."""
        out = []
        for result in report.results:
            if result.status not in (CheckStatus.FAIL, CheckStatus.WARN):
                continue
            ready = []
            for candidate in self.fixes:
                if candidate.check_id != result.check_id:
                    continue
                try:
                    changes = candidate.plan(self.ctx)
                except (HardeningError, OSError) as exc:
                    log.info("Fix %s cannot plan: %s", candidate.fix_id, exc)
                    continue
                if changes:
                    ready.append((candidate, changes))
            out.append(Recommendation(result, ready, result.remediation))
        return out

    # -- apply -------------------------------------------------------------- #
    def preview(self, fix_id: str) -> HardeningResult:
        fix = self._require(fix_id)
        try:
            changes = fix.plan(self.ctx)
        except (HardeningError, OSError) as exc:
            return HardeningResult(fix.fix_id, fix.title, Outcome.FAILED, str(exc))
        if not changes:
            return HardeningResult(fix.fix_id, fix.title, Outcome.NOTHING_TO_DO,
                                   "This setting is already safe.")
        return HardeningResult(fix.fix_id, fix.title, Outcome.PREVIEW,
                               "Nothing has been changed.", changes)

    def apply(self, fix_id: str, *, confirmed: bool = False) -> HardeningResult:
        fix = self._require(fix_id)
        planned = self.preview(fix_id)
        if planned.outcome is not Outcome.PREVIEW:
            return planned
        changes = planned.changes
        if not confirmed:
            return HardeningResult(fix.fix_id, fix.title, Outcome.NEEDS_CONFIRMATION,
                                   "Review the changes and confirm to apply them.", changes)
        if fix.requires_admin and not self.ctx.elevated:
            return self._record(fix, "apply", Outcome.NEEDS_ADMIN, changes, {},
                                "This change needs administrator (or root) rights. "
                                "Restart Aegis elevated and try again.")

        try:
            backup = fix.snapshot(self.ctx)
        except (HardeningError, OSError) as exc:
            return self._record(fix, "apply", Outcome.FAILED, changes, {},
                                f"Nothing was changed: could not save the current settings "
                                f"({exc}).")

        try:
            note = fix.apply(self.ctx)
        except Exception as exc:  # noqa: BLE001 - any failure must trigger the rollback
            log.exception("Fix %s failed", fix.fix_id)
            return self._record(fix, "apply", Outcome.FAILED, changes, backup,
                                f"The change failed: {exc}. {self._rollback(fix, backup)}")

        remaining = self._replan(fix)
        if remaining:
            outcome = Outcome.NOT_VERIFIED
            message = ("The change was made, but the setting still reads as unsafe: "
                       + "; ".join(f"{c.setting} is {c.current}" for c in remaining)
                       + ". You can undo it from the history.")
        else:
            outcome = Outcome.FIXED
            message = "Fixed and verified."
        if note:
            message = f"{message} {note}"
        return self._record(fix, "apply", outcome, changes, backup, message)

    def undo(self, record_id: int, *, confirmed: bool = False) -> HardeningResult:
        record = self.store.remediation(record_id)
        if record is None:
            raise ValueError(f"No hardening record #{record_id}.")
        fix = self._require(record.fix_id)
        changes = [Change(c["setting"], c["target"], c["current"]) for c in record.changes]
        if not record.can_undo:
            return HardeningResult(fix.fix_id, fix.title, Outcome.FAILED,
                                   f"Record #{record_id} cannot be undone "
                                   f"({'already undone' if record.undone_at else record.status}).")
        if not confirmed:
            return HardeningResult(fix.fix_id, fix.title, Outcome.NEEDS_CONFIRMATION,
                                   "Confirm to put the previous settings back.", changes)
        if fix.requires_admin and not self.ctx.elevated:
            return HardeningResult(fix.fix_id, fix.title, Outcome.NEEDS_ADMIN,
                                   "Undoing this change needs administrator (or root) rights.")
        try:
            note = fix.restore(self.ctx, record.backup)
        except Exception as exc:  # noqa: BLE001
            log.exception("Undo of %s failed", fix.fix_id)
            return self._record(fix, "undo", Outcome.FAILED, changes, {},
                                f"Could not undo the change: {exc}", undo_of=record_id)
        self.store.mark_remediation_undone(record_id, datetime.now())
        message = "The previous settings were put back."
        if not fix.reversible:
            message += " Some parts of this fix cannot be restored (see its description)."
        if note:
            message = f"{message} {note}"
        return self._record(fix, "undo", Outcome.UNDONE, changes, {}, message,
                            undo_of=record_id)

    def history(self, limit: int = 100) -> list[Remediation]:
        return self.store.recent_remediations(limit)

    # -- helpers ------------------------------------------------------------ #
    def _require(self, fix_id: str) -> Fix:
        fix = self.fix(fix_id)
        if fix is None:
            raise ValueError(f"Unknown fix {fix_id!r} (or it does not apply to this computer).")
        return fix

    def _replan(self, fix: Fix) -> list[Change]:
        try:
            return fix.plan(self.ctx)
        except (HardeningError, OSError) as exc:
            return [Change(fix.title, f"unreadable ({exc})", "verified")]

    def _rollback(self, fix: Fix, backup: dict) -> str:
        try:
            fix.restore(self.ctx, backup)
        except Exception as exc:  # noqa: BLE001
            log.exception("Rollback of %s failed", fix.fix_id)
            return f"Rolling back also failed ({exc}); check the setting by hand."
        return "The previous settings were restored."

    def _check_status(self, check_id: str) -> str:
        check = self._checks.get(check_id)
        if check is None or not check.applies(self.ctx):
            return ""
        try:
            return check.run(self.ctx).status.value
        except Exception:  # noqa: BLE001
            log.exception("Re-running %s failed", check_id)
            return ""

    def _record(self, fix: Fix, action: str, outcome: Outcome, changes: list[Change],
                backup: dict, message: str, undo_of: int | None = None) -> HardeningResult:
        check_status = (self._check_status(fix.check_id)
                        if outcome in (Outcome.FIXED, Outcome.NOT_VERIFIED, Outcome.UNDONE)
                        else "")
        record_id = self.store.save_remediation(Remediation(
            fix_id=fix.fix_id, check_id=fix.check_id, title=fix.title, action=action,
            status=outcome.value, message=message, changes=[c.to_dict() for c in changes],
            backup=backup, undo_of=undo_of))
        severity = (Severity.INFO if outcome in (Outcome.FIXED, Outcome.UNDONE)
                    else Severity.MEDIUM)
        verb = "fix" if action == "apply" else "undo"
        self.store.add_audit(AuditEvent(
            category="HARDENING", action=f"{verb}_{outcome.value}", severity=severity,
            message=f"{fix.title}: {message}",
            detail="; ".join(f"{c.setting}: {c.current} -> {c.target}" for c in changes)))
        return HardeningResult(fix.fix_id, fix.title, outcome, message, changes, record_id,
                               check_status)
