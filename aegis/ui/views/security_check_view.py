"""Security check view: posture score, one-click hardening with undo, threat intel."""
from __future__ import annotations

import logging
import threading

import flet as ft

from aegis.config import settings
from aegis.elevate import can_elevate, restart_as_admin
from aegis.intel import get_intel, intel_dir, reset_cache
from aegis.posture import CheckStatus, run_posture_checks
from aegis.posture.base import PostureReport
from aegis.ui import components as c
from aegis.ui import theme
from aegis.ui.views.base import BaseView

log = logging.getLogger(__name__)


class SimpleResult:
    """What ``_run_fix`` needs from a result: did it work, and what to say."""

    def __init__(self, ok: bool, message: str, title: str):
        self.ok, self.message, self.title = ok, message, title

_STATUS = {
    CheckStatus.FAIL: (ft.Icons.CANCEL, theme.DANGER, "FAIL"),
    CheckStatus.WARN: (ft.Icons.WARNING_AMBER_ROUNDED, theme.WARN, "WARN"),
    CheckStatus.PASS: (ft.Icons.CHECK_CIRCLE, theme.OK, "PASS"),
    CheckStatus.SKIP: (ft.Icons.REMOVE_CIRCLE_OUTLINE, theme.TEXT_MUTED, "SKIP"),
}
_ORDER = {CheckStatus.FAIL: 0, CheckStatus.WARN: 1, CheckStatus.PASS: 2, CheckStatus.SKIP: 3}
_OUTCOME_COLOR = {
    "fixed": theme.OK, "undone": theme.INFO, "not_verified": theme.WARN,
    "failed": theme.DANGER, "needs_admin": theme.DANGER,
}
_OUTCOME_LABEL = {
    "fixed": "FIXED", "undone": "UNDONE", "not_verified": "NOT VERIFIED",
    "failed": "FAILED", "needs_admin": "NEEDS ADMIN",
}


class SecurityCheckView(BaseView):
    title = "Security Check"
    icon = ft.Icons.HEALTH_AND_SAFETY_OUTLINED

    def build(self) -> ft.Control:
        self._report: PostureReport | None = None
        self._fixes: dict[str, list] = {}
        self._routine: list = []
        self._checking = False
        self._fixing = False
        self._updating_intel = False
        self._checking_vulns = False
        self._stop_vulns = threading.Event()

        self.score = ft.Text("-", size=40, weight=ft.FontWeight.BOLD, color=theme.TEXT)
        self.grade = ft.Text("Not run yet", size=13, color=theme.TEXT_MUTED)
        self.counts = ft.Text("", size=12, color=theme.TEXT_MUTED)
        self.check_progress = ft.ProgressRing(width=18, height=18, stroke_width=2, visible=False)
        self.run_btn = ft.FilledButton("Run check", icon=ft.Icons.REFRESH, on_click=self.run_check)
        self.fix_all_btn = ft.FilledButton("Fix the safe ones", icon=ft.Icons.AUTO_FIX_HIGH,
                                           visible=False, on_click=self._confirm_fix_all)
        self.admin_banner = self._admin_banner()
        score_panel = c.panel(ft.Row([
            ft.Column([ft.Text("Security score", size=12, color=theme.TEXT_MUTED),
                       self.score, self.grade], spacing=2, tight=True),
            ft.Container(expand=True),
            ft.Column([self.counts, ft.Row([self.check_progress, self.fix_all_btn,
                                            self.run_btn], spacing=10)],
                      horizontal_alignment=ft.CrossAxisAlignment.END, spacing=8, tight=True),
        ], vertical_alignment=ft.CrossAxisAlignment.CENTER), expand=True)

        self.intel_count = ft.Text("-", size=14, color=theme.TEXT, weight=ft.FontWeight.W_600)
        self.intel_sources = ft.Text("", size=11, color=theme.TEXT_MUTED)
        self.intel_progress = ft.ProgressRing(width=18, height=18, stroke_width=2, visible=False)
        self.intel_btn = ft.OutlinedButton("Update blocklists", icon=ft.Icons.DOWNLOAD,
                                           on_click=self._update_intel)
        intel_panel = c.panel(ft.Row([
            ft.Icon(ft.Icons.PUBLIC, color=theme.PRIMARY, size=28),
            ft.Column([ft.Text("Threat intelligence", size=12, color=theme.TEXT_MUTED),
                       self.intel_count, self.intel_sources], spacing=2, tight=True, expand=True),
            self.intel_progress, self.intel_btn,
        ], spacing=12, vertical_alignment=ft.CrossAxisAlignment.CENTER), expand=True)

        self.vuln_count = ft.Text("-", size=14, color=theme.TEXT, weight=ft.FontWeight.W_600)
        self.vuln_detail = ft.Text("", size=11, color=theme.TEXT_MUTED)
        self.vuln_progress = ft.ProgressRing(width=18, height=18, stroke_width=2,
                                             visible=False)
        self.vuln_btn = ft.OutlinedButton("Check installed programs",
                                          icon=ft.Icons.INVENTORY_2_OUTLINED,
                                          on_click=self._confirm_vuln_check)
        self.vuln_stop_btn = ft.TextButton("Stop", icon=ft.Icons.STOP_CIRCLE_OUTLINED,
                                           visible=False, on_click=self._stop_vuln_check)
        vuln_panel = c.panel(ft.Row([
            ft.Icon(ft.Icons.INVENTORY_2_OUTLINED, color=theme.PRIMARY, size=28),
            ft.Column([ft.Text("Installed programs", size=12, color=theme.TEXT_MUTED),
                       self.vuln_count, self.vuln_detail],
                      spacing=2, tight=True, expand=True),
            self.vuln_progress, self.vuln_stop_btn, self.vuln_btn,
        ], spacing=12, vertical_alignment=ft.CrossAxisAlignment.CENTER))

        self.results = ft.ListView(spacing=8, expand=True, padding=4)
        self.results.controls = [c.empty_state("Running the security check...",
                                               ft.Icons.HEALTH_AND_SAFETY_OUTLINED)]
        self.history = ft.ListView(spacing=6, height=120, padding=4)
        return ft.Column([
            ft.Row([score_panel, intel_panel], spacing=16),
            ft.Text("The check only reads settings. A fix changes a setting only after you "
                    "confirm, is verified afterwards, and can be undone below.",
                    size=12, color=theme.TEXT_MUTED),
            self.admin_banner,
            vuln_panel,
            c.panel(self.results, padding=6, expand=True),
            c.panel(ft.Column([c.section_title("Fix history", ft.Icons.HISTORY), self.history],
                              spacing=6, tight=True), padding=10),
        ], spacing=12, expand=True)

    def refresh(self) -> None:
        self._show_intel()
        self._show_vulns()
        self._show_history()
        if self._report is None and not self._checking:
            self.run_check()
        else:
            self.safe_update()

    # -- security check ----------------------------------------------------- #
    def run_check(self, e=None) -> None:
        if self._checking:
            return
        self._set_checking(True)
        # Checks shell out (PowerShell, netsh) and take seconds; keep the UI responsive.
        self.page.run_thread(self._check_worker)

    def _check_worker(self) -> None:
        try:
            report = run_posture_checks()
        except Exception:  # noqa: BLE001 - surface failure instead of freezing the view
            log.exception("Security check failed")
            self.app.toast("The security check could not run.", ok=False)
        else:
            self._report = report
            try:
                recommendations = self.service.hardening.recommendations(report)
            except Exception:  # noqa: BLE001 - fixes are optional; the report still shows
                log.exception("Could not work out the available fixes")
                recommendations = []
            self._fixes = {rec.check.check_id: rec.fixes for rec in recommendations}
            self._routine = self.service.hardening.routine_fixes(report)
            self.fix_all_btn.visible = bool(self._routine)
            self.fix_all_btn.content = (f"Fix the safe ones ({len(self._routine)})"
                                        if self._routine else "Fix the safe ones")
            self._render(report)
            self.app.posture_updated(report)
        finally:
            self._set_checking(False)

    def _set_checking(self, busy: bool) -> None:
        self._checking = busy
        self.check_progress.visible = busy
        self.run_btn.disabled = busy
        self.safe_update()

    def _render(self, report) -> None:
        if report.evaluated:
            self.score.value = str(report.score)
            self.score.color = (theme.OK if report.score >= 90
                                else theme.WARN if report.score >= 70 else theme.DANGER)
            self.grade.value = f"Grade {report.grade}"
        else:
            self.score.value = "-"
            self.score.color = theme.TEXT
            self.grade.value = "No checks could run on this machine"
        self.counts.value = " | ".join([
            f"{report.count(CheckStatus.FAIL)} failed",
            f"{report.count(CheckStatus.WARN)} warnings",
            f"{report.count(CheckStatus.PASS)} passed",
            f"{report.count(CheckStatus.SKIP)} skipped",
        ])
        ordered = sorted(report.results, key=lambda r: (_ORDER[r.status], -r.severity.rank))
        self.results.controls = [self._row(r) for r in ordered] or [
            c.empty_state("No checks apply to this platform.")]

    def _row(self, result) -> ft.Control:
        icon, color, label = _STATUS[result.status]
        lines: list[ft.Control] = [
            ft.Row([
                ft.Icon(icon, color=color, size=20),
                ft.Text(result.title, size=14, color=theme.TEXT, weight=ft.FontWeight.W_600,
                        expand=True),
                c.pill(label, color),
                c.severity_badge(result.severity),
            ], spacing=8, vertical_alignment=ft.CrossAxisAlignment.CENTER),
            ft.Text(result.summary, size=12, color=theme.TEXT),
        ]
        lines.extend(ft.Text(f"- {detail}", size=11, color=theme.TEXT_MUTED, selectable=True)
                     for detail in result.details)
        if result.remediation:
            lines.append(ft.Container(
                ft.Text(f"How to fix: {result.remediation}", size=12, color=theme.TEXT,
                        selectable=True),
                bgcolor=ft.Colors.with_opacity(0.12, color), border_radius=8,
                padding=ft.Padding.symmetric(horizontal=10, vertical=8)))
        buttons: list[ft.Control] = [
            ft.OutlinedButton(fix.title, icon=ft.Icons.BUILD_OUTLINED,
                              on_click=lambda e, f=fix, ch=changes: self._confirm_fix(f, ch))
            for fix, changes in self._fixes.get(result.check_id, [])]
        if buttons:
            lines.append(ft.Row(buttons, spacing=8, wrap=True))
        return ft.Container(
            content=ft.Column(lines, spacing=4, tight=True),
            padding=ft.Padding.symmetric(horizontal=14, vertical=12),
            bgcolor=theme.SURFACE_ALT, border_radius=10, border=ft.Border.all(1, theme.BORDER))

    # -- hardening ---------------------------------------------------------- #
    def _confirm_fix(self, fix, changes) -> None:
        elevated = self.service.hardening.ctx.elevated
        body: list[ft.Control] = [
            ft.Text("Why this matters", size=12, color=theme.TEXT_MUTED),
            ft.Text(fix.risk, size=13, color=theme.TEXT),
            ft.Text("What will change", size=12, color=theme.TEXT_MUTED),
            *(ft.Text(f"{ch.setting}\n    {ch.current}  ->  {ch.target}", size=12,
                      color=theme.TEXT, selectable=True) for ch in changes),
            ft.Text("Afterwards", size=12, color=theme.TEXT_MUTED),
            ft.Text(fix.effect, size=13, color=theme.TEXT),
        ]
        if fix.restart_note:
            body.append(ft.Text(fix.restart_note, size=12, color=theme.WARN))
        body.append(ft.Text(
            "The current settings are saved first, so you can undo this from Fix history."
            if fix.reversible else
            "Undo is available, but part of this change cannot be restored (see above).",
            size=12, color=theme.TEXT_MUTED))
        if fix.requires_admin and not elevated:
            body.append(ft.Text("This change needs administrator rights. Restart Aegis as "
                                "administrator to apply it.", size=12, color=theme.DANGER))

        def apply(e):
            self.page.pop_dialog()
            self._run_fix(lambda: self.service.hardening.apply(fix.fix_id, confirmed=True))

        self.page.show_dialog(ft.AlertDialog(
            modal=True, title=ft.Text(fix.title),
            content=ft.Container(ft.Column(body, spacing=6, tight=True,
                                           scroll=ft.ScrollMode.AUTO), width=520),
            actions=[ft.TextButton("Cancel", on_click=lambda e: self.page.pop_dialog()),
                     ft.FilledButton("Apply fix", icon=ft.Icons.BUILD,
                                     disabled=fix.requires_admin and not elevated,
                                     on_click=apply)]))

    def _admin_banner(self) -> ft.Control:
        """Offered only when a restart would actually change what Aegis can do."""
        if not can_elevate():
            return ft.Container(height=0)
        return ft.Container(
            content=ft.Row([
                ft.Icon(ft.Icons.ADMIN_PANEL_SETTINGS_OUTLINED, color=theme.WARN, size=20),
                ft.Text("Some checks and fixes need administrator rights. Aegis works "
                        "without them, but cannot change firewall settings or read "
                        "sign-in history.", size=12, color=theme.TEXT, expand=True),
                ft.FilledButton("Restart as administrator", icon=ft.Icons.SHIELD_OUTLINED,
                                on_click=self._restart_as_admin),
            ], spacing=10, vertical_alignment=ft.CrossAxisAlignment.CENTER),
            padding=ft.Padding.symmetric(horizontal=14, vertical=10),
            bgcolor=ft.Colors.with_opacity(0.12, theme.WARN), border_radius=8,
            border=ft.Border.all(1, ft.Colors.with_opacity(0.4, theme.WARN)))

    def _restart_as_admin(self, e=None) -> None:
        """Ask Windows to start Aegis again with administrator rights."""
        result = restart_as_admin(confirmed=True)
        self.app.toast(result.message, ok=result.ok)
        if result.restarting:
            self.app.close_for_restart()

    def _confirm_fix_all(self, e=None) -> None:
        """Show every routine fix, then apply them all on one confirmation."""
        if not self._routine:
            return
        lines: list[ft.Control] = [
            ft.Text(f"{len(self._routine)} weaknesses can be fixed safely. Each one is "
                    f"applied, checked, and can be undone from Fix history.", size=13,
                    color=theme.TEXT),
        ]
        for fix, changes in self._routine:
            lines.append(ft.Text(fix.title, size=13, color=theme.TEXT,
                                 weight=ft.FontWeight.W_600))
            lines.extend(ft.Text(f"    {c.setting}: {c.current}  ->  {c.target}", size=11,
                                 color=theme.TEXT_MUTED, selectable=True) for c in changes)
        lines.append(ft.Text("Anything that could lock you out of this computer is not "
                             "included here; those are offered one at a time.", size=12,
                             color=theme.TEXT_MUTED))

        def apply(e):
            self.page.pop_dialog()
            self._run_fix(self._apply_routine)

        self.page.show_dialog(ft.AlertDialog(
            modal=True, title=ft.Text("Fix the safe ones?"),
            content=ft.Container(ft.Column(lines, spacing=6, tight=True,
                                           scroll=ft.ScrollMode.AUTO), width=560),
            actions=[ft.TextButton("Cancel", on_click=lambda e: self.page.pop_dialog()),
                     ft.FilledButton("Fix them", icon=ft.Icons.AUTO_FIX_HIGH,
                                     on_click=apply)]))

    def _apply_routine(self):
        """Apply every routine fix and sum the outcome up in one sentence."""
        from aegis.hardening import Outcome

        results = self.service.hardening.apply_routine(self._report, confirmed=True)
        fixed = sum(1 for r in results if r.outcome is Outcome.FIXED)
        if not results:
            return SimpleResult(True, "Nothing needed fixing.", "Security check")
        if fixed == len(results):
            return SimpleResult(True, f"Fixed {fixed} of {len(results)}. Undo any of them "
                                      f"in Fix history.", "Security check")
        failed = next(r for r in results if r.outcome is not Outcome.FIXED)
        return SimpleResult(False, f"Fixed {fixed} of {len(results)}. {failed.title}: "
                                   f"{failed.message}", "Security check")

    def _confirm_undo(self, record) -> None:
        def undo(e):
            self.page.pop_dialog()
            self._run_fix(lambda: self.service.hardening.undo(record.id, confirmed=True))

        lines = [ft.Text(f"{ch['setting']}\n    {ch['target']}  ->  {ch['current']}", size=12,
                         color=theme.TEXT, selectable=True) for ch in record.changes]
        fix = self.service.hardening.fix(record.fix_id)
        blocked = bool(fix and fix.requires_admin and not self.service.hardening.ctx.elevated)
        if blocked:
            lines.append(ft.Text("Undoing this needs administrator rights. Restart Aegis as "
                                 "administrator to undo it.", size=12, color=theme.DANGER))
        self.page.show_dialog(ft.AlertDialog(
            modal=True, title=ft.Text(f"Undo: {record.title}?"),
            content=ft.Container(ft.Column(
                [ft.Text("The settings from before the fix will be put back:", size=13,
                         color=theme.TEXT), *lines], spacing=6, tight=True), width=520),
            actions=[ft.TextButton("Cancel", on_click=lambda e: self.page.pop_dialog()),
                     ft.FilledButton("Undo", icon=ft.Icons.UNDO, disabled=blocked,
                                     on_click=undo)]))

    def _run_fix(self, action) -> None:
        if self._fixing:
            return
        self._fixing = True

        def worker():
            try:
                result = action()
                self.app.toast(f"{result.title}: {result.message}", ok=result.ok)
            except Exception:  # noqa: BLE001
                log.exception("Hardening action failed")
                self.app.toast("The change could not be made.", ok=False)
            finally:
                self._fixing = False
                self._show_history()
                self.run_check()

        self.page.run_thread(worker)

    def _show_history(self) -> None:
        try:
            records = self.service.hardening.history(30)
        except Exception:  # noqa: BLE001
            log.exception("Could not read the fix history")
            records = []
        self.history.controls = [self._history_row(r) for r in records] or [
            ft.Text("No fixes applied yet.", size=12, color=theme.TEXT_MUTED)]
        self.safe_update()

    def _history_row(self, record) -> ft.Control:
        color = _OUTCOME_COLOR.get(record.status, theme.TEXT_MUTED)
        label = _OUTCOME_LABEL.get(record.status, record.status.upper())
        what = record.title if record.action == "apply" else f"Undo: {record.title}"
        if record.undone_at:
            what += " (undone)"
        row: list[ft.Control] = [
            ft.Text(record.timestamp.strftime("%d %b %H:%M"), size=11, color=theme.TEXT_MUTED,
                    width=90),
            c.pill(label, color),
            ft.Column([ft.Text(what, size=12, color=theme.TEXT, weight=ft.FontWeight.W_600),
                       ft.Text(record.message, size=11, color=theme.TEXT_MUTED)],
                      spacing=1, tight=True, expand=True),
        ]
        if record.can_undo:
            row.append(ft.TextButton("Undo", icon=ft.Icons.UNDO,
                                     on_click=lambda e, r=record: self._confirm_undo(r)))
        return ft.Row(row, spacing=10, vertical_alignment=ft.CrossAxisAlignment.CENTER)

    # -- threat intel ------------------------------------------------------- #
    def _show_intel(self) -> None:
        intel = get_intel()
        if len(intel):
            self.intel_count.value = (f"{len(intel):,} known-malicious addresses "
                                      f"and domains loaded")
            detail = ", ".join(f"{name} ({count:,})" for name, count in sorted(intel.sources.items()))
        else:
            self.intel_count.value = "No blocklists loaded"
            detail = ("Download free public lists to catch connections to, and lookups "
                      "of, known attacker servers.")
        if not settings.threat_intel_enabled:
            detail += "  (matching is turned off in Settings)"
        self.intel_sources.value = detail

    def _update_intel(self, e=None) -> None:
        if self._updating_intel:
            return
        self._set_updating(True)
        self.page.run_thread(self._intel_worker)

    def _intel_worker(self) -> None:
        from aegis.intel.feeds import update_feeds

        try:
            results = update_feeds(intel_dir())
            reset_cache()
            succeeded = sum(1 for r in results if r.ok)
            self.app.toast(f"Updated {succeeded} of {len(results)} blocklists.",
                           ok=succeeded > 0)
            self._show_intel()
        except Exception:  # noqa: BLE001
            log.exception("Blocklist update failed")
            self.app.toast("Could not update blocklists.", ok=False)
        finally:
            self._set_updating(False)

    def _set_updating(self, busy: bool) -> None:
        self._updating_intel = busy
        self.intel_progress.visible = busy
        self.intel_btn.disabled = busy
        self.safe_update()

    # -- known vulnerabilities in installed programs ------------------------ #
    def _show_vulns(self) -> None:
        """Summarise what the last lookup found, without asking anything."""
        from aegis.intel.vulns import VulnerabilityCache

        reports = VulnerabilityCache.read().reports()
        vulnerable = [r for r in reports if r.vulnerabilities]
        if not reports:
            self.vuln_count.value = "Not checked yet"
            self.vuln_detail.value = ("Unpatched programs are how most computers are "
                                      "broken into. Aegis can ask the public "
                                      "vulnerability database about the versions "
                                      "installed here.")
        elif vulnerable:
            total = sum(len(r.vulnerabilities) for r in vulnerable)
            self.vuln_count.value = (f"{len(vulnerable)} program(s) with known "
                                     f"vulnerabilities ({total} in total)")
            self.vuln_detail.value = ", ".join(
                f"{r.name} {r.version} ({r.worst.lower()})" for r in vulnerable[:4])
        else:
            checked = sum(1 for r in reports if r.matched)
            self.vuln_count.value = f"Nothing known against {checked} program(s)"
            self.vuln_detail.value = (f"{len(reports) - checked} program(s) are not in "
                                      f"the database, so they could not be checked.")

    def _confirm_vuln_check(self, e=None) -> None:
        """Explain exactly what is sent and how long it takes, then ask."""
        from aegis.intel.vulns import API_KEY_ENV, api_key
        from aegis.software import installed_programs, is_interesting

        try:
            programs = [p for p in installed_programs() if is_interesting(p)]
        except Exception:  # noqa: BLE001 - reading the list must not break the view
            log.exception("Could not list the installed programs")
            self.app.toast("Could not read the list of installed programs.", ok=False)
            return
        if not programs:
            self.app.toast("No installed programs with a version number were found.",
                           ok=False)
            return

        minutes = max(1, round(len(programs) * 2 * (0.7 if api_key() else 6.5) / 60))
        lines: list[ft.Control] = [
            ft.Text(f"{len(programs)} installed program(s) can be looked up in the "
                    f"National Vulnerability Database, the free public record run by "
                    f"the US government.", size=13, color=theme.TEXT),
            ft.Text("Only a program name and a version number are sent, over HTTPS. "
                    "No file contents, no identifiers, nothing about this computer.",
                    size=12, color=theme.TEXT_MUTED),
            ft.Text(f"The database allows only a few questions per minute, so this "
                    f"takes about {minutes} minute(s). You can keep using Aegis while "
                    f"it runs, and stop it at any time: answers already received are "
                    f"kept." + ("" if api_key() else
                                f" Setting {API_KEY_ENV} makes it much faster."),
                    size=12, color=theme.TEXT_MUTED),
        ]

        def start(e):
            self.page.pop_dialog()
            self._start_vuln_check(len(programs))

        self.page.show_dialog(ft.AlertDialog(
            modal=True, title=ft.Text("Check installed programs?"),
            content=ft.Container(ft.Column(lines, spacing=10, tight=True), width=520),
            actions=[ft.TextButton("Cancel", on_click=lambda e: self.page.pop_dialog()),
                     ft.FilledButton("Check them", icon=ft.Icons.INVENTORY_2_OUTLINED,
                                     on_click=start)]))

    def _start_vuln_check(self, total: int) -> None:
        if self._checking_vulns:
            return
        self._stop_vulns.clear()
        self._set_checking_vulns(True)
        self.vuln_count.value = f"Checking 0 of {total}..."
        self.vuln_detail.value = "Waiting for the database."
        self.safe_update()
        self.page.run_thread(lambda: self._vuln_worker(total))

    def _vuln_worker(self, total: int) -> None:
        from aegis.intel.vulns import NvdClient, VulnerabilityCache, refresh
        from aegis.software import installed_programs

        done = 0

        def progress(line: str) -> None:
            nonlocal done
            done += 1
            self.vuln_count.value = f"Checking {done} of {total}..."
            self.vuln_detail.value = line.strip()
            self.safe_update()

        cache = VulnerabilityCache.read()
        try:
            summary = refresh(installed_programs(), cache=cache, client=NvdClient(),
                              limit=total, progress=progress,
                              should_stop=self._stop_vulns.is_set)
            cache.save()
        except Exception:  # noqa: BLE001 - report instead of freezing the panel
            log.exception("Looking up installed programs failed")
            self.app.toast("Could not finish checking the installed programs.", ok=False)
        else:
            if summary.stopped:
                message = (f"Stopped. {summary.checked} program(s) were checked and "
                           f"their answers kept.")
            elif summary.failed:
                message = (f"Checked {summary.checked}; {summary.failed} could not reach "
                           f"the database. Run it again to retry those.")
            else:
                message = (f"Checked {summary.checked} program(s). "
                           f"{summary.vulnerable} have known vulnerabilities.")
            self.app.toast(message, ok=not summary.failed)
            self.run_check()        # the score includes this now, so re-run it
        finally:
            self._show_vulns()
            self._set_checking_vulns(False)

    def _stop_vuln_check(self, e=None) -> None:
        self._stop_vulns.set()
        self.vuln_detail.value = "Stopping after the current program..."
        self.safe_update()

    def _set_checking_vulns(self, busy: bool) -> None:
        self._checking_vulns = busy
        self.vuln_progress.visible = busy
        self.vuln_btn.disabled = busy
        self.vuln_stop_btn.visible = busy
        self.safe_update()
