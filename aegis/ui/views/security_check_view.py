"""Security check view: posture score with fixes, plus threat-intel status."""
from __future__ import annotations

import logging

import flet as ft

from aegis.config import settings
from aegis.intel import get_intel, intel_dir, reset_cache
from aegis.posture import CheckStatus, run_posture_checks
from aegis.ui import components as c
from aegis.ui import theme
from aegis.ui.views.base import BaseView

log = logging.getLogger(__name__)

_STATUS = {
    CheckStatus.FAIL: (ft.Icons.CANCEL, theme.DANGER, "FAIL"),
    CheckStatus.WARN: (ft.Icons.WARNING_AMBER_ROUNDED, theme.WARN, "WARN"),
    CheckStatus.PASS: (ft.Icons.CHECK_CIRCLE, theme.OK, "PASS"),
    CheckStatus.SKIP: (ft.Icons.REMOVE_CIRCLE_OUTLINE, theme.TEXT_MUTED, "SKIP"),
}
_ORDER = {CheckStatus.FAIL: 0, CheckStatus.WARN: 1, CheckStatus.PASS: 2, CheckStatus.SKIP: 3}


class SecurityCheckView(BaseView):
    title = "Security Check"
    icon = ft.Icons.HEALTH_AND_SAFETY_OUTLINED

    def build(self) -> ft.Control:
        self._report = None
        self._checking = False
        self._updating_intel = False

        self.score = ft.Text("-", size=40, weight=ft.FontWeight.BOLD, color=theme.TEXT)
        self.grade = ft.Text("Not run yet", size=13, color=theme.TEXT_MUTED)
        self.counts = ft.Text("", size=12, color=theme.TEXT_MUTED)
        self.check_progress = ft.ProgressRing(width=18, height=18, stroke_width=2, visible=False)
        self.run_btn = ft.FilledButton("Run check", icon=ft.Icons.REFRESH, on_click=self._run_check)
        score_panel = c.panel(ft.Row([
            ft.Column([ft.Text("Security score", size=12, color=theme.TEXT_MUTED),
                       self.score, self.grade], spacing=2, tight=True),
            ft.Container(expand=True),
            ft.Column([self.counts, ft.Row([self.check_progress, self.run_btn], spacing=10)],
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

        self.results = ft.ListView(spacing=8, expand=True, padding=4)
        self.results.controls = [c.empty_state("Running the security check...",
                                               ft.Icons.HEALTH_AND_SAFETY_OUTLINED)]
        return ft.Column([
            ft.Row([score_panel, intel_panel], spacing=16),
            ft.Text("Read-only checks of settings that make this machine easier to attack. "
                    "Nothing is changed.", size=12, color=theme.TEXT_MUTED),
            c.panel(self.results, padding=6, expand=True),
        ], spacing=12, expand=True)

    def refresh(self) -> None:
        self._show_intel()
        if self._report is None and not self._checking:
            self._run_check()
        else:
            self.safe_update()

    # -- security check ----------------------------------------------------- #
    def _run_check(self, e=None) -> None:
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
            self._render(report)
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

    @staticmethod
    def _row(result) -> ft.Control:
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
        return ft.Container(
            content=ft.Column(lines, spacing=4, tight=True),
            padding=ft.Padding.symmetric(horizontal=14, vertical=12),
            bgcolor=theme.SURFACE_ALT, border_radius=10, border=ft.Border.all(1, theme.BORDER))

    # -- threat intel ------------------------------------------------------- #
    def _show_intel(self) -> None:
        intel = get_intel()
        if len(intel):
            self.intel_count.value = f"{len(intel):,} known-malicious addresses loaded"
            detail = ", ".join(f"{name} ({count:,})" for name, count in sorted(intel.sources.items()))
        else:
            self.intel_count.value = "No blocklists loaded"
            detail = "Download free public lists to catch connections to known attacker servers."
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
