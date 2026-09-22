"""Home: one answer to "is my computer safe?", then the details."""
from __future__ import annotations

import flet as ft

from aegis.intel import get_intel
from aegis.posture import CheckStatus
from aegis.ui import charts, theme
from aegis.ui import components as c
from aegis.ui.plain import plural, protection_status, time_ago
from aegis.ui.views.base import BaseView

_STATUS_STYLE = {
    "ok": (ft.Icons.VERIFIED_USER, theme.OK),
    "warn": (ft.Icons.GPP_MAYBE, theme.WARN),
    "danger": (ft.Icons.GPP_BAD, theme.DANGER),
    "paused": (ft.Icons.PAUSE_CIRCLE_OUTLINE, theme.WARN),
}


class DashboardView(BaseView):
    title = "Home"
    icon = ft.Icons.HOME_OUTLINED

    def build(self) -> ft.Control:
        self.status_icon = ft.Icon(ft.Icons.VERIFIED_USER, size=48, color=theme.OK)
        self.status_headline = ft.Text("Checking your computer...", size=24,
                                       weight=ft.FontWeight.BOLD, color=theme.TEXT)
        self.status_details = ft.Column(spacing=2, tight=True)
        self.status_action = ft.FilledButton("Run security check", visible=False)
        # The button sits under the text, not beside it, so the headline keeps the
        # full width and never collapses in a narrow window.
        self.status_card = ft.Container(
            content=ft.Row([
                self.status_icon,
                ft.Column([self.status_headline, self.status_details,
                           ft.Container(self.status_action, padding=ft.Padding.only(top=6))],
                          spacing=6, tight=True, expand=True),
            ], spacing=20, vertical_alignment=ft.CrossAxisAlignment.CENTER),
            padding=24, border_radius=14, bgcolor=theme.SURFACE,
            border=ft.Border.all(1, theme.BORDER))

        self.score_value, self.score_sub = self._value(), self._sub()
        self.alerts_value, self.alerts_sub = self._value(), self._sub()
        self.events_value, self.events_sub = self._value(), self._sub()
        self.intel_value, self.intel_sub = self._value(), self._sub()
        tiles = ft.Row([
            self._tile("Security score", self.score_value, self.score_sub,
                       ft.Icons.HEALTH_AND_SAFETY_OUTLINED, theme.PRIMARY, self._open_check),
            self._tile("Alerts to review", self.alerts_value, self.alerts_sub,
                       ft.Icons.NOTIFICATIONS_ACTIVE_OUTLINED, theme.DANGER, self._open_alerts),
            self._tile("Activity checked", self.events_value, self.events_sub,
                       ft.Icons.RADAR, theme.OK, None),
            self._tile("Attacker addresses", self.intel_value, self.intel_sub,
                       ft.Icons.PUBLIC, theme.WARN, self._open_check),
        ], spacing=16)

        self.severity_host = ft.Container(height=150)
        self.timeline_host = ft.Container(height=150)
        self.programs = ft.Column(spacing=8, tight=True)
        self.recent = ft.Column(spacing=8, tight=True)
        charts_row = ft.Row([
            c.panel(ft.Column([c.section_title("Alerts by severity", ft.Icons.PIE_CHART_OUTLINE),
                               self.severity_host], spacing=12), expand=True),
            c.panel(ft.Column([c.section_title("Alerts in the last 24 hours", ft.Icons.SHOW_CHART),
                               self.timeline_host], spacing=12), expand=True),
        ], spacing=16, vertical_alignment=ft.CrossAxisAlignment.START)
        lists_row = ft.Row([
            c.panel(ft.Column([c.section_title("Programs using the internet most", ft.Icons.APPS),
                               self.programs], spacing=12), expand=True),
            c.panel(ft.Column([
                ft.Row([c.section_title("Latest alerts", ft.Icons.NOTIFICATIONS_OUTLINED),
                        ft.Container(expand=True),
                        ft.TextButton("See all", on_click=self._open_alerts)]),
                self.recent], spacing=12), expand=True),
        ], spacing=16, vertical_alignment=ft.CrossAxisAlignment.START)
        return ft.Column([self.status_card, tiles, charts_row, lists_row], spacing=16,
                         scroll=ft.ScrollMode.AUTO, expand=True)

    # -- building blocks ---------------------------------------------------- #
    @staticmethod
    def _value() -> ft.Text:
        return ft.Text("-", size=26, weight=ft.FontWeight.BOLD, color=theme.TEXT)

    @staticmethod
    def _sub() -> ft.Text:
        return ft.Text("", size=11, color=theme.TEXT_MUTED)

    @staticmethod
    def _tile(title, value, sub, icon, color, on_click) -> ft.Container:
        return ft.Container(
            content=ft.Row([
                ft.Container(ft.Icon(icon, color=color, size=26),
                             bgcolor=ft.Colors.with_opacity(0.15, color), padding=12,
                             border_radius=10),
                ft.Column([ft.Text(title, size=12, color=theme.TEXT_MUTED), value, sub],
                          spacing=2, tight=True),
            ], spacing=14, vertical_alignment=ft.CrossAxisAlignment.CENTER),
            padding=18, bgcolor=theme.SURFACE, border=ft.Border.all(1, theme.BORDER),
            border_radius=12, expand=True, ink=on_click is not None,
            on_click=on_click, tooltip="Open" if on_click else None)

    # -- navigation --------------------------------------------------------- #
    def _open_check(self, e=None) -> None:
        from aegis.ui.views.security_check_view import SecurityCheckView
        self.app.navigate_to(SecurityCheckView)

    def _open_alerts(self, e=None) -> None:
        from aegis.ui.views.detections_view import DetectionsView
        self.app.navigate_to(DetectionsView)

    # -- data --------------------------------------------------------------- #
    def refresh(self) -> None:
        store = self.service.store
        stats = store.stats()
        report = self.app.posture_report
        if report is None:
            self.app.request_posture()
        checked = report is not None and report.evaluated > 0
        failed = report.count(CheckStatus.FAIL) if checked else None

        self._show_status(protection_status(monitoring=self.service.running,
                                            serious_alerts=stats["open_serious_alerts"],
                                            failed_checks=failed))

        if checked:
            self.score_value.value = f"{report.score}/100"
            self.score_sub.value = f"Grade {report.grade}"
        else:
            self.score_value.value = "-"
            self.score_sub.value = "Checking..." if report is None else "Could not check"
        self.alerts_value.value = str(stats["open_alerts"])
        self.alerts_sub.value = f"{stats['open_serious_alerts']} serious"
        self.events_value.value = f"{stats['total_events']:,}"
        self.events_sub.value = "connections and programs"
        intel = get_intel()
        self.intel_value.value = f"{len(intel):,}"
        self.intel_sub.value = "known and watched for" if len(intel) else "no blocklists yet"

        self.severity_host.content = charts.severity_pie(stats["alerts_by_severity"])
        self.timeline_host.content = charts.alerts_timeline_bar(store.alerts_timeline(24))
        self.programs.controls = [
            ft.Row([ft.Icon(ft.Icons.APPS, size=16, color=theme.TEXT_MUTED),
                    ft.Text(row["process_name"], size=13, color=theme.TEXT, expand=True,
                            no_wrap=True, overflow=ft.TextOverflow.ELLIPSIS),
                    ft.Text(plural(row["n"], "connection"), size=12, color=theme.TEXT_MUTED)])
            for row in stats["top_processes"][:6]
        ] or [ft.Text("No internet activity recorded yet.", size=13, color=theme.TEXT_MUTED)]
        self.recent.controls = [
            ft.Row([c.severity_badge(a.severity),
                    ft.Text(a.title, size=13, color=theme.TEXT, expand=True, no_wrap=True,
                            overflow=ft.TextOverflow.ELLIPSIS),
                    ft.Text(time_ago(a.timestamp), size=11, color=theme.TEXT_MUTED)])
            for a in store.recent_alerts(limit=5, unacknowledged_only=True)
        ] or [ft.Text("No alerts waiting for review.", size=13, color=theme.TEXT_MUTED)]
        self.safe_update()

    def _show_status(self, status) -> None:
        icon, color = _STATUS_STYLE[status.level]
        self.status_icon.icon = icon
        self.status_icon.color = color
        self.status_card.bgcolor = ft.Colors.with_opacity(0.08, color)
        self.status_card.border = ft.Border.all(1, ft.Colors.with_opacity(0.55, color))
        self.status_headline.value = status.headline
        self.status_details.controls = [ft.Text(line, size=14, color=theme.TEXT_MUTED)
                                        for line in status.details]

        action = self.status_action
        action.visible = True
        if status.level == "paused":
            action.content, action.icon, action.on_click = \
                "Start monitoring", ft.Icons.PLAY_ARROW, self.app.toggle_monitor
        elif any("alert" in line for line in status.details):
            action.content, action.icon, action.on_click = \
                "Review alerts", ft.Icons.NOTIFICATIONS_ACTIVE, self._open_alerts
        elif status.level == "warn":
            action.content, action.icon, action.on_click = \
                "Fix settings", ft.Icons.BUILD_OUTLINED, self._open_check
        else:
            action.content, action.icon, action.on_click = \
                "Security check", ft.Icons.HEALTH_AND_SAFETY_OUTLINED, self._open_check
