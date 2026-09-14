"""Dashboard: security posture at a glance."""
from __future__ import annotations

import flet as ft

from aegis.response.firewall import is_admin
from aegis.ui import components as c
from aegis.ui import theme
from aegis.ui.views.base import BaseView


class DashboardView(BaseView):
    title = "Dashboard"
    icon = ft.Icons.SPACE_DASHBOARD_OUTLINED

    def build(self) -> ft.Control:
        self.banner_icon = ft.Icon(ft.Icons.VERIFIED_USER, color=theme.OK, size=22)
        self.banner_message = ft.Text("Starting monitoring...", color=theme.TEXT, size=14,
                                      weight=ft.FontWeight.W_600)
        self.banner_role = c.pill("STANDARD USER", theme.WARN)
        self.banner = ft.Container(
            content=ft.Row([self.banner_icon, self.banner_message, ft.Container(expand=True),
                            self.banner_role]),
            padding=ft.Padding.symmetric(horizontal=16, vertical=12), bgcolor=theme.SURFACE,
            border_radius=12, border=ft.Border.all(1, theme.BORDER),
        )

        self.open_alerts = ft.Text("0", size=24, weight=ft.FontWeight.BOLD, color=theme.TEXT)
        self.findings = ft.Text("0", size=24, weight=ft.FontWeight.BOLD, color=theme.TEXT)
        self.events = ft.Text("0", size=24, weight=ft.FontWeight.BOLD, color=theme.TEXT)
        self.monitoring = ft.Text("OFF", size=24, weight=ft.FontWeight.BOLD, color=theme.TEXT)
        self.open_detail = ft.Text("0 total", size=11, color=theme.TEXT_MUTED)
        self.monitor_detail = ft.Text("0 collectors", size=11, color=theme.TEXT_MUTED)
        kpis = ft.Row([
            self._stat_card("Open alerts", self.open_alerts, self.open_detail,
                            ft.Icons.WARNING_AMBER_ROUNDED, theme.DANGER),
            self._stat_card("Findings", self.findings, ft.Text("detections", size=11,
                            color=theme.TEXT_MUTED), ft.Icons.TROUBLESHOOT, theme.WARN),
            self._stat_card("Events logged", self.events, ft.Text("telemetry", size=11,
                            color=theme.TEXT_MUTED), ft.Icons.LAN_OUTLINED, theme.PRIMARY),
            self._stat_card("Monitoring", self.monitoring, self.monitor_detail,
                            ft.Icons.RADAR, theme.OK),
        ], spacing=16)

        self.alert_summary = ft.Text("No alerts yet.", color=theme.TEXT_MUTED, size=13)
        self.activity_summary = ft.Text("No alert activity in the last 24 hours.",
                                        color=theme.TEXT_MUTED, size=13)
        self.remote_summary = ft.Text("No traffic yet.", color=theme.TEXT_MUTED, size=13)
        self.tech_summary = ft.Text("No detections yet.", color=theme.TEXT_MUTED, size=13)
        summary_rows = ft.Row([
            c.panel(ft.Column([c.section_title("Alerts by severity", ft.Icons.PIE_CHART_OUTLINE),
                               self.alert_summary], spacing=12), expand=True),
            c.panel(ft.Column([c.section_title("Alert activity (24h)", ft.Icons.SHOW_CHART),
                               self.activity_summary], spacing=12), expand=True),
        ], spacing=16)
        detail_rows = ft.Row([
            c.panel(ft.Column([c.section_title("Top remote hosts", ft.Icons.PUBLIC),
                               self.remote_summary], spacing=12), expand=True),
            c.panel(ft.Column([c.section_title("Top ATT&CK techniques", ft.Icons.SECURITY),
                               self.tech_summary], spacing=12), expand=True),
        ], spacing=16)
        return ft.Column([self.banner, kpis, summary_rows, detail_rows], spacing=16, expand=True)

    @staticmethod
    def _stat_card(title: str, value: ft.Text, detail: ft.Text, icon: str, color: str) -> ft.Container:
        return ft.Container(
            content=ft.Row([
                ft.Container(ft.Icon(icon, color=color, size=26),
                             bgcolor=ft.Colors.with_opacity(0.15, color), padding=12,
                             border_radius=10),
                ft.Column([ft.Text(title, size=12, color=theme.TEXT_MUTED), value, detail],
                          spacing=2, tight=True),
            ], spacing=14, vertical_alignment=ft.CrossAxisAlignment.CENTER),
            padding=18, bgcolor=theme.SURFACE, border=ft.Border.all(1, theme.BORDER),
            border_radius=12, expand=True,
        )

    def refresh(self) -> None:
        stats = self.service.store.stats()
        running = self.service.running
        admin = is_admin()
        self.banner_icon.name = ft.Icons.VERIFIED_USER if running else ft.Icons.GPP_MAYBE
        self.banner_icon.color = theme.OK if running else theme.WARN
        self.banner_message.value = "Live monitoring active - host protected." if running else "Monitoring paused."
        self.banner_role.content.value = "ADMIN" if admin else "STANDARD USER"
        self.banner_role.content.color = theme.OK if admin else theme.WARN
        self.banner_role.bgcolor = ft.Colors.with_opacity(0.13, theme.OK if admin else theme.WARN)

        self.open_alerts.value = str(stats["open_alerts"])
        self.open_detail.value = f"{stats['total_alerts']} total"
        self.findings.value = str(stats["total_findings"])
        self.events.value = str(stats["total_events"])
        self.monitoring.value = "ON" if running else "OFF"
        self.monitor_detail.value = f"{len(self.service.collectors)} collectors"
        self.alert_summary.value = self._severity_summary(stats["alerts_by_severity"])
        self.activity_summary.value = self._activity_summary(self.service.store.alerts_timeline(24))
        self.remote_summary.value = self._top_summary(stats["top_remote_ips"], "remote_ip", "No traffic yet.")
        self.tech_summary.value = self._top_summary(stats["top_techniques"], "technique", "No detections yet.")
        self.safe_update()

    @staticmethod
    def _severity_summary(rows: dict[str, int]) -> str:
        if not rows:
            return "No alerts yet."
        return " | ".join(f"{name.title()}: {count}" for name, count in sorted(rows.items()))

    @staticmethod
    def _activity_summary(points: list[tuple[str, int]]) -> str:
        if not points:
            return "No alert activity in the last 24 hours."
        return f"{sum(count for _, count in points)} alert(s) in the last 24 hours."

    @staticmethod
    def _top_summary(rows: list[dict], key: str, empty: str) -> str:
        if not rows:
            return empty
        return " | ".join(f"{row[key]} ({row['n']})" for row in rows[:4])
