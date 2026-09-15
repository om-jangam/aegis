"""Settings view — tune monitoring, detection and alerting."""
from __future__ import annotations

import flet as ft

from aegis.config import settings
from aegis.ui import components as c
from aegis.ui import theme
from aegis.ui.views.base import BaseView


class SettingsView(BaseView):
    title = "Settings"
    icon = ft.Icons.SETTINGS_OUTLINED

    def build(self) -> ft.Control:
        self.monitoring = ft.Switch(value=settings.monitoring_enabled, active_color=theme.PRIMARY)
        self.anomaly = ft.Switch(value=settings.anomaly_detection_enabled, active_color=theme.PRIMARY)
        self.threat_intel = ft.Switch(value=settings.threat_intel_enabled, active_color=theme.PRIMARY)
        self.notifications = ft.Switch(value=settings.desktop_notifications, active_color=theme.PRIMARY)
        self.auto_respond = ft.Switch(value=False, active_color=theme.DANGER)
        self.threshold = ft.Slider(min=20, max=100, divisions=8,
                                   value=settings.threat_score_alert_threshold, label="{value}",
                                   active_color=theme.PRIMARY)
        self.net_interval = ft.TextField(value=str(settings.network_poll_interval), width=100,
                                         border_color=theme.BORDER, color=theme.TEXT,
                                         keyboard_type=ft.KeyboardType.NUMBER)

        def row(label, desc, control):
            return ft.Container(
                content=ft.Row([
                    ft.Column([ft.Text(label, size=14, color=theme.TEXT, weight=ft.FontWeight.W_600),
                               ft.Text(desc, size=11, color=theme.TEXT_MUTED)],
                              spacing=2, expand=True, tight=True),
                    control]),
                padding=ft.Padding.symmetric(horizontal=14, vertical=12),
                bgcolor=theme.SURFACE_ALT, border_radius=8)

        return ft.Column([
            c.section_title("Settings", ft.Icons.SETTINGS_OUTLINED),
            c.panel(ft.Column([
                c.section_title("Monitoring & Detection", ft.Icons.RADAR),
                row("Live monitoring", "Continuously scan connections & processes", self.monitoring),
                row("AI anomaly assist", "IsolationForest flags outlier connections", self.anomaly),
                row("Threat intelligence", "Alert on connections to known-malicious IPs "
                    "(update lists on the Security Check page)", self.threat_intel),
                row("Network poll interval (s)", "How often to scan the socket table", self.net_interval),
                ft.Container(ft.Column([
                    ft.Text("Alert threat-score threshold", size=14, color=theme.TEXT,
                            weight=ft.FontWeight.W_600),
                    ft.Text("Raise an alert at/above this score", size=11, color=theme.TEXT_MUTED),
                    self.threshold], spacing=4),
                    padding=ft.Padding.symmetric(horizontal=14, vertical=12),
                    bgcolor=theme.SURFACE_ALT, border_radius=8),
            ], spacing=10)),
            c.panel(ft.Column([
                c.section_title("Alerts & Response", ft.Icons.NOTIFICATIONS_OUTLINED),
                row("Desktop notifications", "Show Windows toast alerts", self.notifications),
                row("Auto-response (block IP)", "Automatically block hosts of high-severity findings",
                    self.auto_respond),
            ], spacing=10)),
            ft.FilledButton("Save settings", icon=ft.Icons.SAVE, on_click=self._save),
            ft.Container(height=20),
        ], spacing=14, scroll=ft.ScrollMode.AUTO, expand=True)

    def _save(self, e=None) -> None:
        settings.monitoring_enabled = self.monitoring.value
        settings.anomaly_detection_enabled = self.anomaly.value
        settings.threat_intel_enabled = self.threat_intel.value
        settings.desktop_notifications = self.notifications.value
        settings.threat_score_alert_threshold = int(self.threshold.value)
        try:
            settings.network_poll_interval = max(0.5, float(self.net_interval.value))
        except ValueError:
            self.app.toast("Interval must be a number.", ok=False)
            return
        settings.save()
        self.service.auto_respond = self.auto_respond.value
        if settings.monitoring_enabled and not self.service.running:
            self.service.start()
        elif not settings.monitoring_enabled and self.service.running:
            self.service.stop()
        self.app.toast("Settings saved.", ok=True)
        self.app.sync_monitor_button()
