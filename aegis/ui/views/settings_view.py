"""Settings, described in everyday words."""
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
        self.threat_intel = ft.Switch(value=settings.threat_intel_enabled, active_color=theme.PRIMARY)
        self.anomaly = ft.Switch(value=settings.anomaly_detection_enabled, active_color=theme.PRIMARY)
        self.notifications = ft.Switch(value=settings.desktop_notifications, active_color=theme.PRIMARY)
        self.auto_respond = ft.Switch(value=self.service.auto_respond, active_color=theme.DANGER)
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
                               ft.Text(desc, size=12, color=theme.TEXT_MUTED)],
                              spacing=2, expand=True, tight=True),
                    control]),
                padding=ft.Padding.symmetric(horizontal=14, vertical=12),
                bgcolor=theme.SURFACE_ALT, border_radius=8)

        return ft.Column([
            c.section_title("Settings", ft.Icons.SETTINGS_OUTLINED),
            c.panel(ft.Column([
                c.section_title("Protection", ft.Icons.SHIELD_OUTLINED),
                row("Watch this computer",
                    "Keep checking network connections and running programs for signs of attack",
                    self.monitoring),
                row("Known attacker addresses",
                    "Alert when a program connects to an address on a threat blocklist "
                    "(update the lists on the Security Check page)", self.threat_intel),
                row("Smart unusual-activity detection",
                    "Learn what is normal for this computer and flag connections that stand out",
                    self.anomaly),
            ], spacing=10)),
            c.panel(ft.Column([
                c.section_title("Alerts", ft.Icons.NOTIFICATIONS_OUTLINED),
                row("Pop-up notifications", "Show a notification when a serious alert appears",
                    self.notifications),
                ft.Container(ft.Column([
                    ft.Text("Alert sensitivity", size=14, color=theme.TEXT,
                            weight=ft.FontWeight.W_600),
                    ft.Text("Lower means more alerts; higher means only the most serious ones. "
                            "70 is a good balance.", size=12, color=theme.TEXT_MUTED),
                    self.threshold], spacing=4),
                    padding=ft.Padding.symmetric(horizontal=14, vertical=12),
                    bgcolor=theme.SURFACE_ALT, border_radius=8),
                row("Automatically block attackers",
                    "Block the address behind a serious alert without asking. Needs administrator "
                    "rights, and could block something you use, so it is off by default.",
                    self.auto_respond),
            ], spacing=10)),
            c.panel(ft.Column([
                c.section_title("Advanced", ft.Icons.TUNE),
                row("Network check interval (seconds)",
                    "How often Aegis looks at network connections. Lower uses more CPU.",
                    self.net_interval),
                row("Welcome guide", "Show the short introduction from the first start again",
                    ft.OutlinedButton("Show again", icon=ft.Icons.WAVING_HAND_OUTLINED,
                                      on_click=lambda e: self.app.show_welcome())),
            ], spacing=10)),
            ft.FilledButton("Save settings", icon=ft.Icons.SAVE, on_click=self._save),
            ft.Container(height=20),
        ], spacing=14, scroll=ft.ScrollMode.AUTO, expand=True)

    def _save(self, e=None) -> None:
        try:
            interval = max(0.5, float(self.net_interval.value))
        except (TypeError, ValueError):
            self.app.toast("The network check interval must be a number of seconds.", ok=False)
            return
        settings.monitoring_enabled = self.monitoring.value
        settings.threat_intel_enabled = self.threat_intel.value
        settings.anomaly_detection_enabled = self.anomaly.value
        settings.desktop_notifications = self.notifications.value
        settings.threat_score_alert_threshold = int(self.threshold.value)
        settings.network_poll_interval = interval
        settings.save()
        self.service.auto_respond = self.auto_respond.value
        if settings.monitoring_enabled and not self.service.running:
            self.service.start()
        elif not settings.monitoring_enabled and self.service.running:
            self.service.stop()
        self.app.toast("Settings saved.", ok=True)
        self.app.sync_monitor_button()
