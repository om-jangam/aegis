"""Settings, described in everyday words."""
from __future__ import annotations

import flet as ft

from aegis.config import settings
from aegis.core.models import Severity
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
        self.auth = ft.Switch(value=settings.auth_monitoring_enabled, active_color=theme.PRIMARY)
        self.dns = ft.Switch(value=settings.dns_monitoring_enabled, active_color=theme.PRIMARY)
        self.notifications = ft.Switch(value=settings.desktop_notifications, active_color=theme.PRIMARY)
        self.auto_respond = ft.Switch(value=self.service.auto_respond, active_color=theme.DANGER)
        self.space = ft.Switch(value=settings.space_background, active_color=theme.PRIMARY)
        self.threshold = ft.Slider(min=20, max=100, divisions=8,
                                   value=settings.threat_score_alert_threshold, label="{value}",
                                   active_color=theme.PRIMARY)
        self.net_interval = ft.TextField(value=str(settings.network_poll_interval), width=100,
                                         border_color=theme.BORDER, color=theme.TEXT,
                                         keyboard_type=ft.KeyboardType.NUMBER)
        self.trusted_list = ft.Column(spacing=6, tight=True)
        self._render_trusted()

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
                row("Watch name lookups (DNS)",
                    "Alert when this computer looks up a known-malicious website, a "
                    "machine-generated name, or smuggles data out through DNS.", self.dns),
                row("Watch sign-ins",
                    "Alert on repeated wrong passwords, new accounts and accounts given "
                    "administrator rights. Needs administrator rights on Windows.", self.auth),
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
                c.section_title("Trusted programs", ft.Icons.VERIFIED_OUTLINED),
                ft.Text("Aegis does not alert about these programs or anything they start "
                        "(what they do is still recorded). Add one from an alert with "
                        "\"Trust\"; remove it here to be alerted again.", size=12,
                        color=theme.TEXT_MUTED),
                self.trusted_list,
            ], spacing=10)),
            c.panel(ft.Column([
                c.section_title("Appearance", ft.Icons.AUTO_AWESOME),
                row("Starry background",
                    "A quiet, still starfield behind the pages. Turn off for a plain dark "
                    "background.", self.space),
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

    def refresh(self) -> None:
        self._render_trusted()
        self.safe_update()

    def _render_trusted(self) -> None:
        self.trusted_list.controls = [
            ft.Container(
                content=ft.Row([
                    ft.Icon(ft.Icons.VERIFIED_OUTLINED, color=theme.OK, size=18),
                    ft.Text(name, size=14, color=theme.TEXT, expand=True),
                    ft.OutlinedButton("Stop trusting", icon=ft.Icons.REMOVE_CIRCLE_OUTLINE,
                                      on_click=lambda e, n=name: self._untrust(n)),
                ], spacing=10, vertical_alignment=ft.CrossAxisAlignment.CENTER),
                padding=ft.Padding.symmetric(horizontal=14, vertical=8),
                bgcolor=theme.SURFACE_ALT, border_radius=8)
            for name in settings.trusted_programs
        ] or [ft.Text("No trusted programs. Every program is watched.", size=13,
                      color=theme.TEXT_MUTED)]

    def _untrust(self, name: str) -> None:
        settings.trusted_programs = [t for t in settings.trusted_programs if t != name]
        settings.save()
        self.service.audit("SYSTEM", "program_untrusted", Severity.INFO,
                           f"Stopped trusting {name}")
        self.app.toast(f"{name} is no longer trusted. Aegis will alert about it again.", ok=True)
        self.refresh()

    def _save(self, e=None) -> None:
        try:
            interval = max(0.5, float(self.net_interval.value))
        except (TypeError, ValueError):
            self.app.toast("The network check interval must be a number of seconds.", ok=False)
            return
        settings.monitoring_enabled = self.monitoring.value
        settings.threat_intel_enabled = self.threat_intel.value
        settings.anomaly_detection_enabled = self.anomaly.value
        settings.auth_monitoring_enabled = self.auth.value
        settings.dns_monitoring_enabled = self.dns.value
        settings.desktop_notifications = self.notifications.value
        settings.threat_score_alert_threshold = int(self.threshold.value or 70)
        settings.network_poll_interval = interval
        settings.space_background = self.space.value
        settings.save()
        self.app.sky.set_visible(settings.space_background)
        self.service.auto_respond = self.auto_respond.value
        if settings.monitoring_enabled and not self.service.running:
            self.service.start()
        elif not settings.monitoring_enabled and self.service.running:
            self.service.stop()
        self.app.toast("Settings saved.", ok=True)
        self.app.sync_monitor_button()
