"""Security alerts / detections view (ATT&CK-mapped)."""
from __future__ import annotations

import flet as ft

from aegis.ui import components as c
from aegis.ui import theme
from aegis.ui.views.base import BaseView


class DetectionsView(BaseView):
    title = "Detections"
    icon = ft.Icons.NOTIFICATIONS_ACTIVE_OUTLINED

    def build(self) -> ft.Control:
        self.unack = ft.Switch(label="Unacknowledged only", value=False,
                               active_color=theme.PRIMARY, on_change=lambda e: self.refresh())
        self.count = ft.Text("", size=12, color=theme.TEXT_MUTED)
        self.rows = ft.ListView(spacing=8, expand=True, padding=4)
        return ft.Column([
            ft.Row([c.section_title("Detections & Alerts", ft.Icons.NOTIFICATIONS_ACTIVE_OUTLINED),
                    ft.Container(expand=True), self.count,
                    ft.OutlinedButton("Acknowledge all", icon=ft.Icons.DONE_ALL,
                                      on_click=self._ack_all)]),
            self.unack,
            c.panel(self.rows, padding=6, expand=True),
        ], spacing=12, expand=True)

    def refresh(self) -> None:
        alerts = self.service.store.recent_alerts(limit=200, unacknowledged_only=self.unack.value)
        self.rows.controls = [self._row(a) for a in alerts] or [
            c.empty_state("No alerts. Host looks clean.", ft.Icons.VERIFIED_USER_OUTLINED)]
        self.count.value = f"{len(alerts)} alert(s)"
        self.safe_update()

    def _row(self, a) -> ft.Control:
        color = theme.SEVERITY_COLOR.get(a.severity, theme.INFO)
        chips = [c.severity_badge(a.severity)]
        if a.technique:
            chips.append(c.pill(a.technique, theme.ACCENT))
        return ft.Container(
            content=ft.Row([
                ft.Container(width=4, bgcolor=color, border_radius=4, height=52),
                ft.Column([
                    ft.Row(chips + [ft.Text(a.title, size=13, color=theme.TEXT,
                                            weight=ft.FontWeight.W_600, expand=True, no_wrap=True,
                                            overflow=ft.TextOverflow.ELLIPSIS)], spacing=8),
                    ft.Text(a.message, size=11, color=theme.TEXT_MUTED, max_lines=2,
                            overflow=ft.TextOverflow.ELLIPSIS),
                    ft.Text(a.timestamp.strftime("%Y-%m-%d %H:%M:%S"), size=10,
                            color=theme.TEXT_MUTED),
                ], spacing=3, expand=True, tight=True),
                (c.pill("ACK", theme.OK) if a.acknowledged else
                 ft.IconButton(ft.Icons.CHECK, icon_color=theme.OK, icon_size=18,
                               tooltip="Acknowledge", on_click=lambda e, i=a.id: self._ack(i))),
            ], spacing=12, vertical_alignment=ft.CrossAxisAlignment.START),
            padding=ft.Padding.symmetric(horizontal=12, vertical=10),
            bgcolor=theme.SURFACE_ALT, border_radius=10, border=ft.Border.all(1, theme.BORDER))

    def _ack(self, alert_id) -> None:
        self.service.store.acknowledge_alert(alert_id)
        self.refresh()

    def _ack_all(self, e=None) -> None:
        self.service.store.acknowledge_all_alerts()
        self.app.toast("All alerts acknowledged.", ok=True)
        self.refresh()
