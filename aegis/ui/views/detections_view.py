"""Alerts: what Aegis noticed, and what to do about each one."""
from __future__ import annotations

import flet as ft

from aegis.ui import components as c
from aegis.ui import theme
from aegis.ui.plain import advice_for_alert, plural, time_ago
from aegis.ui.views.base import BaseView


class DetectionsView(BaseView):
    title = "Alerts"
    icon = ft.Icons.NOTIFICATIONS_ACTIVE_OUTLINED

    def build(self) -> ft.Control:
        self.unreviewed = ft.Switch(label="Only alerts I haven't reviewed", value=True,
                                    active_color=theme.PRIMARY, on_change=lambda e: self.refresh())
        self.count = ft.Text("", size=12, color=theme.TEXT_MUTED)
        self.rows = ft.ListView(spacing=8, expand=True, padding=4)
        return ft.Column([
            ft.Row([c.section_title("Alerts", ft.Icons.NOTIFICATIONS_ACTIVE_OUTLINED),
                    ft.Container(expand=True), self.count,
                    ft.OutlinedButton("Mark all as reviewed", icon=ft.Icons.DONE_ALL,
                                      on_click=self._confirm_review_all)]),
            ft.Text("Things Aegis noticed that could be part of an attack. Each alert tells "
                    "you what to do.", size=12, color=theme.TEXT_MUTED),
            self.unreviewed,
            c.panel(self.rows, padding=6, expand=True),
        ], spacing=12, expand=True)

    def refresh(self) -> None:
        alerts = self.service.store.recent_alerts(limit=200,
                                                  unacknowledged_only=self.unreviewed.value)
        empty = ("No alerts to review. Your computer looks clean." if self.unreviewed.value
                 else "No alerts yet.")
        self.rows.controls = [self._row(a) for a in alerts] or [
            c.empty_state(empty, ft.Icons.VERIFIED_USER_OUTLINED)]
        self.count.value = plural(len(alerts), "alert")
        self.safe_update()

    def _row(self, a) -> ft.Control:
        color = theme.SEVERITY_COLOR.get(a.severity, theme.INFO)
        what_happened = a.message.splitlines()[0] if a.message else ""
        review = (c.pill("Reviewed", theme.OK) if a.acknowledged else
                  ft.TextButton("Mark as reviewed", icon=ft.Icons.CHECK,
                                on_click=lambda e, i=a.id: self._review(i)))
        lines: list[ft.Control] = [
            ft.Row([
                c.severity_badge(a.severity),
                ft.Text(a.title, size=14, color=theme.TEXT, weight=ft.FontWeight.W_600,
                        expand=True, no_wrap=True, overflow=ft.TextOverflow.ELLIPSIS),
                ft.Text(time_ago(a.timestamp), size=11, color=theme.TEXT_MUTED,
                        tooltip=a.timestamp.strftime("%Y-%m-%d %H:%M:%S")),
                review,
            ], spacing=10, vertical_alignment=ft.CrossAxisAlignment.CENTER),
        ]
        if what_happened:
            lines.append(ft.Text(what_happened, size=12, color=theme.TEXT_MUTED, max_lines=2,
                                 overflow=ft.TextOverflow.ELLIPSIS, selectable=True))
        lines.append(ft.Container(
            ft.Row([ft.Icon(ft.Icons.LIGHTBULB_OUTLINE, color=color, size=18),
                    ft.Column([ft.Text("What should I do?", size=12, color=theme.TEXT,
                                       weight=ft.FontWeight.W_600),
                               ft.Text(advice_for_alert(a.technique), size=12, color=theme.TEXT)],
                              spacing=2, tight=True, expand=True)],
                   spacing=10, vertical_alignment=ft.CrossAxisAlignment.START),
            bgcolor=ft.Colors.with_opacity(0.10, color), border_radius=8,
            padding=ft.Padding.symmetric(horizontal=12, vertical=10)))
        if a.technique:
            lines.append(ft.Text(f"Technical reference: MITRE ATT&CK {a.technique}", size=10,
                                 color=theme.TEXT_MUTED))
        return ft.Container(
            content=ft.Column(lines, spacing=6, tight=True),
            padding=ft.Padding.symmetric(horizontal=14, vertical=12),
            bgcolor=theme.SURFACE_ALT, border_radius=10, border=ft.Border.all(1, theme.BORDER))

    def _review(self, alert_id) -> None:
        self.service.store.acknowledge_alert(alert_id)
        self.refresh()

    def _confirm_review_all(self, e=None) -> None:
        waiting = self.service.store.stats()["open_alerts"]
        if not waiting:
            self.app.toast("There are no alerts waiting for review.", ok=True)
            return

        def confirm(e):
            self.page.pop_dialog()
            self.service.store.acknowledge_all_alerts()
            self.app.toast(f"Marked {plural(waiting, 'alert')} as reviewed.", ok=True)
            self.refresh()

        self.page.show_dialog(ft.AlertDialog(
            modal=True, title=ft.Text("Mark all alerts as reviewed?"),
            content=ft.Text(f"{plural(waiting, 'alert')} will be marked as reviewed. Only do "
                            f"this after reading them; they stay in the list."),
            actions=[ft.TextButton("Cancel", on_click=lambda e: self.page.pop_dialog()),
                     ft.FilledButton("Mark all as reviewed", icon=ft.Icons.DONE_ALL,
                                     on_click=confirm)]))
