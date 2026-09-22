"""Activity history: a permanent record of what Aegis did."""
from __future__ import annotations

import flet as ft

from aegis.ui import components as c
from aegis.ui import theme
from aegis.ui.plain import AUDIT_FILTERS, audit_category, plural, time_ago
from aegis.ui.views.base import BaseView


class AuditView(BaseView):
    title = "Activity History"
    icon = ft.Icons.HISTORY

    def build(self) -> ft.Control:
        self.cat = ft.Dropdown(value="All", width=220, on_select=lambda e: self.refresh(),
                               options=[ft.DropdownOption(key=key, text=text)
                                        for key, text in AUDIT_FILTERS])
        self.count = ft.Text("", size=12, color=theme.TEXT_MUTED)
        self.rows = ft.ListView(spacing=4, expand=True, padding=4)
        return ft.Column([
            ft.Row([c.section_title("Activity History", ft.Icons.HISTORY),
                    ft.Container(expand=True), self.count]),
            ft.Text("A permanent record of what Aegis did: alerts raised, addresses blocked "
                    "and firewall changes.", size=12, color=theme.TEXT_MUTED),
            ft.Row([self.cat]),
            c.panel(self.rows, padding=6, expand=True),
        ], spacing=12, expand=True)

    def refresh(self) -> None:
        cat = None if self.cat.value == "All" else self.cat.value
        events = self.service.store.recent_audit(limit=400, category=cat)
        self.rows.controls = [self._row(ev) for ev in events] or [
            c.empty_state("Nothing recorded yet.", ft.Icons.HISTORY)]
        self.count.value = plural(len(events), "entry", "entries")
        self.safe_update()

    def _row(self, ev) -> ft.Control:
        color = theme.SEVERITY_COLOR.get(ev.severity, theme.INFO)
        text: list[ft.Control] = [ft.Text(ev.message, size=12, color=theme.TEXT, no_wrap=True,
                        overflow=ft.TextOverflow.ELLIPSIS)]
        if ev.detail:
            text.append(ft.Text(ev.detail, size=11, color=theme.TEXT_MUTED, no_wrap=True,
                                overflow=ft.TextOverflow.ELLIPSIS))
        return ft.Container(
            content=ft.Row([
                ft.Text(time_ago(ev.timestamp), size=11, color=theme.TEXT_MUTED, width=120,
                        tooltip=ev.timestamp.strftime("%Y-%m-%d %H:%M:%S")),
                ft.Container(c.pill(audit_category(ev.category), color), width=90),
                ft.Column(text, spacing=1, tight=True, expand=True),
            ], spacing=10, vertical_alignment=ft.CrossAxisAlignment.CENTER),
            padding=ft.Padding.symmetric(horizontal=12, vertical=6),
            bgcolor=theme.SURFACE_ALT, border_radius=6)
