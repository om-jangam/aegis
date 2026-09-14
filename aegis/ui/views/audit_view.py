"""Audit log view — accountability for everything Aegis did/observed."""
from __future__ import annotations

import flet as ft

from aegis.ui import components as c
from aegis.ui import theme
from aegis.ui.views.base import BaseView

_CATS = ["All", "RULE", "DETECTION", "RESPONSE", "SYSTEM"]


class AuditView(BaseView):
    title = "Audit Log"
    icon = ft.Icons.FACT_CHECK_OUTLINED

    def build(self) -> ft.Control:
        self.cat = ft.Dropdown(value="All", width=170, on_select=lambda e: self.refresh(),
                               options=[ft.DropdownOption(k) for k in _CATS])
        self.count = ft.Text("", size=12, color=theme.TEXT_MUTED)
        self.rows = ft.ListView(spacing=4, expand=True, padding=4)
        return ft.Column([
            ft.Row([c.section_title("Audit Log", ft.Icons.FACT_CHECK_OUTLINED),
                    ft.Container(expand=True), self.count]),
            ft.Row([self.cat]),
            c.panel(self.rows, padding=6, expand=True),
        ], spacing=12, expand=True)

    def refresh(self) -> None:
        cat = None if self.cat.value == "All" else self.cat.value
        events = self.service.store.recent_audit(limit=400, category=cat)
        self.rows.controls = [self._row(ev) for ev in events] or [
            c.empty_state("No audit events yet.", ft.Icons.FACT_CHECK_OUTLINED)]
        self.count.value = f"{len(events)} event(s)"
        self.safe_update()

    def _row(self, ev) -> ft.Control:
        color = theme.SEVERITY_COLOR.get(ev.severity, theme.INFO)
        return ft.Container(
            content=ft.Row([
                ft.Text(ev.timestamp.strftime("%m-%d %H:%M:%S"), size=11,
                        color=theme.TEXT_MUTED, width=110),
                c.pill(ev.category, color),
                ft.Text(ev.message, size=12, color=theme.TEXT, expand=True, no_wrap=True,
                        overflow=ft.TextOverflow.ELLIPSIS, tooltip=ev.detail or ev.message),
            ], spacing=10),
            padding=ft.Padding.symmetric(horizontal=12, vertical=6),
            bgcolor=theme.SURFACE_ALT, border_radius=6)
