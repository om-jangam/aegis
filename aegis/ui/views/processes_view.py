"""Running processes view with suspicion flags."""
from __future__ import annotations

import flet as ft

from aegis.collectors.processes import snapshot
from aegis.ui import components as c
from aegis.ui import theme
from aegis.ui.views.base import BaseView


class ProcessesView(BaseView):
    title = "Processes"
    icon = ft.Icons.MEMORY_OUTLINED

    def build(self) -> ft.Control:
        self.only_sus = ft.Switch(label="Only suspicious", value=False,
                                  active_color=theme.PRIMARY, on_change=lambda e: self.refresh())
        self.search = ft.TextField(hint_text="Filter processes…", prefix_icon=ft.Icons.SEARCH,
                                   on_change=lambda e: self.refresh(), border_color=theme.BORDER,
                                   height=44, content_padding=10, expand=True, color=theme.TEXT)
        self.count = ft.Text("", size=12, color=theme.TEXT_MUTED)
        self.rows = ft.ListView(spacing=6, expand=True, padding=4)
        return ft.Column([
            ft.Row([c.section_title("Running Processes", ft.Icons.MEMORY_OUTLINED),
                    ft.Container(expand=True), self.count]),
            ft.Row([self.search, self.only_sus], spacing=12),
            c.panel(self.rows, padding=6, expand=True),
        ], spacing=12, expand=True)

    def refresh(self) -> None:
        procs = snapshot(limit=400)
        kw = (self.search.value or "").casefold()
        if self.only_sus.value:
            procs = [p for p in procs if p.is_suspicious]
        if kw:
            procs = [p for p in procs if kw in p.name.casefold() or kw in (p.exe or "").casefold()]
        procs = procs[:200]
        self.rows.controls = [self._row(p) for p in procs] or [
            c.empty_state("No processes match.", ft.Icons.MEMORY_OUTLINED)]
        self.count.value = f"{len(procs)} shown"
        self.safe_update()

    def _row(self, p) -> ft.Control:
        sus = p.is_suspicious
        return ft.Container(
            content=ft.Row([
                ft.Icon(ft.Icons.WARNING_AMBER_ROUNDED if sus else ft.Icons.CHECK_CIRCLE_OUTLINE,
                        color=theme.WARN if sus else theme.OK, size=18),
                ft.Column([
                    ft.Text(p.name, size=13, color=theme.TEXT, weight=ft.FontWeight.W_600,
                            no_wrap=True, overflow=ft.TextOverflow.ELLIPSIS),
                    ft.Text(p.exe or "(path unavailable)", size=10, color=theme.TEXT_MUTED,
                            no_wrap=True, overflow=ft.TextOverflow.ELLIPSIS),
                    ft.Text("⚠ " + "; ".join(p.suspicious_reasons), size=10, color=theme.WARN,
                            no_wrap=True, overflow=ft.TextOverflow.ELLIPSIS) if sus
                    else ft.Container(height=0),
                ], spacing=1, expand=True, tight=True),
                c.pill(f"PID {p.pid}", theme.TEXT_MUTED),
                c.pill(f"{p.num_connections} conn", theme.INFO if p.num_connections else theme.TEXT_MUTED),
                c.pill(f"{p.memory_mb:.0f} MB", theme.TEXT_MUTED),
            ], spacing=12),
            padding=ft.Padding.symmetric(horizontal=14, vertical=8),
            bgcolor=ft.Colors.with_opacity(0.08, theme.WARN) if sus else theme.SURFACE_ALT,
            border_radius=8,
            border=ft.Border.all(1, ft.Colors.with_opacity(0.4, theme.WARN) if sus else theme.BORDER))
