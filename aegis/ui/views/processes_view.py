"""Running programs, with a warning on any that look out of place."""
from __future__ import annotations

import flet as ft

from aegis.collectors.processes import snapshot
from aegis.ui import components as c
from aegis.ui import theme
from aegis.ui.plain import plural
from aegis.ui.views.base import BaseView


class ProcessesView(BaseView):
    title = "Running Programs"
    icon = ft.Icons.MEMORY_OUTLINED

    def build(self) -> ft.Control:
        self.only_sus = ft.Switch(label="Only show suspicious programs", value=False,
                                  active_color=theme.PRIMARY, on_change=lambda e: self.refresh())
        self.search = ft.TextField(hint_text="Search programs", prefix_icon=ft.Icons.SEARCH,
                                   on_change=lambda e: self.refresh(), border_color=theme.BORDER,
                                   height=44, content_padding=10, expand=True, color=theme.TEXT)
        self.count = ft.Text("", size=12, color=theme.TEXT_MUTED)
        self.rows = ft.ListView(spacing=6, expand=True, padding=4)
        return ft.Column([
            ft.Row([c.section_title("Running Programs", ft.Icons.MEMORY_OUTLINED),
                    ft.Container(expand=True), self.count]),
            ft.Text("Every program running right now. A warning means the program is somewhere "
                    "malware likes to hide, such as a temporary or downloads folder.",
                    size=12, color=theme.TEXT_MUTED),
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
        empty = ("No suspicious programs found." if self.only_sus.value
                 else "No programs match your search.")
        self.rows.controls = [self._row(p) for p in procs] or [
            c.empty_state(empty, ft.Icons.MEMORY_OUTLINED)]
        self.count.value = plural(len(procs), "program")
        self.safe_update()

    def _confirm_stop(self, proc) -> None:
        """Ask before stopping a program, and say what stopping it means."""
        def stop(e):
            self.page.pop_dialog()
            result = self.service.stop_process(proc.pid, proc.name, confirmed=True,
                                               reason="stopped from Running Programs")
            self.app.toast(result.message, ok=result.ok)
            self.refresh()

        self.page.show_dialog(ft.AlertDialog(
            modal=True, title=ft.Text(f"Stop {proc.name}?"),
            content=ft.Text(
                f"{proc.name} (process {proc.pid}) will be asked to close, and closed "
                f"firmly if it refuses. Anything it has not saved is lost, and a program "
                f"the computer needs may start again by itself.\n\n"
                f"{proc.exe or 'Location not available'}", width=460),
            actions=[ft.TextButton("Cancel", on_click=lambda e: self.page.pop_dialog()),
                     ft.FilledButton("Stop program", icon=ft.Icons.STOP_CIRCLE_OUTLINED,
                                     on_click=stop)]))

    def _row(self, p) -> ft.Control:
        sus = p.is_suspicious
        pills = [c.pill(f"{p.memory_mb:.0f} MB memory", theme.TEXT_MUTED)]
        if p.num_connections:
            pills.insert(0, c.pill(plural(p.num_connections, "network connection"), theme.INFO))
        return ft.Container(
            content=ft.Row([
                ft.Icon(ft.Icons.WARNING_AMBER_ROUNDED if sus else ft.Icons.CHECK_CIRCLE_OUTLINE,
                        color=theme.WARN if sus else theme.OK, size=18),
                ft.Column([
                    ft.Text(p.name, size=13, color=theme.TEXT, weight=ft.FontWeight.W_600,
                            no_wrap=True, overflow=ft.TextOverflow.ELLIPSIS,
                            tooltip=f"Process ID {p.pid}"),
                    ft.Text(p.exe or "Location not available", size=10, color=theme.TEXT_MUTED,
                            no_wrap=True, overflow=ft.TextOverflow.ELLIPSIS, selectable=True),
                    ft.Text("Why this is flagged: " + "; ".join(p.suspicious_reasons), size=11,
                            color=theme.WARN) if sus else ft.Container(height=0),
                ], spacing=1, expand=True, tight=True),
                *pills,
                ft.TextButton("Stop", icon=ft.Icons.STOP_CIRCLE_OUTLINED,
                              tooltip=f"Stop {p.name} (process {p.pid})",
                              on_click=lambda e, proc=p: self._confirm_stop(proc)),
            ], spacing=12),
            padding=ft.Padding.symmetric(horizontal=14, vertical=8),
            bgcolor=ft.Colors.with_opacity(0.08, theme.WARN) if sus else theme.SURFACE_ALT,
            border_radius=8,
            border=ft.Border.all(1, ft.Colors.with_opacity(0.4, theme.WARN) if sus else theme.BORDER))
