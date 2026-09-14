"""Live network connections view."""
from __future__ import annotations

import flet as ft

from aegis.ui import components as c
from aegis.ui import theme
from aegis.ui.views.base import BaseView


class ConnectionsView(BaseView):
    title = "Connections"
    icon = ft.Icons.LAN_OUTLINED

    def build(self) -> ft.Control:
        self.search = ft.TextField(hint_text="Filter by process or IP…",
                                   prefix_icon=ft.Icons.SEARCH, on_change=lambda e: self.refresh(),
                                   border_color=theme.BORDER, height=44, content_padding=10,
                                   expand=True, color=theme.TEXT)
        self.count = ft.Text("", size=12, color=theme.TEXT_MUTED)
        self.rows = ft.ListView(spacing=6, expand=True, padding=4)
        return ft.Column([
            ft.Row([c.section_title("Live Network Connections", ft.Icons.LAN_OUTLINED),
                    ft.Container(expand=True), self.count]),
            self.search,
            c.panel(self.rows, padding=6, expand=True),
        ], spacing=12, expand=True)

    def refresh(self) -> None:
        events = self.service.store.recent_network_events(limit=400)
        kw = (self.search.value or "").casefold()
        seen, filtered = set(), []
        for r in events:
            key = (r["pid"], r["remote_ip"], r["remote_port"], r["protocol"])
            if key in seen:
                continue
            seen.add(key)
            hay = f"{r['process_name']} {r['remote_ip']} {r['remote_port']}".casefold()
            if kw and kw not in hay:
                continue
            filtered.append(r)
        filtered = filtered[:200]
        self.rows.controls = [self._row(r) for r in filtered] or [
            c.empty_state("No connections captured yet.", ft.Icons.LAN_OUTLINED)]
        self.count.value = f"{len(filtered)} shown"
        self.safe_update()

    def _row(self, r: dict) -> ft.Control:
        remote = f"{r['remote_ip']}:{r['remote_port']}" if r["remote_ip"] else "(listening)"
        return ft.Container(
            content=ft.Row([
                ft.Text(r["process_name"] or "?", width=170, size=12, color=theme.TEXT,
                        no_wrap=True, overflow=ft.TextOverflow.ELLIPSIS, tooltip=f"PID {r['pid']}"),
                ft.Text(remote, size=12, color=theme.TEXT, expand=True, no_wrap=True,
                        overflow=ft.TextOverflow.ELLIPSIS),
                c.pill(r["protocol"] or "", theme.INFO),
                ft.Text(r["status"] or "", width=110, size=11, color=theme.TEXT_MUTED),
                ft.IconButton(ft.Icons.BLOCK, icon_color=theme.DANGER, icon_size=18,
                              tooltip="Block this remote IP",
                              on_click=lambda e, ip=r["remote_ip"]: self._block(ip)),
            ], spacing=10),
            padding=ft.Padding.symmetric(horizontal=14, vertical=8),
            bgcolor=theme.SURFACE_ALT, border_radius=8, border=ft.Border.all(1, theme.BORDER))

    def _block(self, ip: str) -> None:
        if not ip:
            self.app.toast("No remote IP to block.", ok=False)
            return
        result = self.service.block_ip(ip, note="blocked from Connections view")
        self.app.toast(result.message, ok=result.ok)
