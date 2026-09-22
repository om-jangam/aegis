"""Network activity: which programs are talking to which addresses."""
from __future__ import annotations

import flet as ft

from aegis.platforms import privilege_hint
from aegis.response.firewall import is_admin
from aegis.ui import components as c
from aegis.ui import theme
from aegis.ui.plain import connection_state, plural
from aegis.ui.views.base import BaseView


class ConnectionsView(BaseView):
    title = "Network Activity"
    icon = ft.Icons.LAN_OUTLINED

    def build(self) -> ft.Control:
        self.search = ft.TextField(hint_text="Search by program or address",
                                   prefix_icon=ft.Icons.SEARCH, on_change=lambda e: self.refresh(),
                                   border_color=theme.BORDER, height=44, content_padding=10,
                                   color=theme.TEXT)
        self.count = ft.Text("", size=12, color=theme.TEXT_MUTED)
        self.rows = ft.ListView(spacing=6, expand=True, padding=4)
        return ft.Column([
            ft.Row([c.section_title("Network Activity", ft.Icons.LAN_OUTLINED),
                    ft.Container(expand=True), self.count]),
            ft.Text("Programs on this computer that use the network, and the addresses they "
                    "talk to. Block an address you do not trust.", size=12,
                    color=theme.TEXT_MUTED),
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
            c.empty_state("No network activity recorded yet.", ft.Icons.LAN_OUTLINED)]
        self.count.value = plural(len(filtered), "connection")
        self.safe_update()

    def _row(self, r: dict) -> ft.Control:
        block: ft.Control
        if r["remote_ip"]:
            where = f"{r['remote_ip']}  port {r['remote_port']}"
            admin = is_admin()
            block = ft.IconButton(
                ft.Icons.BLOCK, icon_color=theme.DANGER if admin else theme.TEXT_MUTED,
                icon_size=18, disabled=not admin,
                tooltip="Block this address" if admin
                else "Blocking needs administrator rights (run Aegis as administrator)",
                on_click=lambda e, row=r: self._confirm_block(row))
        else:
            where = f"Waiting for incoming connections on port {r['local_port']}"
            block = ft.Container(width=40)
        return ft.Container(
            content=ft.Row([
                ft.Text(r["process_name"] or "Unknown program", width=190, size=13,
                        color=theme.TEXT, no_wrap=True, overflow=ft.TextOverflow.ELLIPSIS,
                        weight=ft.FontWeight.W_600, tooltip=f"Process ID {r['pid']}"),
                ft.Text(where, size=12, color=theme.TEXT, expand=True, no_wrap=True,
                        overflow=ft.TextOverflow.ELLIPSIS, selectable=True),
                ft.Text(connection_state(r["status"]), width=170, size=11,
                        color=theme.TEXT_MUTED),
                c.pill(r["protocol"] or "", theme.INFO),
                block,
            ], spacing=10),
            padding=ft.Padding.symmetric(horizontal=14, vertical=8),
            bgcolor=theme.SURFACE_ALT, border_radius=8, border=ft.Border.all(1, theme.BORDER))

    def _confirm_block(self, row: dict) -> None:
        ip = row["remote_ip"]
        if not is_admin():
            self.app.toast(f"Blocking needs administrator rights. {privilege_hint()}", ok=False)
            return

        def block(e):
            self.page.pop_dialog()
            result = self.service.block_ip(ip, note="blocked from Network Activity")
            self.app.toast(result.message, ok=result.ok)

        self.page.show_dialog(ft.AlertDialog(
            modal=True, title=ft.Text(f"Block {ip}?"),
            content=ft.Text(f"No program on this computer, including "
                            f"{row['process_name'] or 'this one'}, will be able to reach this "
                            f"address. You can undo this on the Firewall page."),
            actions=[ft.TextButton("Cancel", on_click=lambda e: self.page.pop_dialog()),
                     ft.FilledButton("Block address", icon=ft.Icons.BLOCK, on_click=block)]))
