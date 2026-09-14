"""Firewall rules management view."""
from __future__ import annotations

import flet as ft

from aegis.core.models import FirewallAction, FirewallDirection, FirewallRule, Protocol
from aegis.response.firewall import is_admin
from aegis.ui import components as c
from aegis.ui import theme
from aegis.ui.views.base import BaseView


class RulesView(BaseView):
    title = "Firewall Rules"
    icon = ft.Icons.SHIELD_OUTLINED

    def build(self) -> ft.Control:
        self.search = ft.TextField(hint_text="Search rules…", prefix_icon=ft.Icons.SEARCH,
                                   on_change=lambda e: self.refresh(), border_color=theme.BORDER,
                                   height=44, content_padding=10, expand=True, color=theme.TEXT)
        self.status = ft.Text("", size=12, color=theme.TEXT_MUTED)
        self.rule_list = ft.ListView(spacing=8, expand=True, padding=4)
        toolbar = ft.Row([
            self.search,
            ft.IconButton(ft.Icons.REFRESH, icon_color=theme.PRIMARY, on_click=lambda e: self.refresh()),
            ft.FilledButton("New Rule", icon=ft.Icons.ADD, on_click=self._open_new_rule),
        ], spacing=8)
        return ft.Column([
            ft.Row([c.section_title("Firewall Rules", ft.Icons.SHIELD_OUTLINED),
                    ft.Container(expand=True), self.status]),
            toolbar,
            c.panel(self.rule_list, expand=True),
        ], spacing=14, expand=True)

    def refresh(self) -> None:
        try:
            rules = self.service.firewall.list_rules(only_aegis=True)
        except Exception as exc:  # noqa: BLE001
            self.status.value = f"Error: {exc}"
            self.safe_update()
            return
        kw = (self.search.value or "").casefold()
        if kw:
            rules = [r for r in rules if kw in (r.name + r.remote_ip).casefold()]
        self.rule_list.controls = [self._card(r) for r in rules] or [
            c.empty_state("No Aegis-managed rules yet. Click “New Rule”.", ft.Icons.SHIELD_OUTLINED)]
        self.status.value = f"{len(rules)} rule(s) · {'Admin' if is_admin() else 'Standard user (create/delete needs admin)'}"
        self.safe_update()

    def _display_name(self, name: str) -> str:
        from aegis import LEGACY_RULE_TAG, RULE_TAG
        for tag in (RULE_TAG, LEGACY_RULE_TAG):
            if name.startswith(tag):
                return name[len(tag):].strip()
        return name

    def _card(self, rule: FirewallRule) -> ft.Control:
        action_color = theme.OK if rule.action == FirewallAction.ALLOW else theme.DANGER
        dir_icon = (ft.Icons.SOUTH_WEST if rule.direction == FirewallDirection.IN
                    else ft.Icons.NORTH_EAST)
        return ft.Container(
            content=ft.Row([
                ft.Icon(ft.Icons.SHIELD, color=theme.OK if rule.enabled else theme.TEXT_MUTED,
                        size=20),
                ft.Column([
                    ft.Text(self._display_name(rule.name), color=theme.TEXT,
                            weight=ft.FontWeight.W_600, no_wrap=True,
                            overflow=ft.TextOverflow.ELLIPSIS),
                    ft.Text(f"{rule.remote_ip}:{rule.remote_port}", size=11, color=theme.TEXT_MUTED),
                ], spacing=1, expand=True, tight=True),
                ft.Icon(dir_icon, size=16, color=theme.TEXT_MUTED, tooltip=rule.direction.value),
                c.pill(rule.protocol.value, theme.INFO),
                c.pill(rule.action.value, action_color),
                ft.Switch(value=rule.enabled, active_color=theme.PRIMARY,
                          on_change=lambda e, n=rule.name: self._toggle(n, e.control.value)),
                ft.IconButton(ft.Icons.DELETE_OUTLINE, icon_color=theme.DANGER,
                              on_click=lambda e, n=rule.name: self._confirm_delete(n)),
            ], spacing=12),
            padding=ft.Padding.symmetric(horizontal=14, vertical=10),
            bgcolor=theme.SURFACE_ALT, border_radius=10, border=ft.Border.all(1, theme.BORDER))

    def _toggle(self, name: str, enabled: bool) -> None:
        r = self.service.set_rule_enabled(name, enabled)
        self.app.toast(r.message, ok=r.ok)
        self.refresh()

    def _confirm_delete(self, name: str) -> None:
        def do(e):
            self.page.pop_dialog()
            r = self.service.delete_rule(name)
            self.app.toast(r.message, ok=r.ok)
            self.refresh()
        dlg = ft.AlertDialog(modal=True, title=ft.Text("Delete firewall rule?"),
                             content=ft.Text(f"Permanently remove:\n\n{name}"),
                             actions=[ft.TextButton("Cancel", on_click=lambda e: self.page.pop_dialog()),
                                      ft.FilledButton("Delete", icon=ft.Icons.DELETE, on_click=do)])
        self.page.show_dialog(dlg)

    def _open_new_rule(self, e=None) -> None:
        name = ft.TextField(label="Rule name *", border_color=theme.BORDER, color=theme.TEXT, dense=True)
        direction = ft.Dropdown(label="Direction", value="Out",
                                options=[ft.DropdownOption("In"), ft.DropdownOption("Out")])
        action = ft.Dropdown(label="Action", value="Block",
                             options=[ft.DropdownOption(x) for x in ["Allow", "Block"]])
        protocol = ft.Dropdown(label="Protocol", value="TCP",
                               options=[ft.DropdownOption(x) for x in ["TCP", "UDP", "Any"]])
        remote_ip = ft.TextField(label="Remote IP", hint_text="any / 1.2.3.4", border_color=theme.BORDER,
                                 color=theme.TEXT, dense=True)
        remote_port = ft.TextField(label="Remote port", hint_text="any / 80,443",
                                   border_color=theme.BORDER, color=theme.TEXT, dense=True)
        error = ft.Text("", color=theme.DANGER, size=12)

        def create(e):
            rule = FirewallRule(
                name=name.value or "",
                direction=FirewallDirection.IN if direction.value == "In" else FirewallDirection.OUT,
                action=FirewallAction(action.value),
                protocol=Protocol[protocol.value.upper()],
                remote_ip=remote_ip.value or "any", remote_port=remote_port.value or "any")
            result = self.service.create_rule(rule)
            if result.ok:
                self.page.pop_dialog()
                self.app.toast(result.message, ok=True)
                self.refresh()
            else:
                error.value = result.message
                error.update()

        form = ft.Column([name, ft.Row([direction, action], spacing=10), protocol,
                          ft.Row([remote_ip, remote_port], spacing=10), error],
                         spacing=10, width=460, height=340, tight=True)
        dlg = ft.AlertDialog(modal=True, title=ft.Text("New firewall rule"), content=form,
                             actions=[ft.TextButton("Cancel", on_click=lambda e: self.page.pop_dialog()),
                                      ft.FilledButton("Create", icon=ft.Icons.CHECK, on_click=create)])
        self.page.show_dialog(dlg)
