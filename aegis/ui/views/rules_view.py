"""Firewall: the rules Aegis created, described in plain sentences."""
from __future__ import annotations

import flet as ft

from aegis.core.models import FirewallAction, FirewallDirection, FirewallRule, Protocol
from aegis.platforms import privilege_hint
from aegis.response.firewall import is_admin
from aegis.ui import components as c
from aegis.ui import theme
from aegis.ui.plain import plural
from aegis.ui.views.base import BaseView


def describe_rule(rule: FirewallRule) -> str:
    verb = "Allows" if rule.action == FirewallAction.ALLOW else "Blocks"
    incoming = rule.direction == FirewallDirection.IN
    traffic = "any" if rule.protocol == Protocol.ANY else rule.protocol.value
    who = "any address" if rule.remote_ip in ("", "any") else rule.remote_ip
    port = "" if rule.remote_port in ("", "any") else f" on port {rule.remote_port}"
    return (f"{verb} {'incoming' if incoming else 'outgoing'} {traffic} traffic "
            f"{'from' if incoming else 'to'} {who}{port}")


class RulesView(BaseView):
    title = "Firewall"
    icon = ft.Icons.SHIELD_OUTLINED

    def build(self) -> ft.Control:
        self.admin = is_admin()
        self.search = ft.TextField(hint_text="Search rules", prefix_icon=ft.Icons.SEARCH,
                                   on_change=lambda e: self.refresh(), border_color=theme.BORDER,
                                   height=44, content_padding=10, expand=True, color=theme.TEXT)
        self.status = ft.Text("", size=12, color=theme.TEXT_MUTED)
        self.rule_list = ft.ListView(spacing=8, expand=True, padding=4)
        self.new_btn = ft.FilledButton("New rule", icon=ft.Icons.ADD, on_click=self._open_new_rule,
                                       disabled=not self.admin)
        admin_notice = ft.Container(
            content=ft.Row([
                ft.Icon(ft.Icons.ADMIN_PANEL_SETTINGS_OUTLINED, color=theme.WARN, size=26),
                ft.Column([
                    ft.Text("View only", size=14, color=theme.TEXT, weight=ft.FontWeight.W_600),
                    ft.Text("Adding, changing or deleting firewall rules needs administrator "
                            "rights. Close Aegis, right-click it and choose "
                            "'Run as administrator'.", size=12, color=theme.TEXT_MUTED),
                ], spacing=2, tight=True, expand=True),
            ], spacing=14, vertical_alignment=ft.CrossAxisAlignment.CENTER),
            padding=14, border_radius=10, bgcolor=ft.Colors.with_opacity(0.10, theme.WARN),
            border=ft.Border.all(1, ft.Colors.with_opacity(0.5, theme.WARN)),
            visible=not self.admin)
        return ft.Column([
            ft.Row([c.section_title("Firewall", ft.Icons.SHIELD_OUTLINED),
                    ft.Container(expand=True), self.status]),
            ft.Text("Rules Aegis created to allow or block network traffic. Addresses you "
                    "block appear here, and you can undo them.", size=12, color=theme.TEXT_MUTED),
            admin_notice,
            ft.Row([self.search,
                    ft.IconButton(ft.Icons.REFRESH, icon_color=theme.PRIMARY, tooltip="Refresh",
                                  on_click=lambda e: self.refresh()),
                    self.new_btn], spacing=8),
            c.panel(self.rule_list, expand=True),
        ], spacing=12, expand=True)

    def refresh(self) -> None:
        try:
            rules = self.service.firewall.list_rules(only_aegis=True)
        except Exception as exc:  # noqa: BLE001
            self.status.value = f"Could not read the firewall: {exc}"
            self.safe_update()
            return
        kw = (self.search.value or "").casefold()
        if kw:
            rules = [r for r in rules if kw in (r.name + r.remote_ip).casefold()]
        self.rule_list.controls = [self._card(r) for r in rules] or [
            c.empty_state("Aegis has not created any firewall rules yet.",
                          ft.Icons.SHIELD_OUTLINED)]
        self.status.value = plural(len(rules), "rule")
        self.safe_update()

    def _display_name(self, name: str) -> str:
        from aegis import LEGACY_RULE_TAG, RULE_TAG
        for tag in (RULE_TAG, LEGACY_RULE_TAG):
            if name.startswith(tag):
                return name[len(tag):].strip()
        return name

    def _card(self, rule: FirewallRule) -> ft.Control:
        blocks = rule.action != FirewallAction.ALLOW
        return ft.Container(
            content=ft.Row([
                ft.Icon(ft.Icons.BLOCK if blocks else ft.Icons.CHECK_CIRCLE_OUTLINE,
                        color=(theme.DANGER if blocks else theme.OK) if rule.enabled
                        else theme.TEXT_MUTED, size=20),
                ft.Column([
                    ft.Text(self._display_name(rule.name), color=theme.TEXT,
                            weight=ft.FontWeight.W_600, no_wrap=True,
                            overflow=ft.TextOverflow.ELLIPSIS),
                    ft.Text(describe_rule(rule), size=12, color=theme.TEXT_MUTED),
                ], spacing=2, expand=True, tight=True),
                ft.Text("On" if rule.enabled else "Off", size=12, color=theme.TEXT_MUTED),
                ft.Switch(value=rule.enabled, active_color=theme.PRIMARY, disabled=not self.admin,
                          tooltip="Turn this rule on or off",
                          on_change=lambda e, n=rule.name: self._toggle(n, e.control.value)),
                ft.IconButton(ft.Icons.DELETE_OUTLINE, icon_color=theme.DANGER,
                              disabled=not self.admin, tooltip="Delete this rule",
                              on_click=lambda e, n=rule.name: self._confirm_delete(n)),
            ], spacing=12),
            padding=ft.Padding.symmetric(horizontal=14, vertical=10),
            bgcolor=theme.SURFACE_ALT, border_radius=10, border=ft.Border.all(1, theme.BORDER))

    def _require_admin(self) -> bool:
        if self.admin:
            return True
        self.app.toast(f"This needs administrator rights. {privilege_hint()}", ok=False)
        return False

    def _toggle(self, name: str, enabled: bool) -> None:
        if not self._require_admin():
            return
        r = self.service.set_rule_enabled(name, enabled)
        self.app.toast(r.message, ok=r.ok)
        self.refresh()

    def _confirm_delete(self, name: str) -> None:
        if not self._require_admin():
            return

        def do(e):
            self.page.pop_dialog()
            r = self.service.delete_rule(name)
            self.app.toast(r.message, ok=r.ok)
            self.refresh()
        self.page.show_dialog(ft.AlertDialog(
            modal=True, title=ft.Text("Delete this firewall rule?"),
            content=ft.Text(f"{self._display_name(name)}\n\nThis cannot be undone."),
            actions=[ft.TextButton("Cancel", on_click=lambda e: self.page.pop_dialog()),
                     ft.FilledButton("Delete", icon=ft.Icons.DELETE, on_click=do)]))

    def _open_new_rule(self, e=None) -> None:
        if not self._require_admin():
            return
        name = ft.TextField(label="Name", hint_text="For example: Block suspicious server",
                            border_color=theme.BORDER, color=theme.TEXT, dense=True)
        direction = ft.Dropdown(label="Traffic", value="Out", options=[
            ft.DropdownOption(key="Out", text="Outgoing (from this computer)"),
            ft.DropdownOption(key="In", text="Incoming (to this computer)")])
        action = ft.Dropdown(label="Action", value="Block", options=[
            ft.DropdownOption(key="Block", text="Block"),
            ft.DropdownOption(key="Allow", text="Allow")])
        protocol = ft.Dropdown(label="Protocol", value="TCP", options=[
            ft.DropdownOption(key="TCP", text="TCP"), ft.DropdownOption(key="UDP", text="UDP"),
            ft.DropdownOption(key="Any", text="Any protocol")])
        remote_ip = ft.TextField(label="Address", hint_text="Leave empty for any address",
                                 border_color=theme.BORDER, color=theme.TEXT, dense=True)
        remote_port = ft.TextField(label="Port", hint_text="Leave empty for any port",
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
                         spacing=10, width=520, height=340, tight=True)
        self.page.show_dialog(ft.AlertDialog(
            modal=True, title=ft.Text("New firewall rule"), content=form,
            actions=[ft.TextButton("Cancel", on_click=lambda e: self.page.pop_dialog()),
                     ft.FilledButton("Create rule", icon=ft.Icons.CHECK, on_click=create)]))
