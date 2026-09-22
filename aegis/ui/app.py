"""Main Aegis console (Flet 0.86): sidebar + content, wired to the service."""
from __future__ import annotations

import threading
import time

import flet as ft

from aegis import __app_name__, __version__
from aegis.config import ASSETS_DIR, DATA_DIR, settings
from aegis.service import SecurityService
from aegis.ui import theme
from aegis.ui.space import SpaceBackground
from aegis.ui.views.audit_view import AuditView
from aegis.ui.views.connections_view import ConnectionsView
from aegis.ui.views.dashboard import DashboardView
from aegis.ui.views.detections_view import DetectionsView
from aegis.ui.views.processes_view import ProcessesView
from aegis.ui.views.rules_view import RulesView
from aegis.ui.views.security_check_view import SecurityCheckView
from aegis.ui.views.settings_view import SettingsView

_WELCOME_STEPS = (
    (ft.Icons.HEALTH_AND_SAFETY_OUTLINED, "Check your settings",
     "Security Check finds weak settings and tells you how to fix each one."),
    (ft.Icons.RADAR, "Leave monitoring on",
     "Aegis quietly watches network connections and programs for signs of attack."),
    (ft.Icons.NOTIFICATIONS_ACTIVE_OUTLINED, "Read your alerts",
     "If something looks wrong, Alerts explains what happened and what to do."),
)


class AegisApp:
    def __init__(self, page: ft.Page):
        self.page = page
        self.service = SecurityService()
        #: Latest security-check report, shared by the Home and Security Check pages.
        self.posture_report = None
        self._posture_requested = False
        self._configure_page()

        self.views = [DashboardView(self), SecurityCheckView(self), DetectionsView(self),
                      ConnectionsView(self), ProcessesView(self), RulesView(self),
                      AuditView(self), SettingsView(self)]
        self.active_index = 0
        self.content_host = ft.Container(expand=True, padding=24, content=self.views[0].control)
        self._nav_buttons: list[ft.Container] = []
        #: The icon and text inside each sidebar button, so navigation can
        #: recolour them without digging through the control tree.
        self._nav_labels: list[tuple[ft.Icon, ft.Text]] = []
        self.monitor_btn = ft.FilledButton("Start monitoring", icon=ft.Icons.PLAY_ARROW)

        self.sky = SpaceBackground(visible=settings.space_background,
                                   cache_dir=DATA_DIR / "sky")
        page.add(ft.Stack([
            self.sky.control,
            ft.Row([self._sidebar(), self._main_area()], spacing=0, expand=True),
        ], fit=ft.StackFit.EXPAND, expand=True))

        self.service.on_alert(lambda a: self._safe(self._on_alert))
        if settings.monitoring_enabled:
            self.service.start()
        self.sync_monitor_button()
        self._start_refresh_loop()
        self.navigate(0)
        if not settings.onboarding_done:
            self.show_welcome()

    def _configure_page(self) -> None:
        p = self.page
        p.title = f"{__app_name__} - Security for this computer"
        p.theme_mode = ft.ThemeMode.DARK
        p.theme = ft.Theme(color_scheme_seed=theme.PRIMARY, font_family="Segoe UI")
        p.bgcolor = theme.BG
        p.padding = 0
        try:
            p.window.width = 1280
            p.window.height = 840
            p.window.min_width = 1000
            p.window.min_height = 640
        except Exception:  # noqa: BLE001
            pass

    # -- layout ------------------------------------------------------------- #
    def _sidebar(self) -> ft.Control:
        nav = ft.Column(spacing=6)
        for i, view in enumerate(self.views):
            icon = ft.Icon(view.icon, size=20, color=theme.TEXT_MUTED)
            label = ft.Text(view.title, size=14, color=theme.TEXT_MUTED,
                            weight=ft.FontWeight.W_600)
            btn = ft.Container(
                content=ft.Row([icon, label], spacing=12),
                padding=ft.Padding.symmetric(horizontal=14, vertical=11), border_radius=10,
                ink=True, on_click=lambda e, idx=i: self.navigate(idx))
            self._nav_buttons.append(btn)
            self._nav_labels.append((icon, label))
            nav.controls.append(btn)
        brand = ft.Row([ft.Icon(ft.Icons.SHIELD_MOON, color=theme.PRIMARY, size=30),
                        ft.Column([ft.Text(__app_name__, size=20, weight=ft.FontWeight.BOLD,
                                           color=theme.TEXT),
                                   ft.Text("Keeps this computer safe", size=10,
                                           color=theme.TEXT_MUTED)],
                                  spacing=0, tight=True)], spacing=10)
        return ft.Container(
            content=ft.Column([
                ft.Container(brand, padding=ft.Padding.only(left=18, top=22, bottom=22, right=18)),
                ft.Container(nav, padding=ft.Padding.symmetric(horizontal=12), expand=True),
                ft.Divider(color=theme.BORDER, height=1),
                ft.Container(ft.Text(f"Version {__version__}", size=10, color=theme.TEXT_MUTED),
                             padding=14),
            ], spacing=0, expand=True),
            width=232, bgcolor=theme.SURFACE,
            border=ft.Border.only(right=ft.BorderSide(1, theme.BORDER)))

    def _main_area(self) -> ft.Control:
        self.title_text = ft.Text(self.views[0].title, size=22, weight=ft.FontWeight.BOLD,
                                  color=theme.TEXT)
        self.status_dot = ft.Icon(ft.Icons.CIRCLE, size=12, color=theme.OK)
        self.status_text = ft.Text("Watching", size=12, color=theme.TEXT_MUTED)
        topbar = ft.Container(
            content=ft.Row([self.title_text, ft.Container(expand=True),
                            ft.Row([self.status_dot, self.status_text], spacing=6),
                            self.monitor_btn], vertical_alignment=ft.CrossAxisAlignment.CENTER),
            padding=ft.Padding.symmetric(horizontal=24, vertical=14), bgcolor=theme.SURFACE,
            border=ft.Border.only(bottom=ft.BorderSide(1, theme.BORDER)))
        return ft.Column([topbar, self.content_host], spacing=0, expand=True)

    # -- navigation --------------------------------------------------------- #
    def navigate(self, index: int) -> None:
        self.active_index = index
        view = self.views[index]
        self.content_host.content = view.control
        self.title_text.value = view.title
        for i, (btn, (icon, label)) in enumerate(zip(self._nav_buttons, self._nav_labels,
                                                     strict=True)):
            active = i == index
            btn.bgcolor = theme.SURFACE_ALT if active else None
            icon.color = theme.PRIMARY if active else theme.TEXT_MUTED
            label.color = theme.TEXT if active else theme.TEXT_MUTED
        try:
            view.refresh()
        except Exception:  # noqa: BLE001
            pass
        self.page.update()

    def navigate_to(self, view_type: type) -> None:
        for i, view in enumerate(self.views):
            if isinstance(view, view_type):
                self.navigate(i)
                return

    # -- security check shared between pages -------------------------------- #
    def request_posture(self) -> None:
        """Start the first security check in the background, once."""
        if self._posture_requested:
            return
        self._posture_requested = True
        self.view_of(SecurityCheckView).run_check()

    def posture_updated(self, report) -> None:
        self.posture_report = report
        self.service.record_posture(report)
        if isinstance(self.views[self.active_index], DashboardView):
            self.views[self.active_index].refresh()

    def view_of(self, view_type: type):
        return next(v for v in self.views if isinstance(v, view_type))

    # -- welcome ------------------------------------------------------------ #
    def show_welcome(self) -> None:
        def finish(open_check: bool) -> None:
            settings.onboarding_done = True
            settings.save()
            # Switch pages first: closing the dialog and then redrawing the page in
            # the same handler froze the dialog's fade-out on screen.
            if open_check:
                self.navigate_to(SecurityCheckView)
            self.page.pop_dialog()
            self.page.update()

        steps = [
            ft.Row([
                ft.Container(ft.Icon(icon, color=theme.PRIMARY, size=22),
                             bgcolor=ft.Colors.with_opacity(0.15, theme.PRIMARY),
                             padding=10, border_radius=10),
                ft.Column([ft.Text(f"{n}. {title}", size=14, color=theme.TEXT,
                                   weight=ft.FontWeight.W_600),
                           ft.Text(text, size=12, color=theme.TEXT_MUTED)],
                          spacing=2, tight=True, expand=True),
            ], spacing=14, vertical_alignment=ft.CrossAxisAlignment.START)
            for n, (icon, title, text) in enumerate(_WELCOME_STEPS, start=1)
        ]
        self.page.show_dialog(ft.AlertDialog(
            modal=True,
            title=ft.Row([ft.Icon(ft.Icons.SHIELD_MOON, color=theme.PRIMARY, size=28),
                          ft.Text("Welcome to Aegis", size=22, weight=ft.FontWeight.BOLD)],
                         spacing=10),
            content=ft.Column([
                ft.Text("Aegis watches this computer for attacks and helps you fix weak "
                        "security settings. Three things to know:", size=14),
                *steps,
                ft.Text("Everything stays on this computer. Nothing is sent anywhere.",
                        size=12, color=theme.TEXT_MUTED),
            ], spacing=16, tight=True, width=480),
            actions=[
                ft.TextButton("Skip for now", on_click=lambda e: finish(False)),
                ft.FilledButton("Run my first security check",
                                icon=ft.Icons.HEALTH_AND_SAFETY_OUTLINED,
                                on_click=lambda e: finish(True)),
            ]))

    # -- monitor toggle ----------------------------------------------------- #
    def toggle_monitor(self, e=None) -> None:
        if self.service.running:
            self.service.stop()
        else:
            self.service.start()
        self.sync_monitor_button()
        view = self.views[self.active_index]
        if isinstance(view, DashboardView):
            view.refresh()
        self.page.update()

    def sync_monitor_button(self) -> None:
        running = self.service.running
        self.monitor_btn.content = "Pause monitoring" if running else "Start monitoring"
        self.monitor_btn.icon = ft.Icons.PAUSE if running else ft.Icons.PLAY_ARROW
        self.monitor_btn.on_click = self.toggle_monitor
        self.status_dot.color = theme.OK if running else theme.WARN
        self.status_text.value = "Watching" if running else "Paused"

    # -- live refresh ------------------------------------------------------- #
    def _safe(self, fn) -> None:
        try:
            self.page.run_thread(fn)
        except Exception:  # noqa: BLE001
            pass

    def _on_alert(self) -> None:
        if isinstance(self.views[self.active_index], DashboardView | DetectionsView):
            try:
                self.views[self.active_index].refresh()
            except Exception:  # noqa: BLE001
                pass

    def _start_refresh_loop(self) -> None:
        def loop():
            while True:
                time.sleep(5)
                try:
                    self.page.run_thread(self._tick)
                except Exception:  # noqa: BLE001
                    break
        threading.Thread(target=loop, name="ui-refresh", daemon=True).start()

    def _tick(self) -> None:
        if isinstance(self.views[self.active_index], DashboardView | ConnectionsView | ProcessesView):
            try:
                self.views[self.active_index].refresh()
            except Exception:  # noqa: BLE001
                pass

    # -- toast -------------------------------------------------------------- #
    def toast(self, message: str, ok: bool = True) -> None:
        try:
            self.page.show_dialog(ft.SnackBar(content=ft.Text(message, color="#ffffff"),
                                              bgcolor=theme.OK if ok else theme.DANGER, duration=3500))
        except Exception:  # noqa: BLE001
            pass


def main(page: ft.Page):
    AegisApp(page)


def run():
    from aegis.logging_config import setup_logging
    setup_logging()
    # The cached Windows desktop client is failing to initialize its rendering
    # surface on this host. Serve the same local-only app in the system browser.
    ft.run(main, assets_dir=str(ASSETS_DIR), view=ft.AppView.WEB_BROWSER)
