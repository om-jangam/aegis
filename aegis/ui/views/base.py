"""Base class for all views."""
from __future__ import annotations

import flet as ft


class BaseView:
    title: str = "View"
    icon: ft.IconData = ft.Icons.CIRCLE

    def __init__(self, app):
        self.app = app
        self.page: ft.Page = app.page
        self.service = app.service
        self.control: ft.Control = self.build()

    def build(self) -> ft.Control:  # pragma: no cover
        return ft.Container()

    def refresh(self) -> None:
        pass

    def safe_update(self) -> None:
        try:
            self.control.update()
        except Exception:  # noqa: BLE001
            pass
