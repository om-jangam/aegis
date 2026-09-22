"""Reusable UI building blocks (Flet 0.86)."""
from __future__ import annotations

import flet as ft

from aegis.core.models import Severity
from aegis.ui import theme


def panel(content: ft.Control, padding: int = 16, expand=None) -> ft.Container:
    return ft.Container(content=content, padding=padding, bgcolor=theme.SURFACE,
                        border=ft.Border.all(1, theme.BORDER), border_radius=12, expand=expand)


def section_title(text: str, icon: ft.IconData | None = None) -> ft.Control:
    row: list[ft.Control] = []
    if icon:
        row.append(ft.Icon(icon, color=theme.PRIMARY, size=20))
    row.append(ft.Text(text, size=18, weight=ft.FontWeight.BOLD, color=theme.TEXT))
    return ft.Row(row, spacing=8)


def severity_badge(severity: Severity | str) -> ft.Container:
    name = severity.value if isinstance(severity, Severity) else str(severity)
    color = theme.severity_color(name)
    return ft.Container(
        content=ft.Text(name, size=11, weight=ft.FontWeight.BOLD, color=color),
        bgcolor=ft.Colors.with_opacity(0.15, color),
        border=ft.Border.all(1, ft.Colors.with_opacity(0.5, color)),
        border_radius=6, padding=ft.Padding.symmetric(horizontal=8, vertical=3))


def pill(text: str, color: str) -> ft.Container:
    return ft.Container(content=ft.Text(text, size=11, color=color, weight=ft.FontWeight.W_600),
                        bgcolor=ft.Colors.with_opacity(0.13, color), border_radius=20,
                        padding=ft.Padding.symmetric(horizontal=10, vertical=4))


def empty_state(text: str, icon: ft.IconData = ft.Icons.INBOX_OUTLINED) -> ft.Container:
    return ft.Container(
        content=ft.Column([ft.Icon(icon, color=theme.TEXT_MUTED, size=42),
                           ft.Text(text, color=theme.TEXT_MUTED, size=14)],
                          horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=10),
        alignment=ft.Alignment.CENTER, padding=40, expand=True)
