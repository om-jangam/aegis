"""Native Flet dashboard visualisations.

These intentionally avoid ``flet_charts``.  Some desktop clients render the
optional chart extension as a blank grey surface, while standard Flet controls
work consistently in both the packaged desktop app and development mode.
"""
from __future__ import annotations

import flet as ft

from aegis.ui import theme


def _bar(value: float, color: str) -> ft.ProgressBar:
    return ft.ProgressBar(
        value=max(0.0, min(value, 1.0)), color=color,
        bgcolor=theme.SURFACE_ALT, bar_height=8, border_radius=4,
    )


def severity_pie(by_severity: dict[str, int]) -> ft.Control:
    """Show severity distribution as a compact, reliable native control."""
    palette = {
        "CRITICAL": theme.CRIT,
        "HIGH": theme.DANGER,
        "MEDIUM": theme.WARN,
        "LOW": theme.OK,
        "INFO": theme.INFO,
    }
    total = sum(by_severity.values())
    if not total:
        return ft.Container(
            content=ft.Text("No alerts yet.", color=theme.TEXT_MUTED),
            alignment=ft.Alignment.CENTER,
            expand=True,
        )

    rows: list[ft.Control] = []
    for name, color in palette.items():
        count = by_severity.get(name, 0)
        if not count:
            continue
        rows.append(ft.Column([
            ft.Row([
                ft.Text(name.title(), size=12, color=theme.TEXT, expand=True),
                ft.Text(f"{count} ({count / total:.0%})", size=12, color=theme.TEXT_MUTED),
            ]),
            _bar(count / total, color),
        ], spacing=4))
    return ft.Column(rows, spacing=10, alignment=ft.MainAxisAlignment.CENTER, expand=True)


def alerts_timeline_bar(timeline: list[tuple[str, int]]) -> ft.Control:
    """Show the last 12 hours of alert activity without a chart extension."""
    points = timeline[-12:]
    if not points:
        return ft.Container(
            content=ft.Text("No alert activity in the last 24 hours.", color=theme.TEXT_MUTED),
            alignment=ft.Alignment.CENTER,
            expand=True,
        )
    maximum = max(count for _, count in points) or 1
    columns: list[ft.Control] = []
    for hour, count in points:
        columns.append(ft.Container(
            content=ft.Column([
                ft.Text(str(count), size=10, color=theme.TEXT_MUTED, text_align=ft.TextAlign.CENTER),
                ft.Container(
                    height=max(6, round(120 * count / maximum)),
                    bgcolor=theme.PRIMARY, border_radius=4,
                ),
                ft.Text(hour[-2:], size=10, color=theme.TEXT_MUTED, text_align=ft.TextAlign.CENTER),
            ], alignment=ft.MainAxisAlignment.END, horizontal_alignment=ft.CrossAxisAlignment.CENTER,
               spacing=5),
            expand=True,
            alignment=ft.Alignment.BOTTOM_CENTER,
        ))
    return ft.Row(columns, spacing=6, vertical_alignment=ft.CrossAxisAlignment.END, expand=True)
