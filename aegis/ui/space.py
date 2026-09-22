"""A calm deep-space backdrop for the console.

One still picture: a dark gradient, a few thousand small, dim stars and a faint
Milky-Way band. Nothing moves, so it costs nothing while the app is in use; it
is drawn once in numpy (well under a second) and saved, so later starts load it
instantly.
"""
from __future__ import annotations

import logging
import math
import struct
import threading
import zlib
from dataclasses import dataclass
from pathlib import Path

import flet as ft
import flet.canvas as cv
import numpy as np

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class StarLayer:
    density: float                  # stars per 10,000 square pixels
    radius: tuple[float, float]     # smallest and largest star radius, in pixels
    brightness: tuple[float, float]


STARS = (
    StarLayer(density=12.0, radius=(0.35, 0.6), brightness=(0.20, 0.55)),   # distant
    StarLayer(density=3.0, radius=(0.55, 0.9), brightness=(0.40, 0.75)),
    StarLayer(density=0.5, radius=(0.8, 1.3), brightness=(0.60, 0.90)),    # nearest
)
#: Very faint dust along a diagonal band, which the eye reads as the Milky Way.
DUST = StarLayer(density=90.0, radius=(0.3, 0.5), brightness=(0.06, 0.22))
#: Mostly white, some blue-white, a few warm.
STAR_COLORS = np.array([(255, 255, 255), (255, 255, 255), (214, 228, 255),
                        (190, 214, 255), (255, 236, 210)], dtype=np.float64)
#: Bump when the look changes, so saved pictures are redrawn.
SKY_VERSION = 2
#: Pictures are drawn for window sizes rounded up to this step and reused.
SKY_STEP = 160


# --------------------------------------------------------------------------- #
# Geometry
# --------------------------------------------------------------------------- #
def scatter(width: float, height: float, density: float,
            rng: np.random.Generator) -> np.ndarray:
    """Uniformly scattered (x, y) points over the area."""
    count = int(width * height / 10_000 * density)
    return rng.uniform((0, 0), (width, height), size=(count, 2))


def band(width: float, height: float, density: float, rng: np.random.Generator,
         spread: float = 0.12) -> np.ndarray:
    """(x, y) points clustered around the diagonal from bottom-left to top-right."""
    count = int(width * height / 10_000 * density)
    angle = math.atan2(-height, width)
    ux, uy = math.cos(angle), math.sin(angle)          # along the band
    nx, ny = -uy, ux                                   # across it
    length, thickness = math.hypot(width, height), spread * min(width, height)
    kept = np.empty((0, 2))
    while len(kept) < count:
        n = int((count - len(kept)) * 1.6) + 16
        along = rng.uniform(-length / 2, length / 2, n)
        across = rng.normal(0, thickness, n) * (1 + 0.35 * np.sin(along / 90))
        pts = np.column_stack((width / 2 + along * ux + across * nx,
                               height / 2 + along * uy + across * ny))
        inside = ((pts[:, 0] >= 0) & (pts[:, 0] <= width)
                  & (pts[:, 1] >= 0) & (pts[:, 1] <= height))
        kept = np.vstack((kept, pts[inside]))
    return kept[:count]


def sky_bucket(width: float, height: float) -> tuple[int, int]:
    """The drawing size for a window, rounded up to ``SKY_STEP`` so pictures are reused."""
    return (int(math.ceil(max(width, 1) / SKY_STEP) * SKY_STEP),
            int(math.ceil(max(height, 1) / SKY_STEP) * SKY_STEP))


# --------------------------------------------------------------------------- #
# Drawing
# --------------------------------------------------------------------------- #
def encode_png(rgba: np.ndarray) -> bytes:
    """A minimal PNG encoder for an (h, w, 4) uint8 array."""
    height, width, _ = rgba.shape
    raw = np.zeros((height, width * 4 + 1), dtype=np.uint8)   # filter byte 0 per row
    raw[:, 1:] = rgba.reshape(height, width * 4)

    def chunk(kind: bytes, data: bytes) -> bytes:
        return (struct.pack(">I", len(data)) + kind + data
                + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF))

    header = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header)
            + chunk(b"IDAT", zlib.compress(raw.tobytes(), 6)) + chunk(b"IEND", b""))


def _add_stars(alpha: np.ndarray, color: np.ndarray, width: int, height: int,
               points: np.ndarray, layer: StarLayer, rng: np.random.Generator) -> None:
    """Add soft round stars to the running light and colour totals."""
    if not len(points):
        return
    radii = rng.uniform(*layer.radius, size=len(points))
    light = rng.uniform(*layer.brightness, size=len(points))
    tints = STAR_COLORS[rng.integers(0, len(STAR_COLORS), size=len(points))]
    # One row per (star, nearby pixel), summed per pixel with a single bincount.
    reach = max(1, int(math.ceil(layer.radius[1] * 2)))
    span = np.arange(-reach, reach + 1)
    oy, ox = (a.ravel() for a in np.meshgrid(span, span, indexing="ij"))
    cx = np.floor(points[:, 0]).astype(np.int64)
    cy = np.floor(points[:, 1]).astype(np.int64)
    px, py = cx[:, None] + ox, cy[:, None] + oy
    dist2 = (px + 0.5 - points[:, :1]) ** 2 + (py + 0.5 - points[:, 1:]) ** 2
    weight = light[:, None] * np.exp(-dist2 / (2 * radii[:, None] ** 2))
    inside = (px >= 0) & (px < width) & (py >= 0) & (py < height)
    index, weight = (py * width + px)[inside], weight[inside]
    star = np.broadcast_to(np.arange(len(points))[:, None], px.shape)[inside]
    pixels = width * height
    alpha += np.bincount(index, weight, pixels)
    for channel in range(3):
        color[:, channel] += np.bincount(index, weight * tints[star, channel], pixels)


def render_sky(width: int, height: int, seed: int = 7) -> bytes:
    """The whole starfield as one transparent PNG."""
    rng = np.random.default_rng(seed)
    alpha = np.zeros(width * height)
    color = np.zeros((width * height, 3))
    dust = np.vstack((band(width, height, DUST.density * 0.7, rng),
                      band(width, height, DUST.density * 0.3, rng, spread=0.05)))
    _add_stars(alpha, color, width, height, dust, DUST, rng)
    for layer in STARS:
        _add_stars(alpha, color, width, height,
                   scatter(width, height, layer.density, rng), layer, rng)
    covered = alpha > 1e-4
    rgb = np.zeros_like(color)
    rgb[covered] = color[covered] / alpha[covered, None]
    rgba = np.empty((width * height, 4), dtype=np.uint8)
    rgba[:, :3] = np.clip(rgb, 0, 255).astype(np.uint8)
    rgba[:, 3] = (np.clip(alpha, 0, 1) * 255).astype(np.uint8)
    return encode_png(rgba.reshape(height, width, 4))


def cached_sky(width: int, height: int, cache_dir: Path | None) -> bytes:
    """The sky picture for this size, from disk when it was drawn before."""
    path = cache_dir / f"sky-{width}x{height}-v{SKY_VERSION}.png" if cache_dir else None
    if path is not None:
        try:
            return path.read_bytes()
        except OSError:
            pass
    png = render_sky(width, height)
    if path is not None:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(png)
        except OSError:
            log.debug("Could not save the sky picture", exc_info=True)
    return png


# --------------------------------------------------------------------------- #
# The control
# --------------------------------------------------------------------------- #
class SpaceBackground:
    """A still starfield behind every page. ``visible=False`` leaves a plain dark gradient."""

    def __init__(self, visible: bool = True, cache_dir: Path | None = None):
        self.cache_dir = cache_dir
        self._size: tuple[int, int] | None = None
        self._stars = ft.Container(expand=True, opacity=0, visible=visible,
                                   animate_opacity=ft.Animation(900, ft.AnimationCurve.EASE_OUT))
        self.control = ft.Stack([
            ft.Container(expand=True, gradient=ft.RadialGradient(
                center=ft.Alignment(-0.3, -0.5), radius=1.4,
                colors=["#0d1630", "#070c1c", "#03060e"], stops=[0.0, 0.55, 1.0])),
            cv.Canvas(expand=True, on_resize=self._on_resize),   # reports the window size
            self._stars,
        ], fit=ft.StackFit.EXPAND, expand=True)

    def set_visible(self, visible: bool) -> None:
        self._stars.visible = visible
        self._push()

    def _on_resize(self, e: cv.CanvasResizeEvent) -> None:
        size = sky_bucket(e.width, e.height)
        if e.width <= 0 or e.height <= 0 or size == self._size:
            return
        self._size = size
        threading.Thread(target=self._paint, args=(size,), name="sky", daemon=True).start()

    def _paint(self, size: tuple[int, int]) -> None:
        try:
            png = cached_sky(*size, self.cache_dir)
        except Exception:  # noqa: BLE001 - a missing sky must never break the app
            log.exception("Could not draw the starfield")
            return
        self._stars.image = ft.DecorationImage(src=png, fit=ft.BoxFit.COVER,
                                               alignment=ft.Alignment.TOP_LEFT)
        self._stars.opacity = 1
        self._push()

    def _push(self) -> None:
        try:
            self._stars.update()
        except Exception:  # noqa: BLE001 - not on screen yet, or the window closed
            pass
