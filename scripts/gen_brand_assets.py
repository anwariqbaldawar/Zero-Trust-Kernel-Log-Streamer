#!/usr/bin/env python3
"""Generate the brand assets: logo, banner, social preview.

Everything is written from this file, so the mark is described once and no
asset can drift from its siblings. The mark is the system's own story reduced
to geometry: a kernel boundary (hexagon), three telemetry paths entering it,
and the LSM hook that stops them (the bar). No gradients, no external fonts,
no raster input.

    python3 scripts/gen_brand_assets.py [--png]

``--png`` also rasterises the social preview and the banner, which GitHub needs
for the repository social image. Rasterising uses resvg (``pip install
resvg-py``) or ``rsvg-convert``; without either, the SVG is still written and
the flag reports that it was skipped.
"""
from __future__ import annotations

import argparse
import math
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ASSETS = ROOT / "assets"

# Palette. Two accents and a neutral set; every asset uses these and nothing
# else, so the README reads as one system.
INK_LIGHT = "#0f172a"     # text on light backgrounds
INK_DARK = "#e6edf7"      # text on dark backgrounds
BLUE = "#0369a1"          # primary: telemetry path
BLUE_SOFT = "#38bdf8"     # primary on dark backgrounds
RED = "#b91c1c"           # enforcement / denial
MUTED_LIGHT = "#64748b"
MUTED_DARK = "#94a3b8"

# Safe stacks: the first name on each list is present on macOS and Windows, the
# last is the DejaVu family every Linux distribution ships, so a rasterised PNG
# and a browser render of the same SVG agree.
FONT = "Verdana, Arial, DejaVu Sans, sans-serif"
MONO = "Menlo, Consolas, DejaVu Sans Mono, monospace"


def hexagon(cx: float, cy: float, r: float) -> str:
    """Pointy-left/right, flat-top hexagon as a path."""
    pts = [(cx + r * math.cos(math.radians(a)), cy + r * math.sin(math.radians(a)))
           for a in (0, 60, 120, 180, 240, 300)]
    return "M " + " L ".join(f"{x:.2f} {y:.2f}" for x, y in pts) + " Z"


def mark(size: float, blue: str, red: str, stroke_scale: float = 1.0) -> str:
    """The mark inside a box of ``size`` px, as SVG markup."""
    s = size / 128.0
    cx = cy = size / 2
    r = 52 * s
    body = [
        f'<path d="{hexagon(cx, cy, r)}" fill="none" stroke="{blue}" '
        f'stroke-width="{6 * s * stroke_scale:.2f}" stroke-linejoin="round"/>',
    ]
    # three telemetry paths entering from the left, stopped by the hook
    for y in (50, 64, 78):
        body.append(
            f'<line x1="{30 * s:.2f}" y1="{y * s:.2f}" x2="{78 * s:.2f}" y2="{y * s:.2f}" '
            f'stroke="{blue}" stroke-width="{4 * s * stroke_scale:.2f}" stroke-linecap="round"/>'
        )
    # the LSM hook: the only red element, and the only thing that stops a path
    body.append(
        f'<rect x="{84 * s:.2f}" y="{38 * s:.2f}" width="{8 * s:.2f}" height="{52 * s:.2f}" '
        f'rx="{4 * s:.2f}" fill="{red}"/>'
    )
    return "\n    ".join(body)


def logo(dark: bool, width: int = 560, height: int = 128) -> str:
    ink = INK_DARK if dark else INK_LIGHT
    blue = BLUE_SOFT if dark else BLUE
    bg = "#0b1220" if dark else "#ffffff"
    return f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}"
     width="{width}" height="{height}" role="img"
     aria-label="xSypher-Stream: a hexagon with three telemetry paths stopped by an enforcement bar">
  <title>xSypher-Stream logo</title>
  <desc>The mark is a kernel boundary with three telemetry paths entering it and a single bar, the LSM hook, stopping them.</desc>
  <rect width="{width}" height="{height}" fill="{bg}"/>
  <g>
    {mark(112, blue, RED)}
  </g>
  <text x="140" y="66" font-family="{FONT}" font-size="31" font-weight="700" fill="{ink}">xSypher<tspan fill="{blue}">-Stream</tspan></text>
  <text x="141" y="95" font-family="{MONO}" font-size="13" fill="{MUTED_DARK if dark else MUTED_LIGHT}">eBPF telemetry, inline LSM enforcement</text>
</svg>
"""


def banner() -> str:
    w, h = 1280, 320
    return f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}"
     width="{w}" height="{h}" role="img"
     aria-label="xSypher-Stream banner: kernel-level zero-trust enforcement for AI agent hosts">
  <title>xSypher-Stream banner</title>
  <desc>A hexagon mark with telemetry paths stopped by an enforcement bar, the project name and a one line description of the tool chain.</desc>
  <rect width="{w}" height="{h}" fill="#0b1220"/>
  <rect x="0" y="0" width="{w}" height="4" fill="{BLUE_SOFT}"/>
  <g transform="translate(72 92)">
    {mark(136, BLUE_SOFT, "#ef4444")}
  </g>
  <text x="248" y="150" font-family="{FONT}" font-size="56" font-weight="700" fill="{INK_DARK}">xSypher<tspan fill="{BLUE_SOFT}">-Stream</tspan></text>
  <text x="250" y="192" font-family="{FONT}" font-size="22" fill="{MUTED_DARK}">Kernel-level zero-trust enforcement for AI agent hosts</text>
  <line x1="250" y1="216" x2="1208" y2="216" stroke="#1e293b" stroke-width="1"/>
  <text x="250" y="248" font-family="{MONO}" font-size="15" fill="{MUTED_DARK}">eBPF CO-RE tracepoints  ->  16 MiB ring buffer  ->  C++20 collector  ->  Python engine  ->  BPF LSM deny</text>
  <text x="250" y="278" font-family="{MONO}" font-size="15" fill="{BLUE_SOFT}">5 tracepoints  ·  5 LSM hooks  ·  6 rules  ·  wire ABI v3  ·  656 / 736 / 32 bytes</text>
</svg>
"""


def social() -> str:
    w, h = 1280, 640
    return f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}"
     width="{w}" height="{h}" role="img"
     aria-label="xSypher-Stream social preview card">
  <title>xSypher-Stream social preview</title>
  <desc>Repository card: the hexagon mark, the project name, a one line description and the enforced invariants.</desc>
  <rect width="{w}" height="{h}" fill="#0b1220"/>
  <rect x="0" y="0" width="{w}" height="6" fill="{BLUE_SOFT}"/>
  <g transform="translate(96 116)">
    {mark(176, BLUE_SOFT, "#ef4444")}
  </g>
  <text x="320" y="196" font-family="{FONT}" font-size="76" font-weight="700" fill="{INK_DARK}">xSypher<tspan fill="{BLUE_SOFT}">-Stream</tspan></text>
  <text x="324" y="248" font-family="{FONT}" font-size="27" fill="{MUTED_DARK}">Zero-trust telemetry and inline enforcement for AI agent hosts</text>
  <rect x="96" y="332" width="1088" height="1" fill="#1e293b"/>
  <text x="96" y="392" font-family="{MONO}" font-size="19" fill="{BLUE_SOFT}">execve  connect  openat  memfd_create  sched_process_exit</text>
  <text x="96" y="426" font-family="{MONO}" font-size="19" fill="{MUTED_DARK}">bprm_check_security  ·  socket_connect  ·  file_open</text>
  <text x="96" y="490" font-family="{FONT}" font-size="19" fill="{INK_DARK}">The decision is made in user space. The denial happens in the kernel.</text>
  <text x="96" y="556" font-family="{MONO}" font-size="17" fill="{MUTED_DARK}">github.com/anwariqbaldawar/Zero-Trust-Kernel-Log-Streamer</text>
</svg>
"""


def rasterise(svg_path: Path, png_path: Path, width: int) -> bool:
    try:
        import resvg_py  # type: ignore
    except ImportError:
        resvg_py = None
    if resvg_py is not None:
        data = resvg_py.svg_to_bytes(svg_path=str(svg_path), width=width,
                                     font_dirs=["/usr/share/fonts", "/usr/local/share/fonts"])
        png_path.write_bytes(bytes(data))
        return True
    if shutil.which("rsvg-convert"):
        subprocess.run(["rsvg-convert", "-w", str(width), "-o", str(png_path), str(svg_path)],
                       check=True)
        return True
    return False


def write(name: str, content: str) -> Path:
    path = ASSETS / name
    path.write_text(content, encoding="utf-8")
    print(f"wrote assets/{name} ({len(content)} bytes)")
    return path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--png", action="store_true", help="also write PNG siblings")
    args = ap.parse_args()

    ASSETS.mkdir(exist_ok=True)
    write("logo-light.svg", logo(dark=False))
    write("logo-dark.svg", logo(dark=True))
    write("banner.svg", banner())
    write("social-preview.svg", social())

    if not args.png:
        return 0
    targets = [("social-preview.svg", "social-preview.png", 1280),
               ("banner.svg", "banner.png", 1280),
               ("logo-light.svg", "logo-light.png", 560)]
    skipped = []
    for svg, png, width in targets:
        if not rasterise(ASSETS / svg, ASSETS / png, width):
            skipped.append(svg)
        else:
            print(f"wrote assets/{png} (width {width})")
    if skipped:
        print("skipped PNG rendering for: " + ", ".join(skipped)
              + " (install resvg-py or rsvg-convert)", file=sys.stderr)
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
