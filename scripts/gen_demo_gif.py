#!/usr/bin/env python3
"""Render ``assets/demo-session.txt`` into ``assets/demo.gif``.

The transcript is produced by ``scripts/capture_demo.py`` from two real runs.
This script is a terminal emulator for the subset those runs use: SGR colour,
bold, dim, inverse-free line flow and wrap at the captured column count. It
draws each frame with Pillow, assembles one loop and quantises every frame
against a single palette so the file stays small.

    python3 scripts/gen_demo_gif.py [--columns 88] [--rows 26] [--fps 12]

Requires Pillow. The DejaVu fonts are used because they ship with every Linux
distribution; any monospace face with box-drawing glyphs works.
"""
from __future__ import annotations

import argparse
import re
from dataclasses import dataclass, field
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
SESSION = ROOT / "assets" / "demo-session.txt"
OUT = ROOT / "assets" / "demo.gif"

FONT_DIR = Path("/usr/share/fonts/truetype/dejavu")
FONT_REGULAR = FONT_DIR / "DejaVuSansMono.ttf"
FONT_BOLD = FONT_DIR / "DejaVuSansMono-Bold.ttf"

# Terminal palette. Deliberately close to the values an operator sees, with
# enough contrast on the dark canvas to survive GIF quantisation.
BG = "#0b1220"
CHROME = "#161f31"
BORDER = "#243149"
FG = "#dbe3f0"
DIM = "#7b8aa5"
PROMPT = "#67e8f9"
CURSOR = "#67e8f9"

ANSI_COLORS = {
    30: "#64748b", 31: "#f87171", 32: "#4ade80", 33: "#fbbf24",
    34: "#7dd3fc", 35: "#c084fc", 36: "#67e8f9", 37: "#dbe3f0",
    90: "#7b8aa5", 91: "#fca5a5", 92: "#86efac", 93: "#fde68a",
    94: "#bae6fd", 95: "#d8b4fe", 96: "#a5f3fc", 97: "#f8fafc",
}
ANSI_BG = {41: "#991b1b", 42: "#14532d", 43: "#78350f", 44: "#1e3a8a", 45: "#4c1d95"}

SGR = re.compile(r"\x1b\[([0-9;]*)m")
CLEAR = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07]*\x07")


@dataclass
class Style:
    fg: str = FG
    bg: str | None = None
    bold: bool = False
    dim: bool = False


@dataclass
class Line:
    runs: list[tuple[str, Style]] = field(default_factory=list)

    def text(self) -> str:
        return "".join(t for t, _ in self.runs)


def parse_line(raw: str) -> Line:
    """Turn one captured line into styled runs."""
    line = Line()
    style = Style()
    pos = 0
    for match in SGR.finditer(raw):
        chunk = raw[pos:match.start()]
        if chunk:
            line.runs.append((chunk, Style(style.fg, style.bg, style.bold, style.dim)))
        pos = match.end()
        codes = [int(c) if c else 0 for c in match.group(1).split(";")]
        for code in codes:
            if code == 0:
                style = Style()
            elif code == 1:
                style.bold = True
            elif code == 2:
                style.dim = True
            elif code == 22:
                style.bold = style.dim = False
            elif code in ANSI_COLORS:
                style.fg = ANSI_COLORS[code]
            elif code in ANSI_BG:
                style.bg = ANSI_BG[code]
            elif code == 49:
                style.bg = None
    tail = raw[pos:]
    if tail:
        line.runs.append((tail, style))
    if CLEAR.search(line.text()):
        cleaned = CLEAR.sub("", line.text())
        line.runs = [(cleaned, style)]
    return line


def wrap(line: Line, columns: int) -> list[Line]:
    """Hard-wrap a styled line at ``columns``, the way a terminal does."""
    if len(line.text()) <= columns:
        return [line]
    out: list[Line] = []
    current = Line()
    used = 0
    for text, style in line.runs:
        for char in text:
            current.runs.append((char, style))
            used += 1
            if used == columns:
                out.append(current)
                current = Line()
                used = 0
    if current.runs:
        out.append(current)
    return out


def load_session() -> list[dict[str, object]]:
    acts: list[dict[str, object]] = []
    kind: str | None = None
    buf: list[str] = []
    for raw in SESSION.read_text(encoding="utf-8").splitlines():
        if raw in ("@@cmd", "@@out"):
            if kind is not None:
                acts[-1][kind] = buf
            if raw == "@@cmd":
                acts.append({"cmd": [], "out": []})
            kind = raw[2:]
            buf = []
        else:
            buf.append(raw)
    if kind is not None and acts:
        acts[-1][kind] = buf
    return acts


def command_frames(cmd: str, columns: int) -> list[int]:
    """Character counts per frame while the command is typed."""
    counts: list[int] = []
    shown = 0
    while shown < len(cmd):
        shown = min(len(cmd), shown + 2)
        counts.append(shown)
        if len(counts) == 1:
            counts.insert(0, min(len(cmd), 1))
    return counts or [0]


def build_timeline(acts, columns: int, rows: int) -> list[tuple[list[Line], int]]:
    """Return (visible window, duration_ms) per frame."""
    screen: list[Line] = []
    timeline: list[tuple[list[Line], int]] = []

    def window() -> list[Line]:
        return screen[-rows:]

    for act in acts:
        cmd = "".join(act["cmd"]).strip()
        out_lines = list(act["out"])
        if out_lines and out_lines[0].startswith("[xsypher] WARNING: alert log"):
            # the log fallback is accurate but it is noise in a 20 second loop
            out_lines = out_lines[1:]
            while out_lines and not out_lines[0].strip():
                out_lines.pop(0)
        styled: list[Line] = []
        for raw in out_lines:
            styled.extend(wrap(parse_line(raw), columns))

        for count in command_frames(cmd, columns):
            typed = Line([("$ ", Style(PROMPT, None, True)), (cmd[:count], Style(FG))])
            timeline.append((window() + [typed], 85))
        timeline.append((window() + [Line([("$ ", Style(PROMPT, None, True)), (cmd, Style(FG))])], 420))

        revealed = 0
        per_frame = 2
        while revealed < len(styled):
            revealed = min(len(styled), revealed + per_frame)
            visible = styled[:revealed]
            timeline.append((window() + visible, 170))
        screen.extend(styled)
        screen.append(Line())
        timeline.append((window(), 1400))
    timeline.append((window(), 2400))
    return timeline


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--columns", type=int, default=88)
    ap.add_argument("--rows", type=int, default=24)
    ap.add_argument("--fps", type=int, default=12)
    ap.add_argument("--width", type=int, default=720)
    ap.add_argument("--font-size", type=int, default=13)
    args = ap.parse_args()

    body_pad = 16
    chrome_h = 36
    font = ImageFont.truetype(str(FONT_REGULAR), args.font_size)
    font_bold = ImageFont.truetype(str(FONT_BOLD), args.font_size)
    advance = font.getlength("M")
    line_h = round(args.font_size * 1.45)
    # The canvas follows the widest line the captured terminal could print, so
    # no character is ever clipped.
    width = max(args.width, int(args.columns * advance + 2 * body_pad + 6))
    body_h = args.rows * line_h
    height = chrome_h + body_h + body_pad * 2

    acts = load_session()
    timeline = build_timeline(acts, args.columns, args.rows)
    print(f"{len(timeline)} frames, {width}x{height}, {advance:.2f}px advance")

    def draw(lines: list[Line], cursor_on: bool) -> Image.Image:
        img = Image.new("RGB", (width, height), BG)
        d = ImageDraw.Draw(img)
        d.rectangle([0, 0, width, chrome_h - 1], fill=CHROME)
        d.rectangle([0, chrome_h - 1, width, chrome_h], fill=BORDER)
        for i, colour in enumerate(("#f87171", "#fbbf24", "#4ade80")):
            cx = 18 + i * 16
            d.ellipse([cx - 4, chrome_h // 2 - 4, cx + 4, chrome_h // 2 + 4], fill=colour)
        d.text((86, chrome_h // 2 - 7), "xsypher-stream  ~  demo", font=font, fill=DIM)

        y0 = chrome_h + body_pad
        for row, line in enumerate(lines):
            y = y0 + row * line_h
            x = body_pad
            for text, style in line.runs:
                if not text:
                    continue
                draw_font = font_bold if style.bold else font
                colour = DIM if style.dim else style.fg
                w = draw_font.getlength(text)
                if style.bg:
                    d.rectangle([x - 2, y - 2, x + w + 2, y + line_h - 2], fill=style.bg)
                d.text((x, y), text, font=draw_font, fill=colour)
                x += w
            if cursor_on and row == len(lines) - 1:
                d.rectangle([x + 1, y, x + 9, y + 13], fill=CURSOR)
        return img

    frames: list[Image.Image] = []
    for index, (lines, duration) in enumerate(timeline):
        img = draw(lines, cursor_on=(index % 2 == 0))
        frames.append(img)

    # One palette for every frame: the render only uses the colours above, so a
    # fixed palette avoids per-frame palettes and keeps the file small.
    palette_src = Image.new("RGB", (width, 64), BG)
    swatches = [BG, CHROME, BORDER, FG, DIM, PROMPT] + list(ANSI_COLORS.values()) + list(ANSI_BG.values())
    pd = ImageDraw.Draw(palette_src)
    for i, colour in enumerate(swatches):
        pd.rectangle([i * 8, 0, i * 8 + 7, 63], fill=colour)
    palette = palette_src.quantize(colors=64, method=Image.Quantize.MEDIANCUT)

    quantised = [f.quantize(palette=palette, dither=Image.Dither.NONE) for f in frames]
    durations = [duration for _, duration in timeline]

    OUT.parent.mkdir(parents=True, exist_ok=True)
    quantised[0].save(
        OUT,
        save_all=True,
        append_images=quantised[1:],
        duration=durations,
        loop=0,
        optimize=True,
        disposal=2,
    )
    size = OUT.stat().st_size
    total = sum(durations) / 1000
    print(f"wrote {OUT.relative_to(ROOT)}: {size / 1e6:.2f} MB, {total:.1f}s, {len(frames)} frames")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
