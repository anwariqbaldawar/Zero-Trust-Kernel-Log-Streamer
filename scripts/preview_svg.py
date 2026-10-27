#!/usr/bin/env python3
"""Rasterise the hand-written SVGs for visual review.

No SVG renderer is available in this environment, so this implements the small
element subset the figures use: rect, line, circle, polyline-ish path, and text
with tspans, class-based styles and anchors. It is a review tool, not a
conforming renderer: enough to catch a collision, a stray label or a colour
mistake before the figure ships.

  python3 scripts/preview_svg.py docs/fig-frame.svg /tmp/frame.png
"""
from __future__ import annotations

import re
import sys
import xml.etree.ElementTree as ET

from PIL import Image, ImageDraw, ImageFont

NS = "{http://www.w3.org/2000/svg}"
FONTS = {
    (False, False): "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    (True, False): "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    (False, True): "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    (True, True): "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf",
}
SCALE = 2


def parse_css(raw: str) -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    block = re.search(r"<style><!\[CDATA\[(.*?)\]\]></style>", raw, re.S)
    if not block:
        return out
    for cls, body in re.findall(r"\.([a-z0-9-]+)\s*\{([^}]*)\}", block.group(1)):
        props = {}
        for decl in body.split(";"):
            if ":" in decl:
                k, _, v = decl.partition(":")
                props[k.strip()] = v.strip()
        out[cls] = props
    return out


def font_for(size: float, mono: bool, bold: bool):
    path = FONTS[(bold, mono)]
    return ImageFont.truetype(path, int(round(size * SCALE)))


def px(v: str | None, default: float = 0) -> float:
    if v is None:
        return default
    m = re.match(r"-?[0-9.]+", v)
    return float(m.group(0)) if m else default


def col(v: str | None, default: str | None = None) -> str | None:
    if not v or v == "none":
        return default
    return v


def arrow(draw, x1, y1, x2, y2, color):
    # crude arrowhead at the end of a segment
    import math

    ang = math.atan2(y2 - y1, x2 - x1)
    size = 7 * SCALE
    for side in (+1, -1):
        a = ang + side * 2.6
        draw.line([(x2 * SCALE, y2 * SCALE),
                   (x2 * SCALE + size * math.cos(a), y2 * SCALE + size * math.sin(a))], fill=color, width=SCALE)


def render(path: str, out_path: str) -> None:
    raw = open(path, encoding="utf-8").read()
    css = parse_css(raw)
    root = ET.fromstring(raw)
    vb = [float(v) for v in root.get("viewBox", "0 0 800 600").split()]
    W, H = int(vb[2] * SCALE), int(vb[3] * SCALE)
    img = Image.new("RGB", (W, H), "white")
    d = ImageDraw.Draw(img)

    for el in root.iter():
        tag = el.tag.replace(NS, "")
        get = el.get

        if tag == "rect":
            x, y = px(get("x")), px(get("y"))
            w, h = px(get("width")), px(get("height"))
            r = px(get("rx"))
            fill = col(get("fill"), None)
            stroke = col(get("stroke"), None)
            sw = max(1, int(px(get("stroke-width"), 1) * SCALE))
            box = [x * SCALE, y * SCALE, (x + w) * SCALE, (y + h) * SCALE]
            if r:
                d.rounded_rectangle(box, radius=r * SCALE, fill=fill, outline=stroke, width=sw)
            else:
                d.rectangle(box, fill=fill, outline=stroke, width=sw)

        elif tag == "line":
            x1, y1, x2, y2 = (px(get(k)) for k in ("x1", "y1", "x2", "y2"))
            color = col(get("stroke"), "#000000")
            width = max(1, int(px(get("stroke-width"), 1) * SCALE))
            dash = get("stroke-dasharray")
            if dash:
                total = ((x2 - x1) ** 2 + (y2 - y1) ** 2) ** 0.5
                if total and px(dash.split()[0]) > 0:
                    step = px(dash.split()[0])
                    gap = px(dash.split()[1]) if len(dash.split()) > 1 else step
                    pos = 0.0
                    while pos < total:
                        end = min(pos + step, total)
                        d.line([(x1 + (x2 - x1) * pos / total) * SCALE, (y1 + (y2 - y1) * pos / total) * SCALE,
                                (x1 + (x2 - x1) * end / total) * SCALE, (y1 + (y2 - y1) * end / total) * SCALE],
                               fill=color, width=width)
                        pos = end + gap
            else:
                d.line([x1 * SCALE, y1 * SCALE, x2 * SCALE, y2 * SCALE], fill=color, width=width)

        elif tag == "circle":
            cx, cy, r = px(get("cx")), px(get("cy")), px(get("r"))
            d.ellipse([(cx - r) * SCALE, (cy - r) * SCALE, (cx + r) * SCALE, (cy + r) * SCALE],
                      fill=col(get("fill"), None), outline=col(get("stroke"), None))

        elif tag == "path":
            d_attr = get("d", "")
            nums = [float(n) for n in re.findall(r"-?[0-9.]+", d_attr)]
            pts = [(nums[i] * SCALE, nums[i + 1] * SCALE) for i in range(0, len(nums) - 1, 2)]
            color = col(get("stroke"), "#000000")
            width = max(1, int(px(get("stroke-width"), 1) * SCALE))
            fill = col(get("fill"), None)
            if len(pts) >= 2:
                if fill and len(pts) > 2:
                    d.polygon(pts, fill=fill)
                d.line(pts, fill=color, width=width, joint="curve")
                if get("marker-end"):
                    arrow(d, pts[-2][0] / SCALE, pts[-2][1] / SCALE, pts[-1][0] / SCALE, pts[-1][1] / SCALE, color)

        elif tag == "text":
            x, y = px(get("x")), px(get("y"))
            cls = (get("class") or "").split()
            props = css.get(cls[0], {}) if cls else {}
            size = px(props.get("font-size"), 12)
            mono = "mono" in str(props.get("font-family", "")).lower()
            bold = str(props.get("font-weight", "")) in ("600", "700", "bold")
            color = col(get("fill")) or col(props.get("fill"), "#0f172a")
            anchor = get("text-anchor") or "start"

            runs = []
            if len(el):
                for tspan in el:
                    runs.append((tspan.text or "", col(tspan.get("fill"), color)))
            else:
                runs.append((el.text or "", color))

            full = "".join(t for t, _ in runs)
            f = font_for(size, mono, bold)
            width = d.textlength(full, font=f) / SCALE
            ox = x - (width if anchor == "end" else width / 2 if anchor == "middle" else 0)

            rot = re.search(r"rotate\(\s*(-?[0-9.]+)\s+([-0-9.]+)\s+([-0-9.]+)\s*\)", get("transform") or "")
            if rot:
                ang, cx, cy = float(rot.group(1)), float(rot.group(2)), float(rot.group(3))
                wpx = int(d.textlength(full, font=f)) + 4
                hpx = int(size * SCALE * 1.6) + 4
                tile = Image.new("RGBA", (wpx, hpx), (0, 0, 0, 0))
                td = ImageDraw.Draw(tile)
                td.text((2, 2), full, font=f, fill=runs[0][1])
                tile = tile.rotate(-ang, expand=True)
                px_ = int((x - width / 2) * SCALE) - tile.width // 2
                py_ = int(y * SCALE) - int(size * 0.78 * SCALE) - tile.height // 2
                img.paste(tile, (px_, py_), tile)
                continue

            cursor = ox
            for text, fill in runs:
                if not text:
                    continue
                d.text((cursor * SCALE, (y - size * 0.78) * SCALE), text, font=f, fill=fill)
                cursor += d.textlength(text, font=f) / SCALE

    img.save(out_path)
    print(f"{path} -> {out_path} ({W}x{H})")


if __name__ == "__main__":
    render(sys.argv[1], sys.argv[2])
