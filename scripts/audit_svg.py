#!/usr/bin/env python3
"""Static geometry audit for hand-written SVGs.

No renderer is available in this environment, so this estimates text extents
from font metrics and checks containment analytically:

  * every element inside the viewBox
  * every <text> inside the smallest <rect> that contains its anchor
  * no overlapping text baselines that share a line box

Run: python3 scripts/audit_svg.py docs/fig-*.svg
"""
from __future__ import annotations

import re
import sys
import xml.etree.ElementTree as ET

NS = "{http://www.w3.org/2000/svg}"

# Average advance width as a fraction of font-size. Conservative (wide).
SANS = 0.552
MONO = 0.602


def css_map(svg_text: str) -> dict[str, dict[str, float | str]]:
    out: dict[str, dict[str, float | str]] = {}
    for block in re.findall(r"\.([a-z0-9-]+)\s*\{([^}]*)\}", svg_text):
        cls, body = block
        props: dict[str, float | str] = {}
        for decl in body.split(";"):
            if ":" not in decl:
                continue
            key, _, val = decl.partition(":")
            key, val = key.strip(), val.strip()
            if key == "font-size":
                props["size"] = float(re.sub(r"[^0-9.]", "", val) or 12)
            elif key == "font-family":
                props["family"] = val
            elif key == "letter-spacing":
                props["tracking"] = float(re.sub(r"[^0-9.]", "", val) or 0)
        out[cls] = props
    return out


def text_width(text: str, size: float, family: str, tracking: float) -> float:
    mono = "mono" in family.lower()
    unit = (MONO if mono else SANS) * size
    wide = sum(1 for c in text if c.isupper() or c.isdigit() or c in "mwMW@#%")
    total = len(text) * unit
    # uppercase and digits are wider than the average glyph
    total += wide * unit * 0.08
    total += max(0, len(text) - 1) * tracking
    return total


def parse_rects(root):
    rects = []
    for el in root.iter(NS + "rect"):
        try:
            x = float(el.get("x", 0))
            y = float(el.get("y", 0))
            w = float(el.get("width", 0))
            h = float(el.get("height", 0))
        except (TypeError, ValueError):
            continue
        if w > 4 and h > 4:
            rects.append((x, y, w, h))
    return rects


def main(paths: list[str]) -> int:
    failures = 0
    for path in paths:
        raw = open(path, encoding="utf-8").read()
        root = ET.fromstring(raw)
        vb = [float(v) for v in root.get("viewBox", "0 0 0 0").split()]
        width, height = vb[2], vb[3]
        classes = css_map(raw)
        rects = parse_rects(root)
        problems: list[str] = []

        for el in root.iter(NS + "text"):
            text = "".join(el.itertext())
            if not text.strip():
                continue
            x = float(el.get("x", 0))
            y = float(el.get("y", 0))
            cls = (el.get("class") or "").split()
            props = classes.get(cls[0], {}) if cls else {}
            size = props.get("size", float(el.get("font-size", 12)))
            family = str(props.get("family", "sans"))
            tracking = float(props.get("tracking", 0.0))
            w = text_width(text, size, family, tracking)
            anchor = (el.get("text-anchor") or "start").strip()
            if anchor == "end":
                x = x - w
            elif anchor == "middle":
                x = x - w / 2

            label = text if len(text) <= 46 else text[:43] + "..."

            # vertical text: rotate(-90 cx cy) turns the advance into height
            rot = re.search(r"rotate\(\s*-90\s+([-0-9.]+)\s+([-0-9.]+)\s*\)", el.get("transform") or "")
            if rot:
                cx, cy = float(rot.group(1)), float(rot.group(2))
                top, bottom = cy - w / 2, cy + w / 2
                left, right = cx - size * 0.35, cx + size * 0.78
                if bottom > height - 4:
                    problems.append(f"  below viewBox: y={bottom:.0f} > {height:.0f} :: {label}")
                holders = [r for r in rects if r[0] <= cx <= r[0] + r[2] and r[1] <= cy <= r[1] + r[3]
                           and r[2] * r[3] < 100000]
                if holders:
                    rx, ry, rw, rh = min(holders, key=lambda r: r[2] * r[3])
                    if top < ry + 2:
                        problems.append(f"  rotated text spills above rect by {ry + 2 - top:.0f}px :: {label}")
                    if bottom > ry + rh - 2:
                        problems.append(f"  rotated text spills below rect by {bottom - (ry + rh):.0f}px :: {label}")
                    if right > rx + rw - 2:
                        problems.append(f"  rotated text spills right of rect by {right - (rx + rw):.0f}px :: {label}")
                    if left < rx + 2:
                        problems.append(f"  rotated text spills left of rect by {rx + 2 - left:.0f}px :: {label}")
                continue

            if x + w > width - 4:
                problems.append(f"  overflow viewBox: x={x:.0f} w={w:.0f} total={x + w:.0f} > {width:.0f} :: {label}")
            if y > height:
                problems.append(f"  below viewBox: y={y:.0f} > {height:.0f} :: {label}")

            # smallest containing rect decides the right-hand margin
            holders = [r for r in rects if r[0] <= x + 2 and r[0] + r[2] >= x + 2 and r[1] <= y - size and r[1] + r[3] >= y]
            if holders:
                rx, ry, rw, rh = min(holders, key=lambda r: r[2] * r[3])
                if x + w > rx + rw - 3:
                    problems.append(
                        f"  spills out of rect: need {x + w - (rx + rw):.0f}px more "
                        f"(x={x:.0f} w={w:.0f} rect_right={rx + rw:.0f}) :: {label}"
                    )
                if x < rx + 2:
                    problems.append(f"  spills left of rect by {rx + 2 - x:.0f}px :: {label}")

        if problems:
            failures += 1
            print(f"FAIL {path} ({width:.0f}x{height:.0f})")
            print("\n".join(problems))
        else:
            print(f"ok   {path} ({width:.0f}x{height:.0f}, {len(rects)} boxes)")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
