#!/usr/bin/env python3
"""Capture a real xSypher-Stream session for the README demo GIF.

Two commands, both executed here, byte for byte:

  1. ``python3 -m engine.main --simulate --enforce-kernel`` - the operator view:
     alerts with their resolved lineage and the LSM denials that follow.
  2. ``tests/simulate_mcp_attack.py`` - the end-to-end harness: 10,000 benign
     events, five attack chains and eight expected policy commands over a real
     AF_UNIX socket.

Nothing is staged or reordered. The engine truncates alert bodies to the width
of its terminal and suppresses colour when stdout is not a TTY, so both
commands run under a pty with an explicit window size. The result is stored in
``assets/demo-session.txt`` and rendered by ``scripts/gen_demo_gif.py``.

    python3 scripts/capture_demo.py [--columns 88] [--events 10000]
"""
from __future__ import annotations

import argparse
import fcntl
import os
import pty
import select
import signal
import struct
import subprocess
import termios
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "assets" / "demo-session.txt"


def _spawn(argv: list[str], columns: int, rows: int, env: dict[str, str]):
    primary, secondary = pty.openpty()
    fcntl.ioctl(secondary, termios.TIOCSWINSZ, struct.pack("HHHH", rows, columns, 0, 0))
    proc = subprocess.Popen(
        argv,
        stdin=secondary,
        stdout=secondary,
        stderr=secondary,
        cwd=str(ROOT),
        env=env,
        preexec_fn=os.setsid,
        close_fds=True,
    )
    os.close(secondary)
    return primary, proc


def _drain(fd: int, buffers: list[bytes], deadline: float, quiet_after: float,
           stop: subprocess.Popen, on_data=None) -> bool:
    """Read until the process exits and stays quiet, or until deadline."""
    last_data = time.monotonic()
    while time.monotonic() < deadline:
        ready, _, _ = select.select([fd], [], [], 0.1)
        if ready:
            try:
                chunk = os.read(fd, 65536)
            except OSError:
                return True
            if not chunk:
                return True
            buffers.append(chunk)
            last_data = time.monotonic()
            if on_data is not None:
                on_data(b"".join(buffers))
            continue
        if stop.poll() is not None and time.monotonic() - last_data > quiet_after:
            return True
    return False


def _text(buffers: list[bytes]) -> str:
    raw = b"".join(buffers).decode("utf-8", "replace")
    return raw.replace("\r\n", "\n").replace("\r", "")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--columns", type=int, default=88)
    ap.add_argument("--rows", type=int, default=40)
    ap.add_argument("--events", type=int, default=10000)
    ap.add_argument("--engine-events", type=int, default=120)
    args = ap.parse_args()

    OUT.parent.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env["PYTHONPATH"] = "src"
    env["PYTHONUNBUFFERED"] = "1"
    env.setdefault("TERM", "xterm-256color")

    records: list[tuple[str, str]] = []

    # -- act 1: the operator view --------------------------------------- #
    engine = [
        "python3", "-m", "engine.main", "--simulate", "--enforce-kernel", "--quiet",
        "--simulate-count", str(args.engine_events),
    ]
    records.append(("cmd", "PYTHONPATH=src " + " ".join(engine)))
    fd, proc = _spawn(engine, args.columns, args.rows, env)
    buffers: list[bytes] = []
    _drain(fd, buffers, time.monotonic() + 120.0, 0.5, proc)
    proc.wait(timeout=30)
    os.close(fd)
    records.append(("out", _text(buffers)))

    # -- act 2: the end-to-end harness ---------------------------------- #
    harness = ["python3", "tests/simulate_mcp_attack.py", "--events", str(args.events)]
    records.append(("cmd", "PYTHONPATH=src " + " ".join(harness)))
    fd, proc = _spawn(harness, args.columns, args.rows, env)
    buffers = []
    _drain(fd, buffers, time.monotonic() + 180.0, 0.5, proc)
    proc.wait(timeout=30)
    os.close(fd)
    records.append(("out", _text(buffers)))

    with OUT.open("w", encoding="utf-8") as fh:
        for kind, payload in records:
            fh.write(f"@@{kind}\n")
            if not payload.endswith("\n"):
                payload += "\n"
            fh.write(payload)

    lines = sum(p.count("\n") for _, p in records)
    width = max((len(ln) for _, p in records for ln in p.splitlines()), default=0)
    print(f"wrote {OUT.relative_to(ROOT)}: {lines} lines, widest {width} columns")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
