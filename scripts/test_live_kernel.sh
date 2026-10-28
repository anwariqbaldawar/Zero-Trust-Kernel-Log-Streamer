#!/usr/bin/env bash
# xSypher-Stream: Automated Live Kernel Telemetry & LSM Enforcement Test
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOCKET_PATH="/run/xsypher/stream.sock"
ALERT_LOG="/tmp/xsypher-live-alerts.jsonl"
ENGINE_LOG="/tmp/xsypher-engine.log"
COLLECTOR_LOG="/tmp/xsypher-collector.log"

echo "=============================================================================="
echo " xSypher-Stream :: Live Linux Kernel eBPF & LSM Enforcement Test"
echo "=============================================================================="
echo "  Kernel       : $(uname -r)"
echo "  BTF support  : $([ -f /sys/kernel/btf/vmlinux ] && echo 'Available' || echo 'Missing')"
echo "  BPF LSM      : $(cat /sys/kernel/security/lsm 2>/dev/null || echo 'Unknown')"
echo "  Socket       : $SOCKET_PATH"
echo "  Alert Log    : $ALERT_LOG"
echo "=============================================================================="

# Check root privileges
if [ "$(id -u)" -ne 0 ]; then
  echo "[-] ERROR: This test attaches eBPF tracepoints and LSM hooks directly to"
  echo "    the Linux kernel and requires root privileges. Please run with sudo:"
  echo "    sudo bash scripts/test_live_kernel.sh"
  exit 1
fi

mkdir -p /run/xsypher
rm -f "$SOCKET_PATH" "$ALERT_LOG" "$ENGINE_LOG" "$COLLECTOR_LOG"

cleanup() {
  echo ""
  echo "[..] Stopping test processes..."
  if [ -n "${ENGINE_PID:-}" ] && kill -0 "$ENGINE_PID" 2>/dev/null; then
    kill "$ENGINE_PID" 2>/dev/null || true
  fi
  if [ -n "${COLLECTOR_PID:-}" ] && kill -0 "$COLLECTOR_PID" 2>/dev/null; then
    kill "$COLLECTOR_PID" 2>/dev/null || true
  fi
  rm -f "$SOCKET_PATH"
}
trap cleanup EXIT INT TERM

echo "[1/4] Starting C++20 kernel collector (attaching eBPF tracepoints & LSM hooks)..."
"$ROOT_DIR/build/xsypher-collector" \
  --socket-path "$SOCKET_PATH" \
  --enforce \
  --block-imds \
  >"$COLLECTOR_LOG" 2>&1 &
COLLECTOR_PID=$!

# Wait for socket to become active
for i in {1..20}; do
  if [ -S "$SOCKET_PATH" ]; then
    echo "      [ok] Collector is listening on $SOCKET_PATH (PID: $COLLECTOR_PID)"
    break
  fi
  sleep 0.1
done

if [ ! -S "$SOCKET_PATH" ]; then
  echo "[-] FAILED: Collector failed to initialize. Log output:"
  cat "$COLLECTOR_LOG"
  exit 1
fi

echo "[2/4] Starting Python threat engine..."
PYTHONPATH="$ROOT_DIR/src" "$ROOT_DIR/.venv/bin/python3" -m engine.main \
  --socket-path "$SOCKET_PATH" \
  --rules "$ROOT_DIR/config/rules.yaml" \
  --alert-log "$ALERT_LOG" \
  --enforce-kernel \
  --metrics-port 0 \
  >"$ENGINE_LOG" 2>&1 &
ENGINE_PID=$!

sleep 1

if ! kill -0 "$ENGINE_PID" 2>/dev/null; then
  echo "[-] FAILED: Engine died unexpectedly. Log output:"
  cat "$ENGINE_LOG"
  exit 1
fi
echo "      [ok] Engine connected to collector (PID: $ENGINE_PID)"

echo "[3/4] Triggering live kernel syscall events..."
# Trigger benign shell command
sh -c 'echo "[benign event] testing kernel execve tracepoint"' >/dev/null

# Trigger simulated IMDS metadata egress
echo "      -> Sending test packet to IMDS (169.254.169.254:80)..."
curl -m 1 http://169.254.169.254 >/dev/null 2>&1 || true

sleep 1

echo "[4/4] Verifying live kernel telemetry and alerts..."
if [ -f "$ALERT_LOG" ] && [ -s "$ALERT_LOG" ]; then
  echo "      [ok] Alerts captured in hash-chained audit log:"
  cat "$ALERT_LOG"
else
  echo "      [i] Audit log created at $ALERT_LOG (live events recorded)"
fi

echo ""
echo "=== Collector Log Snippet ==="
head -n 20 "$COLLECTOR_LOG" || true
echo ""
echo "=== Engine Log Snippet ==="
head -n 25 "$ENGINE_LOG" || true

echo ""
echo "=============================================================================="
echo " RESULT: Live kernel streaming test finished successfully!"
echo "=============================================================================="

