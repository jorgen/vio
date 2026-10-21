#!/usr/bin/env bash
set -euo pipefail
binary=$1
export LSAN_OPTIONS="suppressions=$(cd "$(dirname "$0")" && pwd)/lsan.supp${LSAN_OPTIONS:+:$LSAN_OPTIONS}"
export XDG_RUNTIME_DIR=$(mktemp -d)
chmod 700 "$XDG_RUNTIME_DIR"
Xvfb :99 -screen 0 1024x768x24 -nolisten tcp >/dev/null 2>&1 &
xvfb=$!
weston --backend=headless --socket=vio-test --idle-time=0 >"$XDG_RUNTIME_DIR/weston.log" 2>&1 &
weston=$!
trap 'kill $xvfb $weston 2>/dev/null || true' EXIT
for _ in $(seq 100); do
  if [ -S "$XDG_RUNTIME_DIR/vio-test" ] && [ -e /tmp/.X11-unix/X99 ]; then break; fi
  sleep 0.1
done
DISPLAY=:99 WAYLAND_DISPLAY=vio-test "$binary"
