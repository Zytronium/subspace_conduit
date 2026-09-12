#!/usr/bin/env bash

set -euo pipefail

gui_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$gui_dir"

echo "=== Linux: Debian, RPM, and AppImage ==="
npm run build:linux

echo "=== Windows: x86_64 executable ==="
npm run build:windows

echo "All requested artifacts were built."