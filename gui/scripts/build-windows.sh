#!/usr/bin/env bash

set -euo pipefail

gui_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
project_root="$(cd "$gui_dir/.." && pwd)"
target="x86_64-pc-windows-msvc"
exe="$project_root/target/$target/release/gui.exe"
artifact_dir="$project_root/build-artifacts-2026-09-11/windows"

if ! command -v cargo-xwin >/dev/null 2>&1; then
  echo "cargo-xwin is required. Install it with: cargo install cargo-xwin" >&2
  exit 1
fi

if ! rustup target list --installed | grep -qx "$target"; then
  echo "Rust target $target is required. Install it with: rustup target add $target" >&2
  exit 1
fi

cd "$gui_dir"
echo "Building Windows x64 executable..."
CI=false npm run tauri -- build \
  --runner cargo-xwin \
  --target "$target" \
  --no-bundle

if [[ ! -f "$exe" ]]; then
  echo "Windows build completed, but the executable was not found at $exe" >&2
  exit 1
fi

mkdir -p "$artifact_dir"
cp "$exe" "$artifact_dir/subspace_conduit.exe"

echo "Created $artifact_dir/subspace_conduit.exe ($(du -h "$artifact_dir/subspace_conduit.exe" | cut -f1))."