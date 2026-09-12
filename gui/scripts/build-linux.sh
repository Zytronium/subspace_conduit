#!/usr/bin/env bash

set -euo pipefail

gui_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
project_root="$(cd "$gui_dir/.." && pwd)"
artifact_dir="$project_root/build-artifacts-2026-09-11/linux"
bundle_dir="$project_root/target/release/bundle/appimage"
app_dir="$bundle_dir/subspace_conduit.AppDir"
appimage="$bundle_dir/subspace_conduit_0.1.0_amd64.AppImage"
plugin="${XDG_CACHE_HOME:-$HOME/.cache}/tauri/linuxdeploy-plugin-appimage.AppImage"

cd "$gui_dir"

echo "Building Debian and RPM bundles..."
CI=false npm run tauri -- build --bundles deb,rpm

echo "Preparing the AppImage AppDir..."
set +e
CI=false npm run tauri -- build --bundles appimage
tauri_status=$?
set -e

if [[ ! -d "$app_dir" ]]; then
  echo "AppImage bundling did not leave an AppDir (exit status $tauri_status)." >&2
  exit "$tauri_status"
fi

if [[ ! -x "$plugin" ]]; then
  echo "Missing cached AppImage packager: $plugin" >&2
  exit 1
fi

# linuxdeploy's strip step is incompatible with some current Arch/CachyOS ELF
# libraries (.relr.dyn).  The AppDir is complete before that step, so package
# it directly with the already cached AppImage plugin instead.
cp "$gui_dir/src-tauri/icons/128x128.png" "$app_dir/gui.png"
rm -f "$appimage" "$bundle_dir/subspace_conduit-x86_64.AppImage"

(
  cd "$bundle_dir"
  APPIMAGE_EXTRACT_AND_RUN=1 "$plugin" --appdir "$(basename "$app_dir")"
)

mv "$bundle_dir/subspace_conduit-x86_64.AppImage" "$appimage"
chmod +x "$appimage"

mkdir -p "$artifact_dir"
rm -f "$artifact_dir"/*.deb "$artifact_dir"/*.rpm "$artifact_dir"/*.AppImage
cp "$project_root"/target/release/bundle/deb/subspace_conduit_*.deb "$artifact_dir/"
cp "$project_root"/target/release/bundle/rpm/subspace_conduit*.rpm "$artifact_dir/"
cp "$appimage" "$artifact_dir/"

if [[ "$tauri_status" -ne 0 ]]; then
  echo "Tauri linuxdeploy failed after creating the AppDir; direct AppImage packaging succeeded."
fi
echo "Created Linux artifacts in $artifact_dir."