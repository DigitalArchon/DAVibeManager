#!/bin/bash
# Smoke-test the AppImage in clean containers of the distros DAVibeManager targets, under a virtual
# display (X, or Wayland for CachyOS, which is used with KDE Plasma on Wayland): with WebKitGTK missing (must open in the browser and say why), then with it installed
# (app window, a live terminal session, a screenshot of the page in dist/test/<distro>.png).
#   packaging/test-appimage.sh [ubuntu debian fedora arch cachyos]   (default: all)
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
APPIMAGE="$(realpath "${APPIMAGE:-$(ls -t dist/DAVibeManager-*-x86_64.AppImage | head -1)}")"   # or APPIMAGE=path
mkdir -p dist/test

declare -A IMAGE BASE WEBKIT
IMAGE[ubuntu]=docker.io/library/ubuntu:24.04;     BASE[ubuntu]="apt-get update -qq && apt-get install -y -qq xvfb >/dev/null";  WEBKIT[ubuntu]="apt-get install -y -qq gir1.2-webkit2-4.1 >/dev/null"
IMAGE[debian]=docker.io/library/debian:trixie;    BASE[debian]="${BASE[ubuntu]}";                                              WEBKIT[debian]="${WEBKIT[ubuntu]}"
IMAGE[fedora]=registry.fedoraproject.org/fedora:latest; BASE[fedora]="dnf install -y -q xorg-x11-server-Xvfb >/dev/null";       WEBKIT[fedora]="dnf install -y -q webkit2gtk4.1 >/dev/null"
IMAGE[arch]=docker.io/library/archlinux:latest;   BASE[arch]="pacman -Syu --noconfirm -q xorg-server-xvfb >/dev/null";         WEBKIT[arch]="pacman -S --noconfirm -q webkit2gtk-4.1 >/dev/null"
IMAGE[cachyos]=docker.io/cachyos/cachyos:latest;  BASE[cachyos]="pacman -Syu --noconfirm -q weston ttf-dejavu >/dev/null"
# CachyOS's pacman won't run its install hooks in a container (sandbox vs network access): do what a
# real install's hooks do for GTK (image loaders, schemas, MIME database)
WEBKIT[cachyos]="${WEBKIT[arch]} 2>/dev/null; gdk-pixbuf-query-loaders --update-cache; glib-compile-schemas /usr/share/glib-2.0/schemas; update-mime-database /usr/share/mime"
# how the display is provided: an X server, or a headless Wayland compositor (no X at all)
XSERVER='Xvfb :99 -screen 0 1600x1000x24 >/dev/null 2>&1 & export DISPLAY=:99; sleep 1'
WAYLAND='mkdir -p -m 700 /tmp/xdg && export XDG_RUNTIME_DIR=/tmp/xdg && unset DISPLAY
  weston --backend=headless --socket=wayland-1 --width=1600 --height=1000 >/dev/null 2>&1 &
  export WAYLAND_DISPLAY=wayland-1 GDK_BACKEND=wayland; sleep 2'
declare -A SCREEN=([cachyos]="$WAYLAND")

status=0
for d in "${@:-ubuntu debian fedora arch cachyos}"; do
  for name in $d; do
    echo "== $name (${IMAGE[$name]})"
    podman run --rm -v "$APPIMAGE:/app/DAVibeManager.AppImage:ro,Z" -v "$PWD/packaging/appimage/smoke.py:/app/smoke.py:ro,Z" \
        -v "$PWD/dist/test:/out:Z" "${IMAGE[$name]}" bash -c "
      set -e
      ${BASE[$name]}
      cd /tmp && /app/DAVibeManager.AppImage --appimage-extract >/dev/null
      A=/tmp/squashfs-root; PY=\$A/usr/python/bin/python3
      ${SCREEN[$name]:-$XSERVER}
      BROWSER=echo \$PY -I /app/smoke.py \$A /out $name fallback
      ${WEBKIT[$name]}
      \$PY -I /app/smoke.py \$A /out $name full
    " 2>&1 | grep -E '^(PASS|FAIL)|^  \| |Traceback|Error:' | grep -vE 'libEGL|MESA-EGL' || status=1
  done
done
exit $status
