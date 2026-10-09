#!/bin/bash
# Build DAVibeManager's AppImage reproducibly with rootless Podman (see packaging/README.md).
#   packaging/build-appimage.sh build   AppImage of HEAD -> dist/
#   packaging/build-appimage.sh check   build HEAD twice from scratch and compare the hashes
#   packaging/build-appimage.sh lock    re-resolve packaging/appimage/*.lock (review, then commit)
# Only committed files are built (git archive HEAD); SOURCE_DATE_EPOCH is HEAD's commit time.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
. packaging/appimage/pins.sh
mode="${1:-build}"

command -v podman >/dev/null || { echo "Podman is needed: sudo apt install podman (or dnf/pacman)" >&2; exit 1; }
if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
    echo "Note: uncommitted changes are not built; this builds HEAD ($(git rev-parse --short HEAD))." >&2
fi
for ca in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/cert.pem; do
    [ -f "$ca" ] && break
done

TAG="davibemanager-appimage-builder:$(cat packaging/appimage/Containerfile packaging/appimage/pins.sh | sha256sum | cut -c1-12)"
if ! podman image exists "$TAG"; then
    podman build -t "$TAG" -v "$ca:/hostca.crt:ro,Z" \
        --build-arg BASE_IMAGE="$BASE_IMAGE" --build-arg APT_SNAPSHOT="$APT_SNAPSHOT" \
        -f packaging/appimage/Containerfile packaging/appimage
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
git archive --format=tar HEAD > "$WORK/src.tar"
EPOCH="$(git log -1 --format=%ct HEAD)"
VERSION="$(python3 -c 'import tomllib; print(tomllib.load(open("pyproject.toml", "rb"))["project"]["version"])')"
CACHE="${XDG_CACHE_HOME:-$HOME/.cache}/davibemanager-appimage"
mkdir -p "$CACHE" dist

run() {  # out-dir mode
    mkdir -p "$1"
    podman run --rm -v "$WORK/src.tar:/src.tar:ro,Z" -v "$CACHE:/cache:Z" -v "$1:/out:Z" \
        -e SOURCE_DATE_EPOCH="$EPOCH" -e VERSION="$VERSION" "$TAG" \
        bash -c 'tar -xOf /src.tar packaging/appimage/build.sh > /tmp/build.sh && bash /tmp/build.sh "$0"' "$2"
}

case "$mode" in
    build)
        run "$PWD/dist" build ;;
    check)
        run "$WORK/a" build
        rm -rf "$CACHE/pip"          # the second build downloads its wheels again
        run "$WORK/b" build
        a=$(cut -d' ' -f1 "$WORK"/a/*.sha256); b=$(cut -d' ' -f1 "$WORK"/b/*.sha256)
        if [ "$a" = "$b" ]; then
            cp "$WORK"/a/* dist/
            echo "Reproducible: both builds are $a"
        else
            echo "NOT reproducible: $a vs $b (compare with diffoscope; copies in dist/check-a, dist/check-b)" >&2
            rm -rf dist/check-a dist/check-b && cp -r "$WORK/a" dist/check-a && cp -r "$WORK/b" dist/check-b
            exit 1
        fi ;;
    lock)
        run "$WORK/lock" lock
        cp "$WORK"/lock/*.lock packaging/appimage/
        git --no-pager diff --stat -- packaging/appimage/*.lock ;;
    *)
        echo "usage: $0 build|check|lock" >&2; exit 2 ;;
esac
