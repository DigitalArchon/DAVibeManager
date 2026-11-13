#!/bin/bash
# Run the test suite on what ships: the AppImage's own Python and the packages locked into it,
# not a developer's venv, which has whatever was newest the day it was made (and, made with
# --system-site-packages, the distribution's copies too). See packaging/README.md.
#   packaging/test-locked.sh [pytest arguments]     (default: the whole suite, -q)
# APPIMAGE=path tests another than the newest dist/DAVibeManager-*-x86_64.AppImage.
#
# The AppImage is unpacked into a temporary folder and its Python (-I: nothing of this machine's
# Python or of the checkout on its path) runs the checkout's tests/ against the davibemanager
# installed in the image, which must be this checkout's: the files that are not are named, and
# nothing runs. pytest and pytest-asyncio are not in the image. They are installed from
# appimage/test-requirements.lock, with hashes, into a folder of their own that goes last on the
# path, so nothing they bring stands in for a package that ships. Tests that need a display, Xvfb
# or Node skip without them, as they do anywhere.
# This machine needs git, GNU tar, curl and the network: for those few wheels, and for the
# pinned Python the build uses (pins.sh), whose pip installs them, when the build's cache
# (~/.cache/davibemanager-appimage) hasn't it.
set -euo pipefail

for tool in git tar curl sha256sum cmp; do
    command -v "$tool" >/dev/null || { echo "Nothing tested: $0 needs $tool, which this machine lacks." >&2; exit 1; }
done
top="$(git rev-parse --show-toplevel)"
cd "$top"
. packaging/appimage/pins.sh

LOCK=packaging/appimage/test-requirements.lock
if [ ! -f "$LOCK" ]; then
    echo "Nothing tested: $LOCK is not there. It pins pytest and pytest-asyncio (test-requirements.in)" \
         "with hashes; packaging/build-appimage.sh lock writes it. Review it, commit it, and run this again." >&2
    exit 1
fi
if [ -z "${APPIMAGE:-}" ]; then
    APPIMAGE="$(ls -t dist/DAVibeManager-*-x86_64.AppImage 2>/dev/null | head -n 1 || true)"
fi
if [ -z "$APPIMAGE" ] || [ ! -f "$APPIMAGE" ] || [ ! -x "$APPIMAGE" ]; then
    echo "Nothing tested: no AppImage to run (${APPIMAGE:-none in dist/}). Build one with" \
         "packaging/build-appimage.sh build, or name one: APPIMAGE=path $0" >&2
    exit 1
fi
APPIMAGE="$(realpath -- "$APPIMAGE")"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
WORK="$(realpath -- "$WORK")"       # as Python will name it, should TMPDIR go through a link

(cd "$WORK" && "$APPIMAGE" --appimage-extract >/dev/null)
PY="$WORK/squashfs-root/usr/python/bin/python3"
SHIPPED="$("$PY" -I -c 'import davibemanager, os; print(os.path.dirname(davibemanager.__file__))')"
case "$SHIPPED" in
    "$WORK"/squashfs-root/*) ;;
    *) echo "Nothing tested: the AppImage's Python finds davibemanager in $SHIPPED, outside the image." >&2; exit 1 ;;
esac

# The tests are the checkout's, and what they test is the image's: one built from another commit
# would pass or fail for what is not in this one. Every file of the davibemanager installed in the
# image must be, byte for byte, the file of that name in src/.
not_this_checkout() {  # installed-package source-folder -> the installed files that are not the source's
    (cd "$1" && find . -name __pycache__ -prune -o -type f -print0 | sort -z) | while IFS= read -r -d '' file; do
        cmp -s "$1/$file" "$2/$file" || printf '%s\n' "${file#./}"
    done
}
other="$(not_this_checkout "$SHIPPED" "$top/src/davibemanager")"
if [ -n "$other" ]; then
    echo "Nothing tested: $APPIMAGE was not built from this checkout. Of the davibemanager in it, these are" \
         "not as they are in src/davibemanager:" >&2
    while IFS= read -r line; do echo "  $line" >&2; done <<< "$other"
    echo "Build this commit (packaging/build-appimage.sh build), or check out the one the AppImage is of." >&2
    exit 1
fi

fetch() {  # url sha256 dest: download once into the cache, always verify (build.sh's)
    local url=$1 sum=$2 dest=$3
    if [ ! -f "$dest" ] || ! echo "$sum  $dest" | sha256sum -c --quiet - 2>/dev/null; then
        # https only, redirects included: a hash proves what arrived, not who saw it asked for
        curl --proto '=https' --tlsv1.2 -fsSL --retry 3 -o "$dest.part" "$url"
        echo "$sum  $dest.part" | sha256sum -c --quiet -
        mv "$dest.part" "$dest"
    fi
}
# The image has no pip (nothing is installed at run time), so the test tools are installed by the
# pip of the Python the image's was copied from: the same version, so the same wheels fit.
# --isolated: no pip.conf or PIP_ variable of this machine's names another index or lifts a check.
# (pip trusts this machine's CA store, where this Python looks for one, under /etc/ssl; where it
# is kept elsewhere, SSL_CERT_FILE names it, as AppRun does for the app.)
CACHE="${XDG_CACHE_HOME:-$HOME/.cache}/davibemanager-appimage"
mkdir -p "$CACHE" "$WORK/pip-python" "$WORK/test-tools"
fetch "$PBS_URL" "$PBS_SHA256" "$CACHE/python.tar.gz"
tar -xzf "$CACHE/python.tar.gz" -C "$WORK/pip-python" --strip-components=1 --no-same-owner
"$WORK/pip-python/bin/python3" -I -m pip --isolated --disable-pip-version-check install -q --no-cache-dir \
    --no-compile --no-deps --require-hashes --only-binary :all: --target "$WORK/test-tools" -r "$LOCK"

echo "Testing $(basename "$APPIMAGE"): davibemanager $("$PY" -I -c 'import davibemanager; print(davibemanager.__version__)')," \
     "$("$PY" -I -c 'import platform; print("Python", platform.python_version())') and the packages in the image," \
     "with the tests of $(git rev-parse --short HEAD)$([ -z "$(git status --porcelain --untracked-files=no)" ] || echo " and its uncommitted changes")."
# The test tools' folder is appended to the path, where PYTHONPATH would put it first.
# -B: no bytecode is left in tests/; no:cacheprovider: nor a .pytest_cache.
RUN='import sys; sys.path.append(sys.argv.pop(1)); import pytest; sys.exit(pytest.main(sys.argv[1:]))'
suite=("$PY" -I -B -c "$RUN" "$WORK/test-tools" -p no:cacheprovider "${@:--q}")
# under a memory cap where systemd can set one: a test that ran away once took a machine down
if command -v systemd-run >/dev/null && systemd-run --user --scope -q true 2>/dev/null; then
    suite=(systemd-run --user --scope -q -p MemoryMax=3G -p MemorySwapMax=0 "${suite[@]}")
else
    echo "(no systemd user session here: the suite runs without its 3 GB memory cap)" >&2
fi
"${suite[@]}"
