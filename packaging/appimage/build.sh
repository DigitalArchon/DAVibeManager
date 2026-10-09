#!/bin/bash
# Runs inside the build container (see Containerfile); started by packaging/build-appimage.sh.
#   build.sh build   /src.tar (git archive of the commit) -> /out/DAVibeManager-<version>-x86_64.AppImage
#   build.sh lock    re-resolve the *.lock files into /out (review, then commit them)
# Inputs are pinned (pins.sh, *.lock with hashes) and every timestamp is SOURCE_DATE_EPOCH, so the
# same commit gives the same AppImage, byte for byte.
set -euo pipefail
umask 022
export LC_ALL=C.UTF-8 TZ=UTC PYTHONHASHSEED=0 PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_ROOT_USER_ACTION=ignore \
    PIP_CACHE_DIR=/cache/pip
: "${SOURCE_DATE_EPOCH:?}"

mode="${1:-build}"
W=/work
rm -rf "$W" && mkdir -p "$W/src" "$W/wheels" "$W/sdists" "$W/AppDir/usr"
tar -xf /src.tar -C "$W/src"
P="$W/src/packaging/appimage"
# shellcheck source=pins.sh
. "$P/pins.sh"

fetch() {  # url sha256 dest: download once into the cache, always verify
    local url=$1 sum=$2 dest=$3
    if [ ! -f "$dest" ] || ! echo "$sum  $dest" | sha256sum -c --quiet - 2>/dev/null; then
        curl -fsSL --retry 3 -o "$dest.part" "$url"
        echo "$sum  $dest.part" | sha256sum -c --quiet -
        mv "$dest.part" "$dest"
    fi
}
mkdir -p /cache
fetch "$PBS_URL" "$PBS_SHA256" /cache/python.tar.gz
fetch "$RUNTIME_URL" "$RUNTIME_SHA256" /cache/runtime-x86_64

# a Python for building (with the build tools) and a clean copy that becomes the AppImage's
mkdir -p "$W/buildpy"
tar -xzf /cache/python.tar.gz -C "$W/buildpy" --strip-components=1 --no-same-owner
tar -xzf /cache/python.tar.gz -C "$W/AppDir/usr" --no-same-owner        # -> usr/python
"$W/buildpy/bin/python3" -m venv "$W/venv"
V="$W/venv/bin"
export PATH="$V:$PATH"      # meson and ninja for the source builds

if [ "$mode" = lock ]; then
    "$V/pip" install -q "pip-tools==7.6.1"
    cd "$P"
    "$V/pip-compile" -q --generate-hashes --allow-unsafe --no-strip-extras --output-file /out/requirements.lock \
        "$W/src/pyproject.toml"
    "$V/pip-compile" -q --generate-hashes --allow-unsafe --output-file /out/build-requirements.lock build-requirements.in
    "$V/pip-compile" -q --generate-hashes --allow-unsafe --output-file /out/sdists.lock sdists.in
    sed -i "s#$W/src/#./#g; s#/out/#packaging/appimage/#g" /out/*.lock
    exit 0
fi

: "${VERSION:?}"
"$V/pip" install -q --require-hashes --no-deps -r "$P/build-requirements.lock"

# PyGObject and pycairo have no Linux wheels: build them from their pinned sources against the
# GLib 2.80 / girepository-2.0 headers. They load the host's GLib, GTK and WebKitGTK at run time.
# Locked runtime packages that publish no wheel at all, built the same way (pure Python).
SDIST_ONLY="proxy-tools"
fetch_sdists() {  # lock [names...]: fetch pinned source archives from PyPI, checked against the lock
    "$W/buildpy/bin/python3" - "$W/sdists" "$@" <<'PY'
import hashlib, json, re, sys, urllib.request
dest, lockfile, names = sys.argv[1], sys.argv[2], set(sys.argv[3:])
lock = open(lockfile).read()
for name, version, hashes in re.findall(r"^([\w.-]+)==([\w.]+)((?:\s*\\\s*--hash=sha256:\w+)+)", lock, re.M):
    if names and name not in names:
        continue
    meta = json.load(urllib.request.urlopen(f"https://pypi.org/pypi/{name}/{version}/json"))
    sdist = next(u for u in meta["urls"] if u["packagetype"] == "sdist")
    data = urllib.request.urlopen(sdist["url"]).read()
    if hashlib.sha256(data).hexdigest() not in re.findall(r"sha256:(\w+)", hashes):
        sys.exit(f"{sdist['filename']}: its hash isn't in {lockfile}")
    # saved under a normalised name, which the build steps below look for
    open(f"{dest}/{name.lower().replace('-', '_')}-{version}.tar.gz", "wb").write(data)
PY
}
fetch_sdists "$P/sdists.lock"
# shellcheck disable=SC2086
fetch_sdists "$P/requirements.lock" $SDIST_ONLY
# Source paths end up in compiled code (__FILE__ in assertion messages), so each source is unpacked
# into a fixed directory (pip would use a random one) and the build path is mapped out entirely.
export CFLAGS="-ffile-prefix-map=$W/=" CXXFLAGS="-ffile-prefix-map=$W/="
unpack() {  # name -> fixed source directory
    mkdir -p "$W/srcs/$1"
    tar -xzf "$W/sdists/$1"-*.tar.gz -C "$W/srcs/$1" --strip-components=1 --no-same-owner
    echo "$W/srcs/$1"
}
build_sdist() {  # name: fixed source and build directories, stripped
    "$V/pip" wheel -q --no-build-isolation --no-deps -w "$W/wheels" \
        -Cbuild-dir="$W/build-$1" -Cinstall-args=--strip "$(unpack "$1")"
}
build_sdist pycairo
"$V/pip" install -q --no-deps "$W/wheels"/pycairo-*.whl     # PyGObject builds its cairo support against it
build_sdist pygobject
for name in $SDIST_ONLY; do
    "$V/pip" wheel -q --no-build-isolation --no-deps -w "$W/wheels" "$(unpack "${name//-/_}")"
done
"$V/pip" wheel -q --no-build-isolation --no-deps -w "$W/wheels" "$W/src"     # DAVibeManager itself
# the rest of the runtime lock: wheels only
"$W/buildpy/bin/python3" - "$P/requirements.lock" "$W/binary.lock" $SDIST_ONLY <<'PY'
import re, sys
text, skip = open(sys.argv[1]).read(), set(sys.argv[3:])
blocks = re.split(r"(?m)^(?=[\w.-]+==)", text)
open(sys.argv[2], "w").write("".join(b for b in blocks if b.split("==", 1)[0] not in skip))
PY

# the AppImage's Python: locked wheels only (hash-checked), then the ones built here
PY="$W/AppDir/usr/python/bin/python3"
"$PY" -m pip install -q --no-compile --no-deps --require-hashes --only-binary :all: -r "$W/binary.lock"
"$PY" -m pip install -q --no-compile --no-deps "$W/wheels"/*.whl
"$PY" -m pip uninstall -q -y pip                  # nothing is installed at run time
# girepository-2.0 for hosts that don't have it (Debian/Ubuntu split it out of GLib); loaded only
# when missing (app._bundled_girepository), so Fedora and Arch use their own
install -D -m 644 "$(readlink -f /usr/lib/x86_64-linux-gnu/libgirepository-2.0.so.0)" \
    "$W/AppDir/usr/lib/girepository-fallback/libgirepository-2.0.so.0"
# the base typelibs GTK's refer to (xlib, cairo, freetype, ...): Arch ships them separately
# (gobject-introspection-runtime), and WebKitGTK doesn't pull them in. One directory each, so only
# the ones a host lacks are added to its search path.
for t in $(dpkg -L gir1.2-freedesktop | grep '\.typelib$'); do
    install -D -m 644 "$t" "$W/AppDir/usr/lib/girepository-fallback/typelibs/$(basename "$t" .typelib)/$(basename "$t")"
done
find "$W/AppDir" -name direct_url.json -delete    # build paths
find "$W/AppDir" -name __pycache__ -type d -prune -exec rm -rf {} +
# bytecode keyed to the source's hash, not its timestamp: reproducible, and valid on a read-only mount
"$PY" -m compileall -q -j1 --invalidation-mode unchecked-hash "$W/AppDir/usr/python/lib" >/dev/null

# AppDir layout (AppImage spec): entry point, desktop entry, icon, AppStream metadata
install -m 755 "$P/AppRun" "$W/AppDir/AppRun"
install -m 644 "$P/davibemanager.desktop" "$P/davibemanager.png" "$W/AppDir/"
ln -s davibemanager.png "$W/AppDir/.DirIcon"
install -D -m 644 "$P/au.com.digitalarchon.davibemanager.appdata.xml" \
    "$W/AppDir/usr/share/metainfo/au.com.digitalarchon.davibemanager.appdata.xml"
# the version where AppImage managers look: the desktop entry (X-AppImage-Version) and AppStream
sed -i "s/@VERSION@/$VERSION/; s/@DATE@/$(date -u -d "@$SOURCE_DATE_EPOCH" +%F)/" \
    "$W/AppDir/davibemanager.desktop" "$W/AppDir/usr/share/metainfo/au.com.digitalarchon.davibemanager.appdata.xml"
grep -qx "X-AppImage-Version=$VERSION" "$W/AppDir/davibemanager.desktop"
grep -q "<release version=\"$VERSION\"" "$W/AppDir/usr/share/metainfo/au.com.digitalarchon.davibemanager.appdata.xml"
# also where the AppStream launchable (desktop-id davibemanager.desktop) is looked up
install -d "$W/AppDir/usr/share/applications"
ln -s ../../../davibemanager.desktop "$W/AppDir/usr/share/applications/davibemanager.desktop"
desktop-file-validate "$W/AppDir/davibemanager.desktop"

chmod -R u+rwX,go+rX,go-w "$W/AppDir"
find "$W/AppDir" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
# (mksquashfs takes every timestamp from SOURCE_DATE_EPOCH by itself)
mksquashfs "$W/AppDir" "$W/app.squashfs" -quiet -noappend -root-owned -no-xattrs \
    -comp zstd -Xcompression-level 19 -b 1M

NAME="DAVibeManager-$VERSION-x86_64.AppImage"
cat /cache/runtime-x86_64 "$W/app.squashfs" > "/out/$NAME"
chmod 755 "/out/$NAME"
(cd /out && sha256sum "$NAME" > "$NAME.sha256" && cat "$NAME.sha256")
