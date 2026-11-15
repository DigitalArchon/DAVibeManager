#!/bin/bash
# Runs inside the build container (see Containerfile); started by packaging/build-appimage.sh.
#   build.sh build   /src.tar (the commit's files, as committed) -> /out/DAVibeManager-<version>-x86_64.AppImage
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
        # https only, redirects included: a hash proves what arrived, not who saw it asked for
        curl --proto '=https' --tlsv1.2 -fsSL --retry 3 -o "$dest.part" "$url"
        echo "$sum  $dest.part" | sha256sum -c --quiet -
        mv "$dest.part" "$dest"
    fi
}
fetch_any() {  # fetch_any <file> <sha256> <url>...: from the first address that has it
    local file="$1" sum="$2" url
    shift 2
    mkdir -p "$(dirname "$file")"
    if [ -f "$file" ] && echo "$sum  $file" | sha256sum -c --quiet - 2>/dev/null; then
        return 0
    fi
    rm -f "$file"
    for url in "$@"; do
        if curl --proto '=https' --tlsv1.2 -fL --retry 3 -o "$file.part" "$url"; then
            mv "$file.part" "$file"
            if echo "$sum  $file" | sha256sum -c --quiet - 2>/dev/null; then
                return 0
            fi
            echo "the file from $url isn't the one pinned; trying the next address" >&2
            rm -f "$file"
        else
            rm -f "$file.part"
            echo "$url couldn't be fetched; trying the next address" >&2
        fi
    done
    echo "no address gave $(basename "$file") with its pinned sum $sum" >&2
    exit 1
}
mkdir -p /cache
fetch "$PBS_URL" "$PBS_SHA256" /cache/python.tar.gz
fetch "$RUNTIME_URL" "$RUNTIME_SHA256" /cache/runtime-x86_64
# deb.torproject.org keeps only the current tor: the same file is an asset of our release (pins.sh)
fetch_any "/cache/$TOR_DEB" "$TOR_SHA256" "$TOR_URL" "$TOR_FALLBACK_URL"
mkdir -p /cache/debs
for entry in "${TOR_LIBRARY_DEBS[@]}"; do              # tor's libraries, Ubuntu 22.04's (pins.sh)
    read -r file sum <<<"$entry"
    fetch "$UBUNTU_FILES/${file//\~/%7E}" "$sum" "/cache/debs/$file"
done

# a Python for building (with the build tools) and a clean copy that becomes the AppImage's
mkdir -p "$W/buildpy"
tar -xzf /cache/python.tar.gz -C "$W/buildpy" --strip-components=1 --no-same-owner
tar -xzf /cache/python.tar.gz -C "$W/AppDir/usr" --no-same-owner        # -> usr/python
"$W/buildpy/bin/python3" -m venv "$W/venv"
V="$W/venv/bin"
export PATH="$V:$PATH"      # meson and ninja for the source builds

if [ "$mode" = lock ]; then
    # The resolver's own TLS trust while it reads PyPI: the container's CA store (the snapshot's
    # ca-certificates, which blacklists emSign ECC Root CA - G3 since 20260816ubuntu0.24.04.1),
    # never pip's vendored certifi, which pip reads beside the system store; pip 26.2.2
    # (lock-requirements.in) is the first with the root gone from its own copy too. The build
    # itself needs none of this: every package it installs is checked against the lock's hashes.
    export PIP_CERT=/etc/ssl/certs/ca-certificates.crt
    # pip-tools and everything it runs on, checked against their hashes as the build's own tools
    # are: what writes the locks is pinned like what the locks pin.
    "$V/pip" install -q --require-hashes --no-deps -r "$P/lock-requirements.lock"
    cd "$P"
    # pip-compile keeps the pins of a lock it is writing over: so a floor or a package added is
    # locked without moving everything else to whatever is newest today. UPGRADE=1 re-resolves the
    # lot, the lock tools' own lock with them.
    for name in requirements build-requirements sdists lock-requirements test-requirements; do
        if [ "${UPGRADE:-0}" != 1 ] && [ -f "$name.lock" ]; then
            cp "$name.lock" "/out/$name.lock"
        fi
    done
    "$V/pip-compile" -q --generate-hashes --allow-unsafe --no-strip-extras --output-file /out/requirements.lock \
        "$W/src/pyproject.toml"
    for name in build-requirements sdists lock-requirements test-requirements; do
        "$V/pip-compile" -q --generate-hashes --allow-unsafe --output-file "/out/$name.lock" "$name.in"
    done
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

class HttpsOnly(urllib.request.HTTPRedirectHandler):
    # what curl --proto '=https' does above: a redirect away from https is refused
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.startswith("https://"):
            sys.exit(f"{req.full_url} redirects to {newurl}, which is not https")
        return super().redirect_request(req, fp, code, msg, headers, newurl)

def urlopen(url):
    if not url.startswith("https://"):
        sys.exit(f"{url} is not https")
    return urllib.request.build_opener(HttpsOnly).open(url)

dest, lockfile, names = sys.argv[1], sys.argv[2], set(sys.argv[3:])
lock = open(lockfile).read()
for name, version, hashes in re.findall(r"^([\w.-]+)==([\w.]+)((?:\s*\\\s*--hash=sha256:\w+)+)", lock, re.M):
    if names and name not in names:
        continue
    meta = json.load(urlopen(f"https://pypi.org/pypi/{name}/{version}/json"))
    sdist = next(u for u in meta["urls"] if u["packagetype"] == "sdist")
    data = urlopen(sdist["url"]).read()
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
# a block per requirement, extras included (name[extra]==...: else it joins the block before)
blocks = re.split(r"(?m)^(?=[\w.-]+(?:\[[^\]]*\])?==)", text)
open(sys.argv[2], "w").write("".join(b for b in blocks if re.split(r"[\[=]", b, maxsplit=1)[0] not in skip))
PY

# the AppImage's Python: locked wheels only (hash-checked), then the ones built here
PY="$W/AppDir/usr/python/bin/python3"
"$PY" -m pip install -q --no-compile --no-deps --require-hashes --only-binary :all: -r "$W/binary.lock"
"$PY" -m pip install -q --no-compile --no-deps "$W/wheels"/*.whl
# The console scripts pip wrote (davibemanager, uvicorn, httpx, keyring, ...) start
# #!/work/AppDir/usr/python/bin/python3, which is nowhere but in this container: on a user's machine
# they would run nothing, and they carry the build path. The app runs none of them (AppRun starts
# python3 -m davibemanager); python-build-standalone's own scripts start #!/bin/sh and stay.
for script in "$W"/AppDir/usr/python/bin/*; do
    if [ -f "$script" ] && [ ! -L "$script" ] && head -n1 "$script" | grep -q "^#!$W/"; then
        rm "$script"
    fi
done
"$PY" -m pip uninstall -q -y pip                  # nothing is installed at run time
# Pillow's font module (PIL/_imagingft) is the only thing that loads the FreeType, HarfBuzz
# and Brotli it bundles (FreeType reads WOFF2 fonts with Brotli), and nothing here draws text
# with Pillow. Brotli 1.2.0 has CVE-2026-111497, an out-of-bounds write in its decoder (Oct
# 2026), and Pillow 13.0.0 is the newest, so the font module and those libraries are left out.
# Pillow still imports, reads and writes every format, and ImageFont.load_default() falls back
# to its built-in bitmap font. Take this out once a Pillow release bundles Brotli 1.2.1.
for site in "$W"/AppDir/usr/python/lib/python3.*/site-packages; do
    rm -f "$site"/PIL/_imagingft.*.so "$site"/pillow.libs/libfreetype-*.so* \
        "$site"/pillow.libs/libharfbuzz-*.so* "$site"/pillow.libs/libbrotli*.so*
done
left="$(find "$W/AppDir" -type f -name '*.so*' -exec readelf -d {} + 2>/dev/null \
    | grep -E 'NEEDED.*\[lib(freetype|harfbuzz|brotlidec|brotlicommon)-[0-9a-f]{8}\.' || true)"
if [ -n "$left" ]; then
    echo "Something still needs the libraries left out with Pillow's font module:" >&2
    echo "$left" >&2
    exit 1
fi
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
# Each package's RECORD still listed what was taken out above (direct_url.json, the console
# scripts, Pillow's font module and its libraries). direct_url.json's line was more than untidy: it
# carries the hash of a file that holds the hash of the wheel archive pip installed from, and for
# the packages built here (PyGObject, pycairo, proxy-tools, DA Vibe Manager) that archive is made in
# this container, so the image depended on the bytes of a zip that is in none of its files.
# records.py drops the lines of files that are gone and gives a changed file the hash and size it
# has, leaving every other line as it was: RECORD says what is in the image. (DA Toolkit's 266a002.)
"$W/buildpy/bin/python3" "$P/records.py" "$W"/AppDir/usr/python/lib/python3.*/site-packages
# Bytecode that stores the source's hash where its date would go, unchecked: Python loads it without
# looking at the source again, which on a read-only mount nobody can change, and it comes out the same
# from every build. -s/-p name each source as it is inside the image (/usr/python/lib/...), not as it is
# here (/work/AppDir/...); Python puts the true path in when it loads a module. -B, or the interpreter
# running compileall writes the modules it imports itself first, dated, and compileall takes those for
# done. (DA Assistant's build, 8cfe093, Nov 2026.)
"$PY" -B -m compileall -q -j1 --invalidation-mode unchecked-hash -s "$W/AppDir" -p / \
    "$W/AppDir/usr/python/lib" >/dev/null

# Tor, for syncing the user's apps between their computers: tor from the Tor Project's own Ubuntu
# 22.04 package and exactly the libraries it loads (sync/tor.py BUNDLED_LIBRARIES: every one but
# glibc's), from the Ubuntu 22.04 packages pins.sh pins, unmodified, in a folder of their own: tor has
# no RUNPATH, so it finds them through LD_LIBRARY_PATH, which the app sets to this folder for tor
# alone (tor_environment). Never in usr/lib: this OpenSSL and libsystemd must not stand in for
# anything else's. Only the program: no service, configuration or geoip files (onion services need
# none).
TORDIR="$W/AppDir/usr/lib/tor"
LICENCES="$W/AppDir/usr/share/licenses/tor"
read -r -a TOR_LIBS <<<"$(PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$W/AppDir/usr/python/lib/python3.12/site-packages" "$PY" -s -c \
    'from davibemanager.sync.tor import BUNDLED_LIBRARIES; print(*BUNDLED_LIBRARIES)')"
rm -rf "$W/tor-x" && mkdir -p "$W/tor-x" "$TORDIR" "$LICENCES/texts"
dpkg-deb -x "/cache/$TOR_DEB" "$W/tor-x"
install -m 755 "$W/tor-x/usr/bin/tor" "$TORDIR/tor"
install -D -m 644 "$W/tor-x/usr/share/doc/tor/copyright" "$LICENCES/tor/copyright"
for entry in "${TOR_LIBRARY_DEBS[@]}"; do
    read -r file sum <<<"$entry"
    rm -rf "$W/tor-x/lib" && mkdir -p "$W/tor-x/lib"
    dpkg-deb -x "/cache/debs/$file" "$W/tor-x/lib"
    pkg="${file%%_*}"
    # each package's Debian copyright file: its licence (the texts it names from common-licenses: texts/)
    install -D -m 644 "$W/tor-x/lib/usr/share/doc/$pkg/copyright" "$LICENCES/$pkg/copyright"
    for lib in "${TOR_LIBS[@]}"; do
        for dir in lib/x86_64-linux-gnu usr/lib/x86_64-linux-gnu; do
            if [ -e "$W/tor-x/lib/$dir/$lib" ]; then
                install -m 644 "$(readlink -f "$W/tor-x/lib/$dir/$lib")" "$TORDIR/$lib"
            fi
        done
    done
done
for lib in "${TOR_LIBS[@]}"; do
    [ -f "$TORDIR/$lib" ] || { echo "no package brought $lib for tor" >&2; exit 1; }
done
# the licence texts the copyright files name from /usr/share/common-licenses, Debian's, as committed
install -m 644 "$P"/licenses/tor/*.txt "$LICENCES/texts/"
TOR_PACKAGE="${TOR_DEB#tor_}" && TOR_PACKAGE="${TOR_PACKAGE%_amd64.deb}"
TOR_ASSET="${TOR_PACKAGE//\~/.}" && TOR_ASSET="${TOR_ASSET//+/.}"   # its name as GitHub keeps it
TOR_RELEASE="${TOR_FALLBACK_URL%/*}" && TOR_RELEASE="${TOR_RELEASE##*/}"  # the release that carries it
cat > "$LICENCES/NOTICE.txt" <<NOTICE
DA Vibe Manager syncs the user's apps between their computers through tor $TOR_VERSION, taken
unmodified from the Tor Project's own package for Ubuntu 22.04 (tor $TOR_PACKAGE, from
https://deb.torproject.org/torproject.org, signed by the Tor Project's archive key A3C4 F0F9 79CA A22C
DBA8 F512 EE8C BC9E 886D DD89), with the libraries it loads, taken unmodified from Ubuntu 22.04's
packages, in usr/lib/tor. Tor is a program of its own, which the app starts only while the computer
is paired with another.

- Tor is under the 3-clause BSD license, with the licences of the code it includes (tor/copyright).
  This build is made with --enable-gpl (the onion services' proof-of-work defence), so the tor
  program as a whole is under the GNU General Public License, version 3 (texts/GPL-3.0.txt), as
  tor --version says.
- Source: tor $TOR_VERSION is https://archive.torproject.org/tor-package-archive/tor-$TOR_VERSION.tar.gz
  (git tag tor-$TOR_VERSION of https://gitlab.torproject.org/tpo/core/tor; sha256
  $TOR_SOURCE_SHA256, the same file as the Debian source's
  tor_$TOR_VERSION.orig.tar.gz). The package is built from it by the Debian source package
  tor_$TOR_PACKAGE, whose packaging is tag debian-tor-$TOR_VERSION-1 of
  https://gitlab.torproject.org/tpo/core/debian/tor. Its two other files are on
  https://deb.torproject.org/torproject.org/pool/main/t/tor/ while $TOR_VERSION is Tor's current
  version, and attached for good to DA Vibe Manager's release $TOR_RELEASE
  (https://github.com/DigitalArchon/DAVibeManager/releases/tag/$TOR_RELEASE) under names GitHub
  keeps as they are: tor_$TOR_PACKAGE.dsc as tor_$TOR_ASSET.dsc (sha256
  $TOR_DSC_SHA256) and tor_$TOR_PACKAGE.diff.gz as
  tor_$TOR_ASSET.diff.gz (sha256 $TOR_DIFF_SHA256),
  beside the package itself, tor_${TOR_ASSET}_amd64.deb.
- The libraries, each with its Debian copyright file (its licence) in <package>/copyright; the
  licence texts those files name from /usr/share/common-licenses are in texts/ (Apache-2.0.txt,
  GPL-2.0.txt, GPL-3.0.txt, LGPL-2.0.txt, LGPL-2.1.txt, CC0-1.0.txt, Artistic-1.0.txt,
  GPL-1.0.txt). Their source is Ubuntu's source package of the same name and version, at
  https://launchpad.net/ubuntu/+source/SOURCE/VERSION (and in deb-src of the Ubuntu 22.04 archive):

  Library                          Ubuntu package (source)     Version                     Licence
  libevent-2.1.so.7                libevent-2.1-7 (libevent)   2.1.12-stable-1ubuntu0.2    3-clause BSD
  libssl.so.3, libcrypto.so.3      libssl3 (openssl)           3.0.2-0ubuntu1.30           Apache 2.0
  libz.so.1                        zlib1g (zlib)               1:1.2.11.dfsg-2ubuntu9.2    zlib
  liblzma.so.5                     liblzma5 (xz-utils)         5.2.5-2ubuntu1.2            public domain
  libzstd.so.1                     libzstd1 (libzstd)          1.4.8+dfsg-3build1          BSD or GPL-2
  libcap.so.2                      libcap2 (libcap2)           1:2.44-1ubuntu0.22.04.3     BSD or GPL-2
  libseccomp.so.2                  libseccomp2 (libseccomp)    2.5.3-2ubuntu3~22.04.1      LGPL 2.1
  libsystemd.so.0                  libsystemd0 (systemd)       249.11-0ubuntu3.23          LGPL 2.1 or later
  liblz4.so.1                      liblz4-1 (lz4)              1.9.3-2build2               2-clause BSD
  libgcrypt.so.20                  libgcrypt20 (libgcrypt20)   1.9.4-3ubuntu3.3            LGPL 2.1 or later
  libgpg-error.so.0                libgpg-error0 (libgpg-error) 1.43-3                     LGPL 2.1 or later

  OpenSSL is Ubuntu's 3.0.2, with the security fixes Ubuntu has backported to it
  (3.0.2-0ubuntu1.30); tor --version names it 3.0.2.

- Replacing them: extract the AppImage and put your own tor and libraries in usr/lib/tor, or run the
  AppImage with DVM_TOR set to the path of another tor.
NOTICE
rm -rf "$W/tor-x"
# the bundled tor, run with the environment the app gives it (from one holding a library path tor
# must not inherit): it says it's the version pinned, the --enable-gpl build with the onion services'
# proof-of-work defence, loads every library but glibc's from its own folder and exactly those, and
# nothing in its folder needs a glibc newer than 2.34 (Ubuntu 22.04's packages: they run wherever the
# AppImage does)
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$W/AppDir/usr/python/lib/python3.12/site-packages" "$PY" -s - "$TORDIR/tor" "$TOR_VERSION" <<'TOR'
import re
import subprocess
import sys
from pathlib import Path

from davibemanager.sync.tor import BUNDLED_LIBRARIES, tor_environment

tor, version = Path(sys.argv[1]), sys.argv[2]
env = tor_environment(tor, {"HOME": "/nonexistent", "PATH": "/usr/bin:/bin", "LD_LIBRARY_PATH": "/elsewhere"})
if env.get("LD_LIBRARY_PATH") != str(tor.parent):
    sys.exit(f"the app wouldn't give tor its own libraries: {env}")
said = subprocess.run([tor, "--version"], env=env, capture_output=True, text=True, check=True).stdout
if not re.match(rf"Tor version {re.escape(version)}[ .]", said):
    sys.exit(f"the bundled tor says {said!r}, not version {version}")
if "GNU General Public License" not in said:
    sys.exit(f"the bundled tor isn't the --enable-gpl build the notice says: {said!r}")
modules = subprocess.run([tor, "--list-modules"], env=env, capture_output=True, text=True, check=True).stdout
if "pow: yes" not in modules.splitlines():
    sys.exit(f"the bundled tor has no onion services' proof-of-work defence: {modules!r}")
# every library it loads is its own, but glibc's (the system's, as every program's)
GLIBC = {"linux-vdso.so.1", "libc.so.6", "libm.so.6", "libdl.so.2", "libpthread.so.0", "librt.so.1"}
links = subprocess.run(["ldd", tor], env=env, capture_output=True, text=True, check=True).stdout
loaded = set()
for line in links.splitlines():
    name, _, found = line.strip().partition(" => ")
    name = name.split(" ")[0]
    if "not found" in found:
        sys.exit(f"tor can't find {name}")
    if name.startswith("/") or name in GLIBC:
        continue
    loaded.add(name)
    if not found.startswith(f"{tor.parent}/"):
        sys.exit(f"tor would load {name} from {found}, not its own folder")
if loaded != set(BUNDLED_LIBRARIES):
    sys.exit(f"tor loads {sorted(loaded)}, BUNDLED_LIBRARIES says {sorted(BUNDLED_LIBRARIES)}")
newest = (0, 0)
for elf in sorted(tor.parent.iterdir()):
    symbols = subprocess.run(["objdump", "-T", elf], capture_output=True, text=True, check=True).stdout
    for major, minor in re.findall(r"GLIBC_(\d+)\.(\d+)", symbols):
        newest = max(newest, (int(major), int(minor)))
if newest > (2, 34):
    sys.exit(f"tor or a library beside it needs glibc {newest[0]}.{newest[1]}, past the floor of 2.34")
print(said.splitlines()[0], f"with pow, its {len(loaded)} libraries its own, glibc {newest[0]}.{newest[1]} at most")
TOR

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

# Nothing in the image may name the folder it was built in: a path there leads nowhere on a user's
# machine. (Wheels built elsewhere may name their own build folders; this is ours.)
if named="$(grep -rlaF "$W/AppDir" "$W/AppDir")"; then
    echo "These name the build folder $W/AppDir:" >&2
    echo "$named" >&2
    exit 1
fi

chmod -R u+rwX,go+rX,go-w "$W/AppDir"
find "$W/AppDir" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
# (mksquashfs takes every timestamp from SOURCE_DATE_EPOCH by itself)
mksquashfs "$W/AppDir" "$W/app.squashfs" -quiet -noappend -root-owned -no-xattrs \
    -comp zstd -Xcompression-level 19 -b 1M

NAME="DAVibeManager-$VERSION-x86_64.AppImage"
cat /cache/runtime-x86_64 "$W/app.squashfs" > "/out/$NAME"
chmod 755 "/out/$NAME"
(cd /out && sha256sum "$NAME" > "$NAME.sha256" && cat "$NAME.sha256")
