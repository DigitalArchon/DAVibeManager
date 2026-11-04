# Everything the AppImage build downloads, pinned. Change these deliberately: a new value means
# a different AppImage. (Sourced by build-appimage.sh on the host and build.sh in the container.)

# Ubuntu 24.04 base image, by digest; GLib 2.80 here is the oldest GLib the AppImage runs on
BASE_IMAGE="docker.io/library/ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3"
# build tools come from the Ubuntu archive as it was at this moment (snapshot.ubuntu.com)
APT_SNAPSHOT="20261022T000000Z"

# Python, from python-build-standalone (relocatable, built for old glibc)
PBS_URL="https://github.com/astral-sh/python-build-standalone/releases/download/20260929/cpython-3.12.14%2B20260929-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz"
PBS_SHA256="ef605200f8174e87ecfc308e52a88127543f85dd5c940dc5e92cab244b98a003"

# AppImage type 2 runtime, static (no libfuse2 needed on the host)
RUNTIME_URL="https://github.com/AppImage/type2-runtime/releases/download/20251108/runtime-x86_64"
RUNTIME_SHA256="2fca8b443c92510f1483a883f60061ad09b46b978b2631c807cd873a47ec260d"

# Tor, for syncing the user's apps between their computers (sync/tor.py): the official Tor Expert
# Bundle, of which build.sh takes tor and the three libraries it was built against. The same file
# SealedLore pins, checked by hand against its signature there (the Tor Browser Developers key,
# EF6E 286D DA85 EA2A 4BA7 DE68 4E2C 6E87 9329 8290). archive.torproject.org keeps every release.
# Bump it for tor's fixes; the notice build.sh writes names its source and the build system's tag.
TOR_BUNDLE_VERSION="16.0"
TOR_VERSION="0.4.9.15"
TOR_URL="https://archive.torproject.org/tor-package-archive/torbrowser/$TOR_BUNDLE_VERSION/tor-expert-bundle-linux-x86_64-$TOR_BUNDLE_VERSION.tar.gz"
TOR_SHA256="cc950ebe9acb80188325c3a2cd8817def7dd7237d6fdcd861bb87b234a0cb2fd"
