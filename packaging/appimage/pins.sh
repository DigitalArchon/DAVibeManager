# Everything the AppImage build downloads, pinned. Change these deliberately: a new value means
# a different AppImage. (Sourced by build-appimage.sh on the host and build.sh in the container.)

# Ubuntu 24.04 base image, by digest; GLib 2.80 here is the oldest GLib the AppImage runs on
BASE_IMAGE="docker.io/library/ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3"
# build tools come from the Ubuntu archive as it was at this moment (snapshot.ubuntu.com)
APT_SNAPSHOT="20260930T000000Z"

# Python, from python-build-standalone (relocatable, built for old glibc)
PBS_URL="https://github.com/astral-sh/python-build-standalone/releases/download/20260929/cpython-3.12.14%2B20260929-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz"
PBS_SHA256="ef605200f8174e87ecfc308e52a88127543f85dd5c940dc5e92cab244b98a003"

# AppImage type 2 runtime, static (no libfuse2 needed on the host)
RUNTIME_URL="https://github.com/AppImage/type2-runtime/releases/download/20251108/runtime-x86_64"
RUNTIME_SHA256="2fca8b443c92510f1483a883f60061ad09b46b978b2631c807cd873a47ec260d"
