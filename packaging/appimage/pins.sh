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

# Tor, for syncing the user's apps between their computers (sync/tor.py): the Tor Project's own
# package of tor for Ubuntu 22.04 (jammy), from deb.torproject.org, and the Ubuntu 22.04 packages of
# exactly the libraries it loads (BUNDLED_LIBRARIES in sync/tor.py), which build.sh puts beside it.
# The same files SealedLore pins, checked against the signed indexes (check-tor-debs.sh redoes it):
# the repository's InRelease signed by Tor's archive key (fingerprint TOR_ARCHIVE_KEY, the
# deb.torproject.org archive signing key, fetched over https from deb.torproject.org), Ubuntu's
# InRelease files by Ubuntu's archive key (Ubuntu Archive Automatic Signing Key (2018), F6EC B376
# 2474 EDA9 D21B 7022 8719 20D1 991B C93C), and each .deb's sum here the one its Packages index
# gives. Ubuntu's packages come from Launchpad's file store, which keeps every version (tor's own
# repository doesn't: TOR_FALLBACK_URL). Built with --enable-gpl (the onion services' proof-of-work
# defence), so that tor is GPL-3: the notice build.sh writes names its source. Bump it for tor's
# fixes.
TOR_VERSION="0.4.9.17"
TOR_DEB="tor_0.4.9.17-1~jammy+1_amd64.deb"
TOR_URL="https://deb.torproject.org/torproject.org/pool/main/t/tor/$TOR_DEB"
TOR_SHA256="249f3beef647186a7127f1828c7dec9aaf93de900baca8e01c0fb99bb47c2a58"
# deb.torproject.org keeps only the current tor: the same file, under a name GitHub keeps as it is
# (no "~" or "+"), is an asset of the DA Vibe Manager release that first carried it, tried when
# deb.torproject.org fails or no longer has it, so any tag can be rebuilt. Its sum is the same pin.
# A tor bump points this at the release it comes with, and that release uploads the file (and the
# Debian source's .dsc and .diff.gz the notice names: packaging/README.md).
TOR_FALLBACK_URL="https://github.com/DigitalArchon/DAVibeManager/releases/download/v0.1.0b16/tor_0.4.9.17-1.jammy.1_amd64.deb"
# The source the notice names (tor is GPL-3 here): Tor's tarball, and the Debian source package's
# .dsc and .diff.gz, by the sums the Sources index under the signed InRelease gives (the tarball
# is the Debian source's orig.tar.gz); the release above carries those two files too.
TOR_SOURCE_SHA256="ff372c41ee7013557fe5b7acd96c909950b27a7959c59fcb87c02591682fabe2"
TOR_DSC_SHA256="68a0a524b1fa657612690e6c551df5dcf8a4e908319612dd055f204d404bb2f2"
TOR_DIFF_SHA256="e0a065df902ec2a22f6120f4aacf81a4f0e9c6728a7d490e788e2fca56038078"
TOR_ARCHIVE_KEY="A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89"
UBUNTU_FILES="https://launchpad.net/ubuntu/+archive/primary/+files"
# The Ubuntu 22.04 packages of tor's libraries: file and sha256 (jammy, and jammy-updates where it
# has a newer one, as of Nov 15 2026).
TOR_LIBRARY_DEBS=(
    "zlib1g_1.2.11.dfsg-2ubuntu9.2_amd64.deb 9dc17e51a1be2d9ed63b7b84ef0e4e29c5abe6f1bc62cb03e7181483cce8a2f2"
    "libevent-2.1-7_2.1.12-stable-1ubuntu0.2_amd64.deb 7e73ca523ba62a774c54efc53974178f4f6e94b5726d201f2ebec1a7d684bc89"
    "libssl3_3.0.2-0ubuntu1.30_amd64.deb d1b4636e32ac6d3b95d583ac05ac548b1aa248414bae1c51b14f54be0f8fd7bc"
    "libsystemd0_249.11-0ubuntu3.23_amd64.deb ff02a85ba73f850cf7958d2867b34947c67a1072e2b2d1c108a8c6e23715624d"
    "liblzma5_5.2.5-2ubuntu1.2_amd64.deb a88fca7506963c443c42a578db6c35424336ae28abcdaa60c89f06d30aeb625b"
    "libzstd1_1.4.8+dfsg-3build1_amd64.deb ae7db00ce8b093e50c994518b90203544e063b4bc574836a048bb142b950b2c9"
    "libseccomp2_2.5.3-2ubuntu3~22.04.1_amd64.deb 25c63fd46d24f518f362c47c429b6918182875b0c58f7e2742aaa2d1e545bbac"
    "libcap2_2.44-1ubuntu0.22.04.3_amd64.deb c497efb7fa3cd19a7ff297d95c7c5d678063c80c9fc230c9d034a8ee02ca8446"
    "libgcrypt20_1.9.4-3ubuntu3.3_amd64.deb 8f16329a0aabf4900271a3687890721bbef307e60983acae5b92eeff12e799b3"
    "liblz4-1_1.9.3-2build2_amd64.deb ac9b54d0feb840345060c74fb687675c5e1eb2b195effafae38c5f9991041e98"
    "libgpg-error0_1.43-3_amd64.deb 1fbacdf9bd1e431cee874a697b339f6f925182bc79bba5a112b53669b33265c5"
)
