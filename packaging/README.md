# Packaging: the AppImage

DA Vibe Manager ships as a single AppImage for x86-64 Linux, built so that anyone can rebuild a
release from its commit and get the same file, byte for byte.

## What's in it, and what comes from the system

| In the AppImage | From the system |
|---|---|
| Python 3.12 ([python-build-standalone](https://github.com/astral-sh/python-build-standalone)) | GTK 3 and **WebKitGTK 4.1** (the app window) |
| Every Python dependency, pinned with hashes | **Podman**, rootless (the assistant's sandbox) |
| The Claude Code CLI, inside the pinned `claude-agent-sdk` (its hash is in `workspace/pins.py`) | The tray: XApp (Mint), Ayatana or AppIndicator (KDE, CachyOS) |
| PyGObject and pycairo, built from pinned sources | The Secret Service keyring (GNOME Keyring, KWallet) |
| A fallback `libgirepository-2.0` for hosts that lack it | `xdg-open`, `lspci` (optional) |
| tor 0.4.9.15 and its libraries, unmodified from the Tor Expert Bundle 16.0 (pinned with its hash in `appimage/pins.sh`), for sync; its licences in `usr/share/licenses/tor` | |

WebKitGTK is deliberately **not** bundled: it renders the AI's output, so it should get the
distribution's security updates, not wait for a DA Vibe Manager release. Without it, DA Vibe
Manager opens in the default web browser instead and says what to install. Podman isn't bundled
either: it is the sandbox's boundary, and comes with the system's security updates. Without it,
the first screen offers to install it (with passt on Arch, which Podman needs to build the
sandbox), using the distribution's package manager through pkexec (`podmansetup.py`).

| Distribution | The app window's engine | The sandbox |
|---|---|---|
| Ubuntu 24.04+, Mint 22+, Debian 13+ | `sudo apt install gir1.2-webkit2-4.1` | `sudo apt install podman` |
| Fedora | `sudo dnf install webkit2gtk4.1` | `sudo dnf install podman` |
| Arch, CachyOS | `sudo pacman -S webkit2gtk-4.1` | `sudo pacman -S podman passt` |

The first start builds the sandbox's image (a few minutes; Ubuntu 24.04 pinned, as in
`src/davibemanager/workspace/`), with the Claude Code CLI taken from the AppImage. On a computer
with 4 GB of memory, set the sandbox to 2 GB and 2 CPUs (Settings → The sandbox).

The bundled PyGObject needs GLib 2.80 or newer, which sets the oldest supported systems:
Ubuntu 24.04 / Mint 22, Debian 13, and current Fedora and Arch. The AppImage uses the static
type 2 runtime, so it doesn't need `libfuse2`.

## Building

The machine that builds needs four things, and `build-appimage.sh` says which is missing before
it starts: rootless [Podman](https://podman.io) (`sudo apt install podman`), git, GNU tar (its
`--sort=name` packs the commit's files in one order) and python3 3.11 or newer (its `tomllib`
reads the version from `pyproject.toml`). Everything else the build uses is in the container.

```bash
packaging/build-appimage.sh build    # dist/DAVibeManager-<version>-x86_64.AppImage (+ .sha256)
packaging/build-appimage.sh check    # build twice from scratch, compare: must be identical
packaging/test-appimage.sh           # smoke-test it on Ubuntu, Debian, Fedora, Arch, CachyOS
packaging/test-locked.sh             # the test suite, on the AppImage's own Python and packages
packaging/build-appimage.sh lock     # lock what pyproject.toml and the *.in files add (review the diff, commit)
UPGRADE=1 packaging/build-appimage.sh lock   # re-resolve every lock to what is newest now
DIST=/some/folder packaging/build-appimage.sh build   # the results somewhere other than dist/
```

Only committed files are built: HEAD's, read from git's own objects as they were committed (not
through `git archive`, which would hand them through this machine's git settings first: line endings,
filters), and every timestamp is HEAD's commit time (`SOURCE_DATE_EPOCH`). What builds them is the
commit's too. `build.sh`, the locks and the pins come out of the commit with the sources;
`build-appimage.sh` itself is the file that was run, and it reads `pins.sh` and the Containerfile from
the working tree to make the builder image, so it first compares itself and everything in
`packaging/appimage/` with HEAD's, byte for byte, and builds nothing while any of them differs: it
names the files, to be committed or put aside. Other uncommitted changes are not built, and a note
says so. The lock run reads `pyproject.toml` and the `*.in` files as they are in the working tree, so
a requirement is locked before it is committed. Builds run in
`packaging/appimage/Containerfile`: Ubuntu 24.04 pinned by digest, with packages from the Ubuntu
archive as it was at a fixed moment ([snapshot.ubuntu.com](https://snapshot.ubuntu.com)); the host's
CA bundle goes into that image's build as a copy, for apt to reach the snapshot over https, and is
removed again. The builder image is made on this machine and run from there (`--pull=never`: no
registry is asked for it). Every download is over https only, redirects included, and is cached in
`~/.cache/davibemanager-appimage` and verified against its pinned hash on every build. Nothing in the
image names the folder it was built in: the bytecode names its source as it is inside the image, and
pip's console scripts, which would name the build's Python, are left out (the build stops if anything
still names it). Each package's `RECORD` is then made to say what is in the image
(`appimage/records.py`): the lines of files the build left out (`direct_url.json`, the console
scripts, Pillow's font module) are dropped, and a file the build changed gets its present hash and
size; every other line stays as pip wrote it.

A relock keeps the versions the locks already pin, and moves only what a new floor or a new package
needs; `UPGRADE=1` moves everything.

## What is pinned, and where

| What | Pinned in |
|---|---|
| Base image (digest), apt snapshot, Python build, AppImage runtime | `appimage/pins.sh` |
| Runtime Python packages (wheels, with hashes) | `appimage/requirements.lock` |
| PyGObject, pycairo (source archives, with hashes) | `appimage/sdists.lock` |
| meson, meson-python, ninja, setuptools (with hashes) | `appimage/build-requirements.lock` |
| pip and pip-tools, which write the locks (with hashes) | `appimage/lock-requirements.lock` |
| pytest and pytest-asyncio, for `test-locked.sh` (with hashes; not in the image) | `appimage/test-requirements.lock` |

Changing any of these changes the AppImage, which is the point: an update is a reviewed commit.
Most runtime packages are installed only as prebuilt wheels; the few without one
(`SDIST_ONLY` in `appimage/build.sh`) are built from their pinned sources with the pinned tools.

## Verifying a release

1. Check out the release's tag (`git clone -c core.autocrlf=false`: the scripts run from the
   checkout, and with Windows line endings they would not start).
2. `packaging/build-appimage.sh build`.
3. Compare `sha256sum dist/DAVibeManager-*.AppImage` with the release's `.sha256`.

If they differ, `diffoscope` on the two files shows where.

## Testing what ships

A developer's venv is not the AppImage: its packages are the newest of the day it was made (and the
distribution's own, when it was made with `--system-site-packages`), on the system's Python.
`packaging/test-locked.sh` runs the test suite on the AppImage instead:

```bash
packaging/test-locked.sh                          # the whole suite, on dist/'s newest AppImage
packaging/test-locked.sh -q tests/test_safety.py  # any pytest arguments
APPIMAGE=/elsewhere/DAVibeManager-<version>-x86_64.AppImage packaging/test-locked.sh
```

It unpacks the AppImage into a temporary folder and has its Python (`-I`, as AppRun runs it) run the
checkout's `tests/` against the `davibemanager` and the packages installed in the image. The image
must be of the checkout: if a file of its `davibemanager` is not the one in `src/davibemanager`, the
script names it and tests nothing. pytest and pytest-asyncio are not in the image; they are installed
from `appimage/test-requirements.lock`, with hashes, into a folder of their own that comes last on the
path, so that nothing they bring stands in for a package that ships. The pip that installs them is the
pinned Python's the build uses (`pins.sh`), taken from the build's cache or downloaded and checked as
the build does. The suite runs under a 3 GB memory cap where there is a systemd user session. The
script needs git, GNU tar, curl and the network (for those few wheels).

## Releasing

1. Update the version in `pyproject.toml` and `src/davibemanager/__init__.py`, commit, tag.
2. `packaging/build-appimage.sh check` (reproducible), then `packaging/test-locked.sh` (the test
   suite passes on what was built) and `packaging/test-appimage.sh` (it starts on each distribution).
3. Attach the AppImage and its `.sha256` to the release.

Rebuild and re-release when a pinned dependency has a security fix: the locks don't move by
themselves. WebKitGTK and GTK update with the system.
