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

You need rootless [Podman](https://podman.io) (`sudo apt install podman`).

```bash
packaging/build-appimage.sh build    # dist/DAVibeManager-<version>-x86_64.AppImage (+ .sha256)
packaging/build-appimage.sh check    # build twice from scratch, compare: must be identical
packaging/test-appimage.sh           # smoke-test it on Ubuntu, Debian, Fedora, Arch, CachyOS
packaging/build-appimage.sh lock     # lock what pyproject.toml and the *.in files add (review the diff, commit)
UPGRADE=1 packaging/build-appimage.sh lock   # re-resolve every lock to what is newest now
DIST=/some/folder packaging/build-appimage.sh build   # the results somewhere other than dist/
```

Only committed files are built: HEAD's, read from git's own objects as they were committed (not
through `git archive`, which would hand them through this machine's git settings first: line endings,
filters), and every timestamp is HEAD's commit time (`SOURCE_DATE_EPOCH`). Builds run in
`packaging/appimage/Containerfile`: Ubuntu 24.04 pinned by digest, with packages from the Ubuntu
archive as it was at a fixed moment ([snapshot.ubuntu.com](https://snapshot.ubuntu.com)); the host's
CA bundle goes into that image's build as a copy, for apt to reach the snapshot over https, and is
removed again. Every download is over https only, redirects included, and is cached in
`~/.cache/davibemanager-appimage` and verified against its pinned hash on every build. Nothing in the
image names the folder it was built in: the bytecode names its source as it is inside the image, and
pip's console scripts, which would name the build's Python, are left out (the build stops if anything
still names it).

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

Changing any of these changes the AppImage, which is the point: an update is a reviewed commit.
Most runtime packages are installed only as prebuilt wheels; the few without one
(`SDIST_ONLY` in `appimage/build.sh`) are built from their pinned sources with the pinned tools.

## Verifying a release

1. Check out the release's tag (`git clone -c core.autocrlf=false`: the scripts run from the
   checkout, and with Windows line endings they would not start).
2. `packaging/build-appimage.sh build`.
3. Compare `sha256sum dist/DAVibeManager-*.AppImage` with the release's `.sha256`.

If they differ, `diffoscope` on the two files shows where.

## Releasing

1. Update the version in `pyproject.toml` and `src/davibemanager/__init__.py`, commit, tag.
2. `packaging/build-appimage.sh check` (reproducible), then `packaging/test-appimage.sh`.
3. Attach the AppImage and its `.sha256` to the release.

Rebuild and re-release when a pinned dependency has a security fix: the locks don't move by
themselves. WebKitGTK and GTK update with the system.
