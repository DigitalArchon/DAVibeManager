#!/bin/bash
# Build DAVibeManager's AppImage reproducibly with rootless Podman (see packaging/README.md).
#   packaging/build-appimage.sh build   AppImage of HEAD -> dist/
#   packaging/build-appimage.sh check   build HEAD twice from scratch and compare the hashes
#   packaging/build-appimage.sh lock    lock what pyproject.toml and the *.in files add (UPGRADE=1:
#                                       re-resolve everything); review, then commit
# DIST=dir puts the results somewhere other than dist/.
# Only committed files are built (HEAD's, as committed); SOURCE_DATE_EPOCH is HEAD's commit time.
# What builds them is HEAD's too: with this script or anything in packaging/appimage changed
# since, nothing is built, and the changed files are named.
# lock reads pyproject.toml and the *.in files as they are in the working tree.
# This machine needs rootless Podman, git, GNU tar and python3 3.11 or newer.
set -euo pipefail

# What this script itself runs, looked for before anything else, so that a machine without one
# is told so in a sentence: git's absence was "command not found" from the first line, and a
# python3 before 3.11 a traceback about tomllib once the builder image had been made.
missing_host_tools() {  # -> a line for each this machine lacks
    command -v git >/dev/null || echo "git"
    command -v podman >/dev/null || echo "Podman, rootless: sudo apt install podman (or dnf/pacman)"
    # --sort=name, which packs the commit's files in one order whatever order the file system
    # gives them in, is GNU tar's
    case "$(tar --version 2>/dev/null || true)" in
        *"GNU tar"*) ;;
        *) echo "GNU tar (bsdtar and BusyBox's tar have no --sort=name)" ;;
    esac
    python3 -c 'import tomllib' 2>/dev/null \
        || echo "python3 3.11 or newer (its tomllib reads the version from pyproject.toml)"
}
missing="$(missing_host_tools)"
if [ -n "$missing" ]; then
    echo "Nothing built. $0 needs these, which this machine lacks:" >&2
    while IFS= read -r line; do echo "  $line" >&2; done <<< "$missing"
    exit 1
fi

mode="${1:-build}"
case "$mode" in
    build|check|lock) ;;
    *) echo "usage: $0 build|check|lock" >&2; exit 2 ;;
esac
self="$(realpath -- "${BASH_SOURCE[0]}")"
top="$(git rev-parse --show-toplevel)"
cd "$top"

# What builds the AppImage is taken as committed, as what is built is. build.sh, the locks and
# the pins the container reads come out of the commit with the sources (export_head, below); but
# this script is the file that was run, and it reads the Containerfile and pins.sh (the base
# image's digest, the apt snapshot) from the working tree to make the builder image. Until Nov
# 2026 a changed one of those went into the build while the note below said uncommitted changes
# are not built. Now the build's definition, this script and everything in packaging/appimage,
# is compared with HEAD's byte for byte (no filter or line-ending setting of the machine's in
# between), and a build is refused while any of it differs: so what the working tree's files
# make is what the commit's would.
changed_definition() {  # this-script -> the files of the build's definition that are not HEAD's
    local self=$1 entry oid path
    if [ "$(git hash-object --no-filters -- "$self")" != "$(git rev-parse -q --verify HEAD:packaging/build-appimage.sh)" ]; then
        printf '%s\n' packaging/build-appimage.sh
    fi
    git ls-tree -r -z HEAD -- packaging/appimage | while IFS= read -r -d '' entry; do
        oid="${entry%%$'\t'*}"
        oid="${oid##* }"
        path="${entry#*$'\t'}"
        if [ ! -f "$path" ] || [ "$(git hash-object --no-filters -- "$path")" != "$oid" ]; then
            printf '%s\n' "$path"
        fi
    done
}
if [ "$mode" != lock ]; then
    changed="$(changed_definition "$self")"
    if [ -n "$changed" ]; then
        echo "Nothing built. The build is defined by the commit it builds, HEAD ($(git rev-parse --short HEAD))," \
             "and these are not as committed there:" >&2
        while IFS= read -r line; do echo "  $line" >&2; done <<< "$changed"
        echo "Commit the changes, or put them aside (git stash), and build again." >&2
        exit 1
    fi
    if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
        echo "Note: uncommitted changes are not built; this builds HEAD ($(git rev-parse --short HEAD))." >&2
    fi
fi
. packaging/appimage/pins.sh
# The host's CA bundle, for apt in the builder to reach the package snapshot over https: the
# first of these this machine has, where Debian and its kin, Fedora and RHEL, openSUSE and the
# rest keep it, in the order AppRun looks. Only the builder image is made with it, and apt
# checks what it fetches by signature whatever the bundle: nothing of it is in the AppImage.
# Looked for only when that image is to be built. (DA Assistant's build-appimage.sh, 2a569de.)
CA_BUNDLES=(/etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt
            /etc/ssl/ca-bundle.pem /etc/pki/tls/cert.pem /etc/ssl/cert.pem)
host_ca_bundle() {
    local ca
    for ca in "$@"; do
        if [ -f "$ca" ]; then
            printf '%s\n' "$ca"
            return 0
        fi
    done
    echo "No CA bundle on this machine: looked for $*. The builder's apt needs one to reach the" \
         "package snapshot over https; install the distribution's ca-certificates package." >&2
    return 1
}

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

TAG="davibemanager-appimage-builder:$(cat packaging/appimage/Containerfile packaging/appimage/pins.sh | sha256sum | cut -c1-12)"
if ! podman image exists "$TAG"; then
    ca="$(host_ca_bundle "${CA_BUNDLES[@]}")"
    # The bundle goes in as a copy in a build context of its own rather than a mount: on an
    # SELinux host (Fedora, RHEL) a mount needs :Z, and rootless Podman may not relabel a file
    # root owns, nor should anything relabel a file the host's own programs read. Readable by
    # all whatever the umask: COPY keeps its mode, and apt fetches as its own user, _apt.
    mkdir "$WORK/context"
    install -m 0644 "$ca" "$WORK/context/hostca.crt"
    podman build -t "$TAG" \
        --build-arg BASE_IMAGE="$BASE_IMAGE" --build-arg APT_SNAPSHOT="$APT_SNAPSHOT" \
        -f packaging/appimage/Containerfile "$WORK/context"
fi

EPOCH="$(git log -1 --format=%ct HEAD)"
# HEAD's files exactly as committed, from git's object store. git archive would pass each through
# this machine's git settings first (core.autocrlf, core.eol, the filters and ident its attributes
# name, tar.umask), and a verifier's own settings would change the AppImage. Only plain files are
# taken; the tree has nothing else. (DA Assistant's build-appimage.sh, d4153ff.)
export_head() {  # -> $WORK/src.tar
    mkdir "$WORK/tree"
    git ls-tree -r -z HEAD | while IFS= read -r -d '' entry; do
        read -r fmode ftype oid <<< "${entry%%$'\t'*}"
        path="${entry#*$'\t'}"
        case "$fmode" in
            100644|100755) ;;
            *) echo "$path is a $ftype of mode $fmode, which the build does not take" >&2; exit 1 ;;
        esac
        mkdir -p "$WORK/tree/$(dirname "$path")"
        git cat-file blob "$oid" > "$WORK/tree/$path"
        chmod "${fmode#100}" "$WORK/tree/$path"
    done
    (cd "$WORK/tree" && shopt -s dotglob && tar -cf "$WORK/src.tar" --sort=name --owner=0 \
        --group=0 --numeric-owner --mode=u+rwX,go+rX,go-w --mtime="@$EPOCH" -- *)
}
VERSION="$(git show HEAD:pyproject.toml | python3 -c 'import sys, tomllib; print(tomllib.load(sys.stdin.buffer)["project"]["version"])')"
CACHE="${XDG_CACHE_HOME:-$HOME/.cache}/davibemanager-appimage"
DIST="$(mkdir -p "${DIST:-dist}" && cd "${DIST:-dist}" && pwd)"
mkdir -p "$CACHE"

run() {  # out-dir mode
    mkdir -p "$1"
    # --pull=never: the builder is the image made above, on this machine, and no registry is
    # ever asked for one of its name
    podman run --rm --pull=never -v "$WORK/src.tar:/src.tar:ro,Z" -v "$CACHE:/cache:Z" -v "$1:/out:Z" \
        -e SOURCE_DATE_EPOCH="$EPOCH" -e VERSION="$VERSION" -e UPGRADE="${UPGRADE:-0}" "$TAG" \
        bash -c 'tar -xOf /src.tar packaging/appimage/build.sh > /tmp/build.sh && bash /tmp/build.sh "$0"' "$2"
}

case "$mode" in
    build)
        export_head
        run "$DIST" build ;;
    check)
        export_head
        run "$WORK/a" build
        rm -rf "$CACHE/pip"          # the second build downloads its wheels again
        run "$WORK/b" build
        a=$(cut -d' ' -f1 "$WORK"/a/*.sha256); b=$(cut -d' ' -f1 "$WORK"/b/*.sha256)
        if [ "$a" = "$b" ]; then
            cp "$WORK"/a/* "$DIST"/
            echo "Reproducible: both builds are $a"
        else
            echo "NOT reproducible: $a vs $b (compare with diffoscope; copies in $DIST/check-a, $DIST/check-b)" >&2
            rm -rf "$DIST/check-a" "$DIST/check-b" && cp -r "$WORK/a" "$DIST/check-a" && cp -r "$WORK/b" "$DIST/check-b"
            exit 1
        fi ;;
    lock)
        # from the working tree, so that a requirement is locked before it is committed: the
        # tracked files as they are now (pyproject.toml, the *.in files and their locks)
        git ls-files -z | tar -cf "$WORK/src.tar" --null -T -
        run "$WORK/lock" lock
        cp "$WORK"/lock/*.lock packaging/appimage/
        git --no-pager diff --stat -- packaging/appimage/*.lock
        # a lock written for the first time is in no diff: named, so that it gets added
        git ls-files --others --exclude-standard -- 'packaging/appimage/*.lock' | sed 's/^/ new, to git add: /' ;;
esac
