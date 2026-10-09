"""Scripts the app itself runs in the sandbox or its clean containers (as the agent's user, or
another where it says so),
with no AI involved: keeping an app's official source, making its source with the user's changes
on a release (carrying them over to a new one), checking what a delivered branch holds, building
it with its own build script, reading a release's change log, and taking an AppImage's menu entry
and icon out of it.

Each takes its inputs as arguments ("$1", sys.argv), never pasted into the script."""

# Lines starting @@ are for the app: @@STEP <name> (progress), @@FAILED <step> (what went wrong).

# the official source of an app, as the app keeps it: a bare clone made and fetched by the mirrors'
# own user (podman.exec_mirror: not root, not the agent), from the official repository only,
# readable but not writable by the assistant (outside /work, which is the assistant's: it could move
# a folder there aside and put its own in its place). Git refuses another user's repository unless
# told it is safe, in /etc/gitconfig (SAFE_DIRECTORY, by root).
# Not kept if the container is made again: then it is cloned again.
MIRROR = r"""
set -eu
upstream="$1"; mirror="$2"
echo "@@STEP fetch"
case "$mirror" in /var/lib/dvm/mirrors/*.git) ;; *) echo "@@FAILED fetch: $mirror isn't a mirror"; exit 2;; esac
umask 022
if [ ! -d "$mirror" ]; then
  rm -rf "$mirror.part"
  git clone -q --bare "$upstream" "$mirror.part" || { echo "@@FAILED fetch"; exit 2; }
  mv "$mirror.part" "$mirror"
fi
git -C "$mirror" fetch -q --force --prune --tags "$upstream" '+refs/heads/*:refs/heads/*' || { echo "@@FAILED fetch"; exit 2; }
chmod -R a+rX,go-w "$mirror"
"""

# as root, before a mirror is used: the agent's git may read it (it is another user's)
SAFE_DIRECTORY = r"""
set -eu
case "$1" in /var/lib/dvm/mirrors/*.git) ;; *) exit 2;; esac
git config --system --get-all safe.directory 2>/dev/null | grep -qxF "$1" || git config --system --add safe.directory "$1"
"""

# an app's source with its changes, made by the app (never the assistant's own copy of anything):
# a fresh clone of the mirror at $3, whose origin is the official repository, on a branch dvm/work
# at release $5 with each change (pairs of change id and patch file, in order) carried over to it.
# An earlier tree there is moved to .old/ (the newest three are kept). On the release they were
# made on ($4 = $5, or none), the changes are applied as they are. On another, each change is first
# made again on its own release, where it applies as it is, and then cherry-picked: a merge with the
# whole of both trees, which follows renamed files and folders (a file the change adds to a folder
# the project has since renamed goes into the new one; git am -3 would leave it in the old, where
# the build doesn't look), and only if that fails a 3-way apply of its patch. One that is in the release already is dropped. Prints @@CHANGE <id> ok|merged|failed
# for each (a failed one with what failed after it, and left out: the rest go on without it), then
# @@HEAD; exits 3 if any failed.
CARRY = r"""
set -eu
mirror="$1"; upstream="$2"; tree="$3"; old="$4"; new="$5"; shift 5
export GIT_TERMINAL_PROMPT=0
g() { git -c user.name=dvm -c user.email=dvm@sandbox -c commit.gpgsign=false -c advice.detachedHead=false "$@"; }
echo "@@STEP apply"
if [ -e "$tree" ]; then
  keep="$(dirname "$tree")/.old"; name="$(basename "$tree")"
  mkdir -p "$keep"
  mv "$tree" "$keep/$name-$(date +%Y%m%d-%H%M%S)-$$"
  ls -1dt "$keep/$name"-* 2>/dev/null | tail -n +4 | while IFS= read -r d; do rm -rf "$d"; done
fi
mkdir -p "$(dirname "$tree")"
git clone -q --no-checkout "$mirror" "$tree" || { echo "@@FAILED fetch: the official source isn't here"; exit 2; }
cd "$tree"
git remote set-url origin "$upstream"
git rev-parse --verify -q "$new^{commit}" >/dev/null || { echo "@@FAILED fetch: the official source has no $new"; exit 2; }
work="$(mktemp -d)"
failed=0
report() {  # id, what happened, the log
  echo "@@CHANGE $1 $2"
  if [ "$2" = failed ]; then tail -40 "$3"; fi
}
if [ -z "$old" ] || [ "$old" = "$new" ]; then
  g checkout -q -b dvm/work "$new^{commit}"
  id=""; i=0
  for a in "$@"; do
    if [ $((i % 2)) -eq 0 ]; then id="$a"; else
      if g am -q -3 --keep-cr --committer-date-is-author-date "$a" >"$work/log" 2>&1; then report "$id" ok
      else
        { echo "--- the change that didn't apply:"; git am --show-current-patch=diff 2>/dev/null | head -80; } >>"$work/log" || true
        g am --abort >/dev/null 2>&1 || true
        report "$id" failed "$work/log"; failed=1
      fi
    fi
    i=$((i + 1))
  done
else
  git rev-parse --verify -q "$old^{commit}" >/dev/null || { echo "@@FAILED fetch: the official source has no $old"; exit 2; }
  g checkout -q -b dvm/old "$old^{commit}"
  prev="$(git rev-parse HEAD)"; id=""; i=0
  : >"$work/ranges"
  for a in "$@"; do
    if [ $((i % 2)) -eq 0 ]; then id="$a"; else
      g am -q --keep-cr --committer-date-is-author-date "$a" >"$work/log" 2>&1 || {
        g am --abort >/dev/null 2>&1 || true
        echo "@@FAILED apply: the change $id doesn't apply to $old, the release it was made on"; tail -20 "$work/log"; exit 3; }
      tip="$(git rev-parse HEAD)"
      echo "$id $prev $tip $a" >>"$work/ranges"
      prev="$tip"
    fi
    i=$((i + 1))
  done
  g checkout -q -b dvm/work "$new^{commit}"
  exec 3<"$work/ranges"
  while read -r id from to patch <&3; do
    before="$(git rev-parse HEAD)"
    if g -c merge.directoryRenames=true cherry-pick -Xdiff-algorithm=histogram "$from..$to" >"$work/log" 2>&1; then
      report "$id" ok; continue
    fi
    # a commit with nothing left to do (its change is in the release now): skipped
    while [ -f "$(git rev-parse --git-path CHERRY_PICK_HEAD)" ] && [ -z "$(git diff --name-only --diff-filter=U)" ] \
          && [ -z "$(git status --porcelain --untracked-files=no)" ]; do
      g cherry-pick --skip >>"$work/log" 2>&1 || break
    done
    if [ ! -f "$(git rev-parse --git-path CHERRY_PICK_HEAD)" ] && [ ! -d "$(git rev-parse --git-path sequencer)" ]; then
      if [ "$(git rev-parse HEAD)" = "$before" ]; then report "$id" merged; else report "$id" ok; fi
      continue
    fi
    { echo "--- where it conflicts:"; git diff --name-only --diff-filter=U; git diff | head -80; } >>"$work/log" 2>&1 || true
    g cherry-pick --abort >/dev/null 2>&1 || true
    git reset -q --hard "$before"
    if g am -q -3 --keep-cr --committer-date-is-author-date "$patch" >>"$work/log" 2>&1; then report "$id" ok
    else
      g am --abort >/dev/null 2>&1 || true
      git reset -q --hard "$before"
      report "$id" failed "$work/log"; failed=1
    fi
  done
  exec 3<&-
  g branch -q -D dvm/old
fi
rm -rf "$work"
git update-ref refs/dvm/prepared HEAD
echo "@@HEAD $(git rev-parse HEAD)"
[ "$failed" = 0 ] || exit 3
"""

# what a delivered branch holds, for the app's checks: each commit from the base to the head (its
# parents, subject, and the changes its DVM-Change trailers name), the remotes and origin; JSON
INSPECT = r"""
import json, subprocess, sys
repo, base, head = sys.argv[1:4]
def git(*a, check=True):
    return subprocess.run(["git", "-C", repo, *a], capture_output=True, text=True, check=check).stdout
out = git("log", "--reverse", "--format=%H%x1f%P%x1f%s%x1f%(trailers:key=DVM-Change,valueonly,separator=%x1e)%x1d",
          f"{base}..{head}" if base else head)
commits = []
for rec in out.split("\x1d"):
    rec = rec.strip("\n")
    if rec:
        sha, parents, subject, trailers = rec.split("\x1f")
        commits.append({"sha": sha, "merge": len(parents.split()) > 1, "subject": subject,
                        "changes": [t.strip() for t in trailers.split("\x1e") if t.strip()]})
print(json.dumps({"commits": commits, "remotes": git("remote").split(),
                  "origin": git("remote", "get-url", "origin", check=False).strip(),
                  "shallow": git("rev-parse", "--is-shallow-repository", check=False).strip() == "true"}))
"""

# What the app checks and builds of a delivery, taken out of the agent's reach first, in a clean
# container (podman.start_check, where nothing of the agent's runs): the commit at $1's HEAD, with
# all it stands on, and the tag $3 if $1 has it, fetched into a new bare repository of the app's own
# at $2. Git's own transfer: each object arrives with its id checked, and nothing of the agent's
# repository comes along but objects and those refs (no settings, hooks, attributes, replace refs or
# grafts). Everything after (the patch the user reads, the checks, the build) is of this copy, so it
# is one and the same commit, whatever is done to /work meanwhile. Prints @@HEAD <commit>.
SNAPSHOT = r"""
set -eu
src="$1"; snap="$2"; tag="$3"
echo "@@STEP snapshot"
rm -rf "$snap"
git init -q --bare "$snap"
set -- '+HEAD:refs/dvm/check'
if [ -n "$tag" ] && git -C "$src" rev-parse -q --verify "refs/tags/$tag" >/dev/null; then set -- "$@" "+refs/tags/$tag:refs/tags/$tag"; fi
git -C "$snap" fetch -q --no-tags --no-write-fetch-head "$src" "$@" \
  || { echo "@@FAILED snapshot: the app couldn't take a copy of $src's commit"; exit 2; }
echo "@@HEAD $(git -C "$snap" rev-parse --verify refs/dvm/check)"
"""

# a file of the sandbox's ($1, read-only at /sandbox) copied into the clean container ($2), at most 64 KB
COPY_IN = r"""mkdir -p "$(dirname "$2")" && head -c 65536 -- "$1" > "$2"
"""

# a commit of the app's own copy (SNAPSHOT, at $1) built with the build script ($4, a copy the app
# put in this container), in a clean container: nothing there but the image and the packages the
# build says it needs, so the build can't lean on anything else installed or made in the sandbox.
# The build happens at the same paths as it would in the sandbox; the AppImage is left at $out, in
# this container, for the app to take out of it.
CHECK_BUILD = r"""
set -eu
repo="$1"; commit="$2"; work="$3"; script="$4"; out="$5"; label="$6"
echo "@@STEP $label"
rm -rf "$work/src" "$out"; mkdir -p "$work" "$out"
git clone -q --no-checkout "$repo" "$work/src"
git -C "$work/src" fetch -q origin refs/dvm/check
git -C "$work/src" checkout -q --detach "$commit"
cd "$work/src"
export SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)" DVM_OUT="$out" DLA_OUT="$out" TZ=UTC LC_ALL=C.UTF-8
# the build script runs as the agent's own would, with its tools and git settings (podman.AGENT_ENV is the app's)
unset GIT_CONFIG_GLOBAL GIT_NO_REPLACE_OBJECTS GIT_GRAFT_FILE GIT_CONFIG_COUNT GIT_CONFIG_KEY_0 GIT_CONFIG_VALUE_0 \
  GIT_CONFIG_KEY_1 GIT_CONFIG_VALUE_1 GIT_CONFIG_KEY_2 GIT_CONFIG_VALUE_2
export PATH="$HOME/.local/bin:$PATH"
if ! bash "$script" >"$work/$label.log" 2>&1; then
  echo "@@FAILED $label"
  tail -80 "$work/$label.log"
  exit 4
fi
n=$(find "$out" -maxdepth 1 -name '*.AppImage' -type f | wc -l)
if [ "$n" != 1 ]; then echo "@@FAILED $label: the build script left $n AppImages in \$DVM_OUT, not 1"; exit 4; fi
f=$(find "$out" -maxdepth 1 -name '*.AppImage' -type f)
echo "@@OUT $f $(sha256sum "$f" | cut -d' ' -f1)"
"""

# the menu entry and icon inside an AppImage (extracted here, where running it can't matter)
EXTRACT = r"""
set -eu
f="$1"; out="$2"
rm -rf "$out"; mkdir -p "$out/x"; cd "$out/x"
cp "$f" "$out/a.AppImage"; chmod 755 "$out/a.AppImage"
"$out/a.AppImage" --appimage-extract >/dev/null 2>&1 || { echo "@@FAILED extract"; exit 5; }
root="$out/x/squashfs-root"
d=$(find "$root" -maxdepth 1 -name '*.desktop' | sort | head -1)
[ -n "$d" ] && head -c 65536 "$d" > "$out/app.desktop"
icon=$(readlink -f "$root/.DirIcon" 2>/dev/null || true)
case "$icon" in "$root"/*) ;; *) icon="";; esac
if [ -n "$icon" ] && [ -f "$icon" ] && [ "$(stat -c %s "$icon")" -lt 1048576 ]; then
  if head -c 8 "$icon" | grep -q PNG; then cp "$icon" "$out/icon.png";
  elif head -c 400 "$icon" | grep -q '<svg'; then cp "$icon" "$out/icon.svg"; fi
fi
rm -rf "$out/x" "$out/a.AppImage"
ls "$out"
"""

# what changed upstream between two releases: the news/changelog files' new lines, the commit
# subjects, and the forge's release notes (GitHub, GitLab); JSON on stdout
CHANGELOG = r"""
import json, os, re, subprocess, sys, urllib.parse, urllib.request
upstream, repo, old, new = sys.argv[1:5]
os.environ["GIT_TERMINAL_PROMPT"] = "0"
def git(*a):
    return subprocess.run(["git", "-C", repo, *a], capture_output=True, text=True).stdout
if not os.path.isdir(os.path.join(repo, ".git")):
    os.makedirs(os.path.dirname(repo), exist_ok=True)
    subprocess.run(["git", "clone", "-q", "--filter=blob:none", "--no-checkout", upstream, repo], check=True)
subprocess.run(["git", "-C", repo, "fetch", "-q", "--tags", "--force", upstream], check=True)
news = {}
for name in git("ls-tree", "--name-only", new).split("\n"):
    if re.fullmatch(r"(?i)(news|changelog|changes|release[-_ ]?notes|history)(\.(md|txt|rst|markdown))?", name.strip()):
        diff = git("diff", "--no-color", "-U0", old, new, "--", name.strip())
        added = [l[1:] for l in diff.splitlines() if l.startswith("+") and not l.startswith("+++")]
        if added:
            news[name.strip()] = "\n".join(added)[:30000]
commits = [s for s in git("log", "--no-merges", "--format=%s", f"{old}..{new}").splitlines() if s][:400]
count = git("rev-list", "--count", f"{old}..{new}").strip()
notes, url = "", ""
p = urllib.parse.urlsplit(upstream)
path = p.path.strip("/").removesuffix(".git")
try:
    if p.hostname == "github.com":
        api = f"https://api.github.com/repos/{path}/releases/tags/{urllib.parse.quote(new)}"
        body = json.load(urllib.request.urlopen(urllib.request.Request(api, headers={"Accept": "application/vnd.github+json"}), timeout=30))
        notes, url = body.get("body") or "", body.get("html_url") or ""
    elif p.hostname and "gitlab" in p.hostname:
        api = f"https://{p.hostname}/api/v4/projects/{urllib.parse.quote(path, safe='')}/releases/{urllib.parse.quote(new, safe='')}"
        body = json.load(urllib.request.urlopen(api, timeout=30))
        notes = body.get("description") or ""
        url = (body.get("_links") or {}).get("self") or ""
except Exception as e:
    notes = ""
print(json.dumps({"news": news, "commits": commits, "commit_count": int(count or 0), "notes": notes[:30000], "url": url}))
"""

# what the sandbox is doing, for the chat while the assistant or the app works in it: its processor
# time and memory (its own cgroup), its busiest programs, and the last lines written by what's
# running. $1: the log of the app's own build, or -; then Claude Code's task ids, whose output it
# keeps in /tmp/claude-<uid>/<project>/<session>/tasks/<id>.output while they run
ACTIVITY = r"""
log="$1"; shift
echo "@@CPU $(sed -n 's/^usage_usec //p' /sys/fs/cgroup/cpu.stat 2>/dev/null)"
echo "@@MEM $(cat /sys/fs/cgroup/memory.current 2>/dev/null)"
echo "@@PS"
ps -eo pcpu=,comm= --sort=-pcpu 2>/dev/null | head -n 40
tail_of() {  # the last lines, a progress bar's carriage returns taken as line ends
  echo "@@TAIL $1 $(stat -c %Y "$2" 2>/dev/null)"
  tail -c 4000 "$2" 2>/dev/null | tr '\r' '\n' | grep -v '^[[:space:]]*$' | tail -n 3
}
if [ "$log" != - ] && [ -f "$log" ]; then tail_of @check "$log"; fi
for t in "$@"; do
  for f in /tmp/claude-*/*/*/tasks/"$t".output; do
    if [ -f "$f" ]; then tail_of "$t" "$f"; fi
  done
done
exit 0
"""

# run on this computer, not in the sandbox, by the system's sh: waits while the app's process
# ($1, started at $2 in /proc's ticks, so a new process with its number doesn't count) is alive,
# then stops the containers ($3 is podman; the rest, the sandbox and its clean build's, which may
# not be there). The app stops them itself when it quits, and ends this first.
GUARD = r"""
alive() { [ -r "/proc/$1/stat" ] && [ "$(sed 's/.*) //' "/proc/$1/stat" | cut -d' ' -f20)" = "$2" ]; }
while alive "$1" "$2"; do sleep 3; done
podman="$3"; shift 3
exec "$podman" stop --ignore -t 3 "$@" >/dev/null 2>&1
"""
