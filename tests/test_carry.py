"""The app's own git work, with real git (not in the sandbox: the same scripts, on this computer):
carrying an app's changes over to a new release change by change, and what a branch holds."""

import json
import os
import shutil
import subprocess

import pytest

from davibemanager import apps
from davibemanager.workspace import scripts

pytestmark = pytest.mark.skipif(not shutil.which("git"), reason="needs git")


@pytest.fixture
def gitenv(tmp_path, monkeypatch):
    """Git without this computer's own settings."""
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(tmp_path / "gitconfig"))
    for k in ("GIT_AUTHOR_NAME", "GIT_AUTHOR_EMAIL", "GIT_COMMITTER_NAME", "GIT_COMMITTER_EMAIL"):
        monkeypatch.setenv(k, "dev" if k.endswith("NAME") else "dev@example.org")
    (tmp_path / "home").mkdir()
    return tmp_path


def git(cwd, *a):
    return subprocess.run(["git", "-C", str(cwd), *a], capture_output=True, text=True, check=True).stdout


def write(repo, name, text):
    p = repo / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


LINES = "".join(f"line {i}\n" for i in range(1, 30))


def upstream(tmp):
    """A project with releases: v1; v2 moves viewer.c to src/ and changes another part of it; v3
    changes the very line the user's zoom change changed."""
    up = tmp / "up"
    up.mkdir()
    git(up, "init", "-q", "-b", "main")
    write(up, "viewer.c", LINES)
    git(up, "add", "-A"); git(up, "commit", "-qm", "First"); git(up, "tag", "v1")
    git(up, "mv", "viewer.c", "src_viewer.c")
    write(up, "src_viewer.c", LINES.replace("line 25\n", "line 25 (faster)\n"))
    git(up, "commit", "-qam", "Move the viewer, speed it up"); git(up, "tag", "v2")
    write(up, "src_viewer.c", (up / "src_viewer.c").read_text().replace("line 3\n", "line 3 (upstream's own zoom)\n"))
    git(up, "commit", "-qam", "Zoom differently"); git(up, "tag", "v3")
    return up


def changes(tmp, up):
    """The user's two changes on v1, each a patch of its own with its DVM-Change trailer."""
    work = tmp / "made"
    git(tmp, "clone", "-q", str(up), str(work))
    git(work, "checkout", "-q", "-b", "dvm/work", "v1")
    write(work, "viewer.c", LINES.replace("line 3\n", "line 3 (drag to zoom)\n"))
    git(work, "commit", "-qam", "Drag a box to zoom", "--trailer", "DVM-Change: drag-zoom")
    write(work, "copy.c", "copy the path\n")
    git(work, "add", "-A"); git(work, "commit", "-qm", "Copy the file path", "--trailer", "DVM-Change: copy-path")
    (tmp / "drag-zoom.patch").write_text(git(work, "format-patch", "--stdout", "v1..HEAD~1"))
    (tmp / "copy-path.patch").write_text(git(work, "format-patch", "--stdout", "HEAD~1..HEAD"))
    return ["drag-zoom", str(tmp / "drag-zoom.patch"), "copy-path", str(tmp / "copy-path.patch")]


def carry(tmp, old, new, pairs, tree="tree"):
    mirror = tmp / "mirror.git"
    if not mirror.exists():
        subprocess.run(["git", "clone", "-q", "--bare", str(tmp / "up"), str(mirror)], check=True)
    p = subprocess.run(["sh", "-c", scripts.CARRY, "sh", str(mirror), "https://example.org/viewer.git", str(tmp / tree),
                        old, new, *pairs], capture_output=True, text=True)
    return p.returncode, p.stdout + p.stderr


def results(out):
    return {l.split()[1]: l.split()[2] for l in out.splitlines() if l.startswith("@@CHANGE ")}


def test_changes_go_on_their_own_release_as_they_are(gitenv):
    up = upstream(gitenv)
    rc, out = carry(gitenv, "v1", "v1", changes(gitenv, up))
    assert rc == 0, out
    assert results(out) == {"drag-zoom": "ok", "copy-path": "ok"}
    tree = gitenv / "tree"
    assert git(tree, "remote", "get-url", "origin").strip() == "https://example.org/viewer.git"
    assert git(tree, "rev-parse", "--abbrev-ref", "HEAD").strip() == "dvm/work"
    assert git(tree, "rev-parse", "refs/dvm/prepared") == git(tree, "rev-parse", "HEAD")
    log = git(tree, "log", "--format=%(trailers:key=DVM-Change,valueonly)", "v1..HEAD").split()
    assert log == ["copy-path", "drag-zoom"]


def test_a_new_release_that_moved_the_file_still_takes_the_change(gitenv):
    up = upstream(gitenv)
    rc, out = carry(gitenv, "v1", "v2", changes(gitenv, up))
    assert rc == 0, out
    assert results(out) == {"drag-zoom": "ok", "copy-path": "ok"}
    text = (gitenv / "tree" / "src_viewer.c").read_text()
    assert "line 3 (drag to zoom)" in text and "line 25 (faster)" in text      # both: theirs and the user's
    assert git(gitenv / "tree", "merge-base", "--is-ancestor", "v2", "HEAD") == ""


def test_a_file_the_change_adds_follows_a_folder_the_project_renamed(gitenv):
    """Where git am -3 succeeds but leaves the new file in the old folder, which the build no longer
    reads: a merge of the whole trees puts it in the new one."""
    up = gitenv / "up"
    up.mkdir()
    git(up, "init", "-q", "-b", "main")
    write(up, "plugins/a.c", "a\n"); write(up, "plugins/b.c", "b\n")
    git(up, "add", "-A"); git(up, "commit", "-qm", "First"); git(up, "tag", "v1")
    work = gitenv / "made"
    git(gitenv, "clone", "-q", str(up), str(work))
    git(work, "checkout", "-q", "-b", "dvm/work", "v1")
    write(work, "plugins/zoom.c", "zoom\n")
    git(work, "add", "-A"); git(work, "commit", "-qm", "A zoom plug-in", "--trailer", "DVM-Change: zoom")
    (gitenv / "zoom.patch").write_text(git(work, "format-patch", "--stdout", "v1..HEAD"))
    git(up, "mv", "plugins", "extensions"); git(up, "commit", "-qm", "Rename the folder"); git(up, "tag", "v2")
    rc, out = carry(gitenv, "v1", "v2", ["zoom", str(gitenv / "zoom.patch")])
    assert rc == 0 and results(out) == {"zoom": "ok"}, out
    assert (gitenv / "tree" / "extensions" / "zoom.c").exists() and not (gitenv / "tree" / "plugins").exists()


def test_a_change_that_conflicts_is_left_out_and_the_others_still_go_on(gitenv):
    up = upstream(gitenv)
    rc, out = carry(gitenv, "v1", "v3", changes(gitenv, up))
    assert rc == 3
    assert results(out) == {"drag-zoom": "failed", "copy-path": "ok"}
    assert "src_viewer.c" in out                                              # where it conflicts, for the assistant
    tree = gitenv / "tree"
    assert git(tree, "status", "--porcelain") == "" and (tree / "copy.c").exists()
    assert "(drag to zoom)" not in (tree / "src_viewer.c").read_text()


def test_a_change_the_project_has_made_itself_is_dropped(gitenv):
    up = upstream(gitenv)
    pairs = changes(gitenv, up)
    write(up, "copy.c", "copy the path\n")
    git(up, "add", "-A"); git(up, "commit", "-qm", "Copy the path (upstream)"); git(up, "tag", "v4")
    rc, out = carry(gitenv, "v1", "v4", pairs)
    assert results(out)["copy-path"] == "merged"


def test_an_earlier_tree_is_kept_aside_not_lost(gitenv):
    up = upstream(gitenv)
    pairs = changes(gitenv, up)
    carry(gitenv, "v1", "v1", pairs)
    (gitenv / "tree" / "unsaved.txt").write_text("work of an earlier chat")
    rc, _ = carry(gitenv, "v1", "v1", pairs)
    assert rc == 0 and not (gitenv / "tree" / "unsaved.txt").exists()
    kept = list((gitenv / ".old").iterdir())
    assert len(kept) == 1 and (kept[0] / "unsaved.txt").read_text() == "work of an earlier chat"


def test_inspect_reads_each_commits_change_and_merges(gitenv):
    up = upstream(gitenv)
    work = gitenv / "w"
    git(gitenv, "clone", "-q", str(up), str(work))
    git(work, "checkout", "-q", "-b", "x", "v1")
    write(work, "a.c", "a\n"); git(work, "add", "-A"); git(work, "commit", "-qm", "A", "--trailer", "DVM-Change: new")
    git(work, "merge", "-q", "--no-ff", "-m", "Merge", "v2")
    git(work, "remote", "add", "fork", "https://example.org/fork.git")
    p = subprocess.run(["python3", "-c", scripts.INSPECT, str(work), "v1", "HEAD"], capture_output=True, text=True, check=True)
    info = json.loads(p.stdout)
    assert info["origin"] == str(up) and sorted(info["remotes"]) == ["fork", "origin"]
    mine = [c for c in info["commits"] if c["subject"] == "A"][0]
    assert mine["changes"] == ["new"] and not mine["merge"]
    assert any(c["merge"] for c in info["commits"])


def test_a_patch_from_before_trailers_gets_its_change_named_and_still_applies(gitenv):
    up = upstream(gitenv)
    work = gitenv / "w"
    git(gitenv, "clone", "-q", str(up), str(work))
    git(work, "checkout", "-q", "-b", "x", "v1")
    write(work, "a.c", "a\n"); git(work, "add", "-A"); git(work, "commit", "-qm", "Only a subject")
    write(work, "b.c", "b\n"); git(work, "add", "-A")
    git(work, "commit", "-qm", "With a body", "-m", "Why it is so.", "--trailer", "Signed-off-by: dev <dev@example.org>")
    series = git(work, "format-patch", "--stdout", "v1..HEAD")
    named = "".join(apps.with_trailer(chunk, "zoom") for _, chunk in apps.split_patch(series))
    assert [apps.trailer_of(c) for _, c in apps.split_patch(named)] == ["zoom", "zoom"]
    (gitenv / "named.patch").write_text(named)
    git(work, "checkout", "-q", "-b", "y", "v1")
    git(work, "am", "-q", str(gitenv / "named.patch"))
    assert git(work, "log", "--format=%(trailers:key=DVM-Change,valueonly)", "v1..HEAD").split() == ["zoom", "zoom"]
    assert "Signed-off-by: dev" in git(work, "log", "-1", "--format=%B")
