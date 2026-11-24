"""Release tags: which of an upstream's tags is a newer release than the one an app was built on."""

from __future__ import annotations

import re

_NUMBERS = re.compile(r"\d+(?:[._]\d+)*")
_DATED = re.compile(r"\d+(?:-\d+)+")       # a release named by its date, 2024-01-15
# a word of its own: until Nov 2026 "latest" (test) and "src" (rc) made a release a pre-release
_PRERELEASE = re.compile(r"(?<![a-z])(?:alpha|beta|rc|pre|preview|dev|devel|snapshot|nightly|test|testing)(?![a-z])"
                         r"|(?:^|[._-])[ab]\d", re.I)


def parse(tag: str) -> tuple[str, tuple[int, ...], str] | None:
    """("v", (0, 39, 0), "") for "v0.39.0": the text before the version, its numbers, the rest. The
    version is the first run of numbers with a dot or underscore in it, else one with dashes (a date), else
    the first run: a digit in the project's name isn't it ("xfce4-terminal-1.1.3" is 1.1.3, not 4)."""
    runs = list(_NUMBERS.finditer(tag or ""))
    m = next((r for r in runs if re.search(r"[._]", r.group())), None) or _DATED.search(tag or "") or \
        (runs[0] if runs else None)
    if not m or len(m.group()) > 40:
        return None
    return tag[:m.start()], tuple(int(x) for x in re.split(r"[._-]", m.group())), tag[m.end():]


def _pre_number(rest: str) -> int:
    """Which of a release's pre-releases: rc2 is after rc1 (until Nov 2026 they were the same, so a newer one of the
    pre-releases an app was built on was never found)."""
    found = _PRERELEASE.search(rest)
    n = re.search(r"\d+", rest[found.end():]) if found else None
    return int(n.group()) if n else 0


def is_prerelease(tag: str) -> bool:
    p = parse(tag)
    return bool(p and _PRERELEASE.search(p[2]))


def _key(nums: tuple[int, ...]) -> tuple[int, ...]:
    return nums + (0,) * (6 - len(nums)) if len(nums) < 6 else nums


def newer(base: str, tags: list[str]) -> str | None:
    """The newest release among `tags` after `base`, in the same naming (same prefix: "v1.2" isn't
    compared with "gtk-1.3"). Pre-releases count only if `base` is one. None if `base` isn't one
    of the tags (a commit or a branch: nothing to compare with), or nothing is newer."""
    b = parse(base)
    if b is None or base not in tags:
        return None
    base_pre = bool(_PRERELEASE.search(b[2]))
    best, best_key = None, None
    for t in tags:
        p = parse(t)
        if p is None or p[0] != b[0] or len(p[1]) == 1 and len(b[1]) > 1 and p[1][0] > 1000:
            continue                            # another naming, or a date-like tag
        pre = bool(_PRERELEASE.search(p[2]))
        if pre and not base_pre:
            continue
        key = (_key(p[1]), not pre, _pre_number(p[2]) if pre else 0)
        if key > (_key(b[1]), not base_pre, _pre_number(b[2]) if base_pre else 0) and (best_key is None or key > best_key):
            best, best_key = t, key
    return best


def tags_from_ls_remote(out: str) -> list[str]:
    """Tag names from `git ls-remote --tags --refs`."""
    tags = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) == 2 and parts[1].startswith("refs/tags/"):
            tags.append(parts[1][len("refs/tags/"):])
    return tags
