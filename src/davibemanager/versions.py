"""Release tags: which of an upstream's tags is a newer release than the one an app was built on."""

from __future__ import annotations

import re

_NUMBERS = re.compile(r"\d+(?:[._]\d+)*")
_PRERELEASE = re.compile(r"alpha|beta|rc|pre|dev|snapshot|nightly|test|(?:^|[._-])[ab]\d", re.I)


def parse(tag: str) -> tuple[str, tuple[int, ...], str] | None:
    """("v", (0, 39, 0), "") for "v0.39.0": the text before the version, its numbers, the rest."""
    m = _NUMBERS.search(tag or "")
    if not m or len(m.group()) > 40:
        return None
    return tag[:m.start()], tuple(int(x) for x in re.split(r"[._]", m.group())), tag[m.end():]


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
        key = (_key(p[1]), not pre)
        if key > (_key(b[1]), not base_pre) and (best_key is None or key > best_key):
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
