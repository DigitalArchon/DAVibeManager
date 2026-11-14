"""The code every DA app shares is one copy, byte for byte (the cross-app standard, Nov 2026): the TEE
verifier and the Private Mode client are DA Toolkit's (src/datoolkit/llm/), and so are dcap.py, nras.py,
ethsig.py and sdk_guard.py (the last SealedLore's too). This app's copy may differ only in its imports
and in naming itself. A drift is a failing test here, not a finding of the next review: a change is made
in DA Toolkit's copy first, then copied. Skipped where DA Toolkit's repository isn't beside this one."""

import re
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parents[1] / "src" / "davibemanager" / "llm"
CANONICAL = Path(__file__).resolve().parents[1].parent / "DAToolkit" / "src" / "datoolkit" / "llm"
SHARED = ("tee.py", "private_mode.py", "dcap.py", "nras.py", "ethsig.py", "sdk_guard.py", "errors.py")

_NAMES = re.compile(r"datoolkit|davibemanager|daprivatecoder")
_APPS = re.compile(r"DA Toolkit|DA Vibe Manager|DA Private Coder")
# a top-level import statement (never a docstring's line that begins "from SealedLore (its …")
_IMPORT = re.compile(r"(import [\w.]+|from [\w.]+ import )")


def normalised(text: str) -> list[str]:
    """`text` without its top-level import statements (a parenthesised one with its continuation
    lines), each app's package and name the same word."""
    out, in_import = [], False
    for line in text.splitlines():
        if in_import:
            in_import = ")" not in line
            continue
        if _IMPORT.match(line):
            in_import = "(" in line and ")" not in line
            continue
        out.append(_APPS.sub("APPNAME", _NAMES.sub("APP", line)))
    return out


@pytest.mark.skipif(not CANONICAL.is_dir(), reason="DA Toolkit's repository isn't beside this one")
@pytest.mark.parametrize("name", SHARED)
def test_the_shared_code_is_da_toolkits_copy(name):
    ours, theirs = normalised((HERE / name).read_text()), normalised((CANONICAL / name).read_text())
    if ours != theirs:
        first = next((i for i, (a, b) in enumerate(zip(ours, theirs)) if a != b), min(len(ours), len(theirs)))
        pytest.fail(f"{name} differs from DA Toolkit's at line {first + 1} (normalised): "
                    f"{ours[first:first + 1]!r} here, {theirs[first:first + 1]!r} there. Change DA Toolkit's "
                    "copy first, then copy it here.")


def test_imports_are_dropped_whole_and_names_mapped():
    text = ("import a\nfrom .x import (b,\n    c)\nfrom .y import d\nx = 'DA Vibe Manager davibemanager'\n"
            "from SealedLore (its copy, kept)\n    import json\n")
    assert normalised(text) == ["x = 'APPNAME APP'", "from SealedLore (its copy, kept)", "    import json"]
