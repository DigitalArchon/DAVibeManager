"""Characters in a command that the technician can't see, removed before it is queued.

A proposed command is shown in the queue and then typed into a terminal exactly as stored, so
what is shown must be what runs. Text the page can't display faithfully breaks that:

- control characters (ESC, ^C, a bare CR, ...) are invisible in the queue but act in the
  terminal: an escape sequence can end bracketed paste, so the rest runs as typed;
- bidi overrides and isolates reorder what is displayed ("Trojan Source");
- zero-width and other format characters, Unicode tag characters (which can smuggle whole
  hidden sentences) and variation selectors are invisible;
- look-alike spaces (no-break, thin, ideographic, ...) look like a space but don't separate
  words in a shell.

Line breaks and tabs are kept (multi-line PowerShell and heredocs are legitimate); CR LF and
lone CR become LF. Look-alike spaces become plain spaces, everything else is removed, and
what was changed is reported so the technician knows the AI's text carried it."""

from __future__ import annotations

import unicodedata

# invisible, but not "Cf" or "Cc": Hangul fillers render blank
_BLANK_LETTERS = {"\u115f", "\u1160", "\u3164", "\uffa0"}


def _hidden(ch: str) -> bool:
    if ch in "\t\n":
        return False
    cat = unicodedata.category(ch)
    if cat in ("Cc", "Cf", "Cn", "Zl", "Zp"):
        return True
    o = ord(ch)
    return 0xFE00 <= o <= 0xFE0F or 0xE0100 <= o <= 0xE01EF or ch in _BLANK_LETTERS


def _name(ch: str) -> str:
    return f"U+{ord(ch):04X} {unicodedata.name(ch, 'control character')}"


def clean(command: str) -> tuple[str, list[str]]:
    """Return (command as it will be shown and typed, what was changed). The list is empty
    when nothing was."""
    text = command.replace("\r\n", "\n").replace("\r", "\n")
    out, removed, spaces = [], {}, {}
    for ch in text:
        if _hidden(ch):
            removed[ch] = removed.get(ch, 0) + 1
        elif ch != " " and unicodedata.category(ch) == "Zs":
            spaces[ch] = spaces.get(ch, 0) + 1
            out.append(" ")
        else:
            out.append(ch)
    notes = [f"removed {n}× {_name(ch)}" for ch, n in removed.items()]
    notes += [f"{n}× {_name(ch)} made a plain space" for ch, n in spaces.items()]
    return "".join(out), notes
