"""Head+tail truncation so large outputs don't blow the model's context."""

from __future__ import annotations


def head_tail(text: str, max_lines: int, max_chars: int) -> tuple[str, bool]:
    """Keep the start and (more of) the end; errors usually appear late in output."""
    lines = text.splitlines()
    truncated = False
    if len(lines) > max_lines:
        head_n = max_lines // 3
        tail_n = max_lines - head_n
        omitted = len(lines) - head_n - tail_n
        lines = lines[:head_n] + [f"[... {omitted} lines omitted ...]"] + lines[-tail_n:]
        truncated = True
    out = "\n".join(lines)
    if len(out) > max_chars:
        head_c = max_chars // 3
        tail_c = max_chars - head_c
        omitted = len(out) - head_c - tail_c
        out = out[:head_c] + f"\n[... {omitted} characters omitted ...]\n" + out[-tail_c:]
        truncated = True
    return out, truncated
