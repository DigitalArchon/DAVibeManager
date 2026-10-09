"""Heuristic detection of prompt-injection text in command output.

Command output is untrusted: a log line, a banner, a file or a web page can contain text
written to steer the model. The system prompt tells the model to ignore such text, but the
technician should also know it is there before they send it. This is a warning, not a filter.
"""

from __future__ import annotations

import re

_I = re.IGNORECASE

PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\b(ignore|disregard|forget)\b.{0,40}\b(previous|prior|above|earlier|all)\b.{0,20}\b(instructions?|prompts?|rules?)\b", _I),
     "asks to ignore previous instructions"),
    (re.compile(r"\b(new|updated|revised)\s+(system\s+)?(instructions?|prompt|rules?)\s*:", _I), "declares new instructions"),
    (re.compile(r"\bsystem\s+prompt\b", _I), "mentions the system prompt"),
    (re.compile(r"\byou\s+are\s+(now|no\s+longer)\b", _I), "tries to change the AI's role"),
    (re.compile(r"\bas\s+an?\s+(ai|assistant|language\s+model)\b", _I), "addresses the AI directly"),
    (re.compile(r"\b(propose_commands|tool_calls?|function_call)\b", _I), "names the tool interface"),
    (re.compile(r"^\s*(system|assistant|user|human|ai)\s*:\s*\S", _I | re.M), "fake chat-role line"),
    (re.compile(r"<\s*/?\s*\|?\s*(system|instructions?|assistant|tool_result|tool_call|im_start|im_end)\b", _I), "chat/markup control tag"),
    (re.compile(r"\[\s*(INST|/INST|SYSTEM|SYS)\s*\]", _I), "chat/markup control tag"),
    (re.compile(r"\b(run|execute|type)\s+(the\s+)?following\s+(command|script)\b.{0,60}\b(immediately|now|without)\b", _I),
     "urges running a command"),
    (re.compile(r"\bdo\s+not\s+(tell|inform|show|warn)\s+the\s+(technician|user|operator|human)\b", _I), "asks to hide something from you"),
    (re.compile(r"\b(curl|wget|Invoke-WebRequest|iwr)\b[^\n]{0,120}\|\s*(sudo\s+)?(ba|z|)sh\b", _I), "contains a pipe-to-shell command"),
]


def suspicious(text: str) -> list[str]:
    """Return a de-duplicated list of reasons the text looks like a prompt injection."""
    out: list[str] = []
    for pat, why in PATTERNS:
        if why not in out and pat.search(text):
            out.append(why)
    return out
