"""Best-effort secret redaction applied before any text is shown for sending to the AI.

This is a safety net, not a guarantee: the technician reviews and can edit everything
before it is sent.
"""

from __future__ import annotations

import re

MASK = "[REDACTED]"

_I = re.IGNORECASE

# (pattern, replacement). Replacements keep the key name so the AI still understands context.
RULES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----", re.S),
     "[REDACTED PRIVATE KEY]"),
    (re.compile(r"(\bauthorization\s*:\s*)(bearer|basic|token)\s+\S+", _I), r"\1\2 " + MASK),
    (re.compile(r"\bbearer\s+[A-Za-z0-9._~+/=-]{12,}", _I), "Bearer " + MASK),
    (re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), MASK),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{16,}"), MASK),
    (re.compile(r"\b(ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}"), MASK),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), MASK),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), MASK),  # JWT
    # crypt(3) hashes as in /etc/shadow
    (re.compile(r"\$(1|2[abxy]?|5|6|y|gy|7)\$[^\s:]{8,}"), "[REDACTED HASH]"),
    # Cisco / network device secrets
    # (line-anchored or type-digit forms only, so log lines like "Failed password for root" survive)
    (re.compile(r"\b(enable\s+(?:secret|password)|secret|key-string|pre-shared-key|wpa-psk|isakmp\s+key)"
                r"(\s+\d{1,2})?\s+(?!\[REDACTED)\S+", _I), r"\1\2 " + MASK),
    (re.compile(r"\b(password)(\s+\d{1,2})\s+(?!\[REDACTED)\S+", _I), r"\1\2 " + MASK),
    (re.compile(r"^(\s*(?:username\s+\S+.*?\s)?password)\s+(?!\[REDACTED)\S+", _I | re.M), r"\1 " + MASK),
    (re.compile(r"\bsnmp-server\s+community\s+\S+", _I), "snmp-server community " + MASK),
    # PowerShell
    (re.compile(r"(-(Password|Secret|Token|ApiKey|Key|Credential)\s+)(['\"]).*?\3", _I), r"\1" + MASK),
    (re.compile(r"(ConvertTo-SecureString\s+(-String\s+)?)(['\"]).*?\3", _I), r"\1" + MASK),
    # key=value / key: value (env files, config files, URLs, RouterOS password=)
    (re.compile(r"\b([A-Za-z0-9_.-]*(password|passwd|pwd|passphrase|secret|token|api[_-]?key|access[_-]?key|"
                r"private[_-]?key|client[_-]?secret|auth[_-]?key|shared[_-]?key|psk)[A-Za-z0-9_.-]*)(\s*[=:]\s*)"
                r"(?!\s*$)(?!\[REDACTED)(\"[^\"]*\"|'[^']*'|\S+)", _I), r"\1\3" + MASK),
    # credentials in URLs: scheme://user:pass@host
    (re.compile(r"(\b[a-z][a-z0-9+.-]*://[^\s:/@]+:)[^\s@/]+@", _I), r"\1" + MASK + "@"),
]


def redact(text: str) -> tuple[str, int]:
    """Return (redacted_text, number_of_redactions)."""
    total = 0
    for pat, repl in RULES:
        text, n = pat.subn(repl, text)
        total += n
    return text, total
