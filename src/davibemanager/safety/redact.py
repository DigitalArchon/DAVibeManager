"""Best-effort secret redaction applied before any text is shown for sending to the AI.

This is a safety net, not a guarantee: the technician reviews and can edit everything
before it is sent.
"""

from __future__ import annotations

import re

MASK = "[REDACTED]"

_I = re.IGNORECASE

# (pattern, replacement). Replacements keep the key name so the AI still understands context.
# A replacement may be a function, which returns the match unchanged when it is no secret.
_SECRET_WORDS = (r"password|passwd|pwd|passphrase|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret"
                 r"|auth[_-]?key|shared[_-]?key|account[_-]?key|psk|wep[_-]?key\d*")     # AccountKey: Azure's; wep-key0: NetworkManager's
# A key is a whole name holding one of the words, taken at once: read from every - or . inside a
# long name (a base64url blob), and backtracked through, a line took minutes
_NAME = rf"(?=[A-Za-z0-9_.-]*?(?:{_SECRET_WORDS}))[A-Za-z0-9_.-]++"
_WORD = re.compile(_SECRET_WORDS, _I)
_KEY_VALUE = re.compile(
    rf"(?<![A-Za-z0-9_.-])({_NAME})"
    # = : or => (JSON's "key": and PHP's 'key' => too), and the value on the key's own line: a key
    # with nothing after it doesn't take the next line's key or text
    r"([\"']?[ \t]*(?:=>|[=:])[ \t]*)(?![ \t]*$)(?!\[REDACTED)(\"[^\"]*\"|'[^']*'|\S+)", _I | re.M)
_NO_SECRET = re.compile(r"[\"']?(true|false|yes|no|none|null|never|enabled|disabled|n/a)[\"']?[,;]?", _I)
_ABOUT_IT = re.compile(r"last|set|expir|age|date|time|changed|count|length|history|type|flags", _I)   # PasswordLastSet, psk-flags


def _key_value(m: re.Match) -> str:
    key, sep, value = m.group(1), m.group(2), m.group(3)
    word = _WORD.search(key).group()
    if _NO_SECRET.fullmatch(value):                          # PasswordRequired : True
        return m.group(0)
    if _ABOUT_IT.search(key.replace(word, "", 1)) and re.fullmatch(r"[\d/.:-]+[,;]?", value):
        return m.group(0)                                    # PasswordLastSet : 1/2/2025, PasswordAge=42
    if key.upper() in ("PWD", "OLDPWD") and value[:1] in "/~":
        return m.group(0)                                    # the working directory, in env output
    return key + sep + MASK


RULES: list[tuple[re.Pattern, object]] = [
    # PGP's too (PRIVATE KEY BLOCK), and a key cut short (head of a key file, output shortened): to its end
    (re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----|\Z)", re.S),
     "[REDACTED PRIVATE KEY]"),
    # an Authorization header, whatever its scheme (Bearer, Basic, Negotiate, NTLM, Digest...)
    (re.compile(r"(\bauthorization[ \t]*:[ \t]*)([A-Za-z][\w-]*)[ \t]+(?!\[REDACTED)[^\r\n]+", _I), r"\1\2 " + MASK),
    (re.compile(r"\bbearer\s+[A-Za-z0-9._~+/=-]{12,}", _I), "Bearer " + MASK),
    (re.compile(r"(\b(?:set-)?cookie[ \t]*:[ \t]*)(?!\[REDACTED)[^\r\n]+", _I), r"\1" + MASK),     # sessions
    (re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), MASK),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{16,}"), MASK),
    (re.compile(r"\b(ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}"), MASK),
    (re.compile(r"\b(?:xox[abeoprs]|xapp)-[A-Za-z0-9-]{10,}"), MASK),     # Slack's tokens, an app's too
    (re.compile(r"\bgl(?:pat|ptt|dt|rt|cbt)-[A-Za-z0-9_-]{20,}"), MASK),  # GitLab
    (re.compile(r"\bhf_[A-Za-z0-9]{30,}"), MASK),                         # Hugging Face
    (re.compile(r"\bnpm_[A-Za-z0-9]{30,}"), MASK),                        # npm
    (re.compile(r"\bpypi-AgE[A-Za-z0-9_-]{50,}"), MASK),                  # PyPI
    (re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}"), MASK),  # SendGrid
    (re.compile(r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}"), MASK),        # Stripe's secret and restricted keys
    (re.compile(r"\bAIza[0-9A-Za-z_-]{35}"), MASK),                       # Google's API keys
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), MASK),  # JWT
    # webhooks, whose address is their key: Slack's and Discord's
    (re.compile(r"(\bhooks\.slack\.com/(?:services|workflows|triggers)/)[A-Za-z0-9/_-]+"), r"\1" + MASK),
    (re.compile(r"(\bdiscord(?:app)?\.com/api/webhooks/\d+/)[A-Za-z0-9_-]+"), r"\1" + MASK),
    # crypt(3) hashes as in /etc/shadow
    (re.compile(r"\$(1|2[abxy]?|5|6|y|gy|7)\$[^\s:]{8,}"), "[REDACTED HASH]"),
    # Wi-Fi keys, as `netsh wlan show profile name=... key=clear` prints them
    (re.compile(r"(\bKey Content[ \t]*:[ \t]*)(?!\[REDACTED)\S[^\r\n]*", _I), r"\1" + MASK),
    # passwords on a command line: mysql -pSECRET (-p alone asks), sshpass -p SECRET
    (re.compile(r"(\b(?:mysql|mysqldump|mysqladmin|mariadb|mariadb-dump)\b(?:(?!\b(?:mysql|mariadb)\b)[^\n])*?\s-p)(?!\[REDACTED)(?=\S)\S+"),
     r"\1" + MASK),
    (re.compile(r"(\bsshpass\s+(?:-\S+\s+)*?-p[ \t]*)(?!\[REDACTED)\S+"), r"\1" + MASK),
    # curl -u user:password (and its proxy's), the password after the first colon
    (re.compile(r"(\b(?:curl|wget)\b(?:(?!\b(?:curl|wget)\b)[^\n])*?\s(?:-u|--user|-U|--proxy-user)[ \t]*=?[ \t]*)(['\"])?([^\s:'\"]+:)(?!\[REDACTED)"
                r"(?(2)[^'\"\n]*|[^\s'\"]+)"), r"\1\2\3" + MASK),
    # .netrc on one line: machine HOST login NAME password SECRET
    (re.compile(r"^([ \t]*(?:machine[ \t]+\S+|default)(?:[ \t]+(?:login|account|port)[ \t]+\S+)*[ \t]+password[ \t]+)"
                r"(?!\[REDACTED)\S+", re.M), r"\1" + MASK),
    # rclone's `pass = ...` (obscured, which anyone can undo)
    (re.compile(r"^([ \t]*pass[ \t]*=[ \t]*)(?![ \t]*$)(?!\[REDACTED)\S[^\n]*", _I | re.M), r"\1" + MASK),
    # Cisco / network device secrets
    # (line-anchored or type-digit forms only, so log lines like "Failed password for root" survive;
    # not kubectl's `get secret NAME`, which names one). Never an = or : for the value: `secret = X`
    # and `Password : X` are key=value forms, below, which blank X and not the separator
    (re.compile(r"\b(enable[ \t]+(?:secret|password)|(?<!get )(?<!describe )(?<!delete )(?<!edit )(?<!create )secret"
                r"|key-string|pre-shared-key|wpa-psk|isakmp[ \t]+key)([ \t]+\d{1,2})?[ \t]+(?![=:])(?!\[REDACTED)\S+", _I),
     r"\1\2 " + MASK),
    (re.compile(r"\b(password)([ \t]+\d{1,2})[ \t]+(?!\[REDACTED)\S+", _I), r"\1\2 " + MASK),
    # not the labels of `net user` output: "Password last set", "Password expires"
    (re.compile(r"^([ \t]*(?:username[ \t]+\S+.*?[ \t])?password)[ \t]+(?![=:])(?!\[REDACTED)"
                r"(?!(?:last|expires|changeable|required|age|never|history|length|policy|must|may|for|is|was|has|reset|change)\b)\S+",
                _I | re.M), r"\1 " + MASK),
    (re.compile(r"\bsnmp-server\s+community\s+\S+", _I), "snmp-server community " + MASK),
    # PowerShell
    (re.compile(r"(-(Password|Secret|Token|ApiKey|Key|Credential)\s+)(['\"]).*?\3", _I), r"\1" + MASK),
    (re.compile(r"(ConvertTo-SecureString\s+(-String\s+)?)(['\"]).*?\3", _I), r"\1" + MASK),
    # web.config / app.config: <add key="DbPassword" value="..."/>
    (re.compile(rf"(\bkey[ \t]*=[ \t]*\"(?=[^\"]*?(?:{_SECRET_WORDS}|connection[_-]?string))[^\"]*+\"[ \t]+value[ \t]*=[ \t]*\")"
                r"(?!\[REDACTED)[^\"]*\"", _I), r"\1" + MASK + '"'),
    # YAML block scalars: `password: |` and the lines indented under it
    (re.compile(rf"^(([ \t]*){_NAME}[ \t]*:[ \t]*[|>][-+]?[ \t]*\n)"
                r"(?:\2[ \t]+\S[^\n]*(?:\n|$))+", _I | re.M), r"\1\2  " + MASK + "\n"),
    # a YAML value on the line under its key (`password:` then `  s3cret`), not a mapping under it
    (re.compile(rf"^(([ \t]*){_NAME}[ \t]*:[ \t]*\n\2[ \t]+)"
                r"(?![^\n]*:(?:[ \t]|$))(?!-[ \t])(?!\[REDACTED)\S[^\n]*", _I | re.M), r"\1" + MASK),
    # key=value / key: value (env files, config files, JSON, a Python dict, URLs, RouterOS password=)
    (_KEY_VALUE, _key_value),
    (re.compile(r"([\"']auth[\"'][ \t]*:[ \t]*)(?!\[REDACTED)(\"[^\"]*\"|'[^']*')", _I), r"\1" + MASK),     # docker's config.json
    # credentials in URLs: scheme://user:pass@host
    (re.compile(r"((?<![a-z0-9+.-])[a-z][a-z0-9+.-]*+://[^\s:/@]+:)[^\s@/]+@", _I), r"\1" + MASK + "@"),
]


def redact(text: str) -> tuple[str, int]:
    """Return (redacted_text, number_of_redactions)."""
    total = 0
    for pat, repl in RULES:
        if callable(repl):
            done = 0

            def counted(m: re.Match, repl=repl) -> str:
                nonlocal done
                out = repl(m)
                done += out != m.group(0)
                return out
            text = pat.sub(counted, text)
            total += done
        else:
            text, n = pat.subn(repl, text)
            total += n
    return text, total
