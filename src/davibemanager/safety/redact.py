"""Best-effort secret redaction applied before any text is shown for sending to the AI.

This is a safety net, not a guarantee: the technician reviews and can edit everything
before it is sent.

It runs on the whole of a command's output, on the event loop, so every rule reads its text in
linear time: a rule that names a word (a tool, a keyword, a token's prefix) is only tried on text
that holds the word, and a pattern that could be read in more than one way takes what it reads at
once (possessive quantifiers).
"""

from __future__ import annotations

import base64
import binascii
import re
from functools import lru_cache
from typing import NamedTuple

MASK = "[REDACTED]"
KEY_MASK = "[REDACTED PRIVATE KEY]"
HASH_MASK = "[REDACTED HASH]"

_I = re.IGNORECASE
_M = re.MULTILINE
_NEW = r"(?![\"']?\[REDACTED)"                             # not what an earlier rule has blanked
# a value as a command line or a device's configuration writes it: quoted, or to the next blank
_ARG = r"(?:\"[^\"\n]*+\"|'[^'\n]*+'|\S++)"
_VALUE = _NEW + r"(?![-|<>&;])" + _ARG                     # ... and not the next option, or the end of the command


# ---------------------------------------------------------------------------------------------- names
# What a name must hold to be a secret's. The words of the first kind are looked for anywhere in a
# name (DbPassword, userPassword, unicodePwd, ms-Mcs-AdmPwd); those too short for that (pass, pw,
# cred, key) only as a part of it, the parts being what _ - . or a capital letter divide (DB_PASS,
# bindpw, smtpPass, ENCRYPTION_KEY), so that bypass, compass and keyboard aren't.
_STRONG = re.compile(r"passwor[dt]|passwd|pwd|passphrase|secret|token|credential|api[_-]?key|access[_-]?key|private[_-]?key"
                     r"|auth[_-]?key|shared[_-]?key|account[_-]?key|psk|wep[_-]?key|key[_-]?material"     # AccountKey: Azure's
                     r"|kennwort|schlüsselinhalt|contrase[ñn]a|senha|wachtwoord")
# what a name holding a secret may hold, as the pattern that finds names reads it (the names are judged
# by _key), and the names under which an object keeps its value ("password": {"value": "..."})
_HINT = r"pass|pw|secret|token|key|cred|psk|_auth|sig|kennwort|schl|contrase|senha|wachtwoord"
_INNER = frozenset(("value", "val", "plaintext", "plain", "text", "data", "content", "string", "default"))
_INNER_HINT = r"val|plain|text|data|content|string|default"
_COMPOUND = re.compile(r"(?:db|user|usr|smtp|mail|imap|ftp|sftp|root|admin|bind|ldap|sql|mysql|pg|redis|proxy|http|ssh|smb|cifs"
                       r"|rpc|login|auth|my|sys|new|old|wifi|wlan|vpn|api|app|key|store|keystore|truststore|become|sudo|vault"
                       r"|master|svc)(?:pass|pw)|[a-z]{2,12}creds?")
_NOT_CREDS = frozenset(("sacred", "massacred"))
_PASS_OF = frozenset(("through", "thru", "rate", "mark", "band", "filter", "list", "fail", "count"))     # pass_through, pass_rate
# a *_key that is no secret by what stands before it, and what may follow the word in a name that is one
_KEY_OF = frozenset((
    "public", "pub", "primary", "foreign", "sort", "partition", "range", "cache", "registry", "reg", "hash", "index", "idx",
    "map", "dict", "lookup", "unique", "row", "column", "col", "group", "shard", "object", "obj", "config", "option", "opt",
    "setting", "search", "order", "by", "hot", "shortcut", "lang", "i18n", "translation", "message", "msg", "error",
    "routing", "host", "known", "authorized", "composite", "natural", "candidate", "parent", "child", "ref", "json", "yaml",
    "env", "var", "attribute", "attr", "property", "prop", "field", "tag", "label", "metric", "item", "entry", "record",
    "doc", "node", "name", "the", "a", "any", "no", "this", "each", "per", "press", "function", "fn", "modifier", "meta",
    "ctrl", "alt", "shift", "tab", "space", "enter", "escape", "arrow", "kbd", "keyboard", "s3", "bucket", "file", "dedup",
    "next", "prev", "previous", "first", "last", "start", "end", "min", "max",          # a listing's NEXT_KEY, a range's
    "power", "suspend", "hibernate", "reboot", "sleep", "wake", "volume", "media", "menu", "super", "win", "home", "delete",
    "backspace", "insert", "print", "pause", "left", "right", "up", "down"))             # logind.conf's HandlePowerKey
_KEY_TAIL = frozenset(("data", "base", "b64", "base64", "pem", "value", "val", "string", "str", "text", "hex", "bytes"))
_QUERY = frozenset(("key", "sig", "signature"))             # ?key=..., an Azure SAS's sig=
# names that say something about a secret and hold none: with these after the word, any value stays
_DESCRIBES = frozenset((
    "type", "name", "names", "file", "filename", "path", "dir", "directory", "backend", "provider", "endpoint", "url", "uri",
    "algorithm", "alg", "format", "policy", "mode", "source", "ref", "stdin", "header", "field", "label", "method", "scheme",
    "store", "manager", "engine"))
# ... and with these, a number or a date does (PasswordLastSet : 1/2/2025, PasswordAge=42, token_ttl: 3600,
# psk-flags=0), anything else being blanked
_ABOUT = frozenset((
    "last", "set", "expires", "expire", "expired", "expiry", "expiration", "expiring", "age", "date", "time", "timestamp",
    "changed", "change", "count", "length", "len", "history", "flags", "lifetime", "ttl", "days", "attempts", "retries",
    "min", "max", "minimum", "maximum", "size", "bits", "bytes", "version", "timeout", "validity", "duration", "created",
    "updated", "modified", "rotated", "rotation", "interval", "limit", "quota", "used", "remaining", "complexity",
    "iterations", "rounds", "cost", "id", "index", "number", "num", "länge", "laenge", "alter", "chronik", "longueur"))
_ABOUT_GLUED = ("lastset", "last", "expir", "age", "date", "time", "changed", "count", "length", "history", "flags",
                "lifetime", "ttl", "länge", "alter", "chronik")                    # passwordlastset, Kennwortlänge
_COUNTED = frozenset(("max", "min", "maximum", "minimum", "num", "total", "count", "number"))     # max_tokens=4096
_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")
_SPLIT = re.compile(r"[\W_]+|(?<=\D)(?=\d)|(?<=\d)(?=\D)")


class _Key(NamedTuple):
    """What a name says of its value. `about`: a number or a date under it is no secret; `paths`: a file's
    path isn't (credentials=/etc/smb.cred, ssl_key = /etc/ssl/private/x.key); `key`: it is a *_key,
    whose value may be a public key, a small number or a plain word; `passes`: a `pass`, which nginx
    gives an address; `ends`: the name ends with its word (password, not password-policy or libsecret-0);
    `plural`: it names several (secrets, tokens)."""
    about: bool = False
    paths: bool = False
    key: bool = False
    passes: bool = False
    ends: bool = False
    plural: bool = False


def _key(name: str, query: bool = False) -> _Key | None:
    """What the name of a setting, a field, an element or an option says of its value, None when it is
    no secret's. `query`: the name is a parameter of a URL's query, where key= and sig= are secrets too."""
    if len(name) > 80:                                       # a blob that happens to end in = or :
        return None
    return _judged(name, query)


@lru_cache(maxsize=4096)
def _judged(name: str, query: bool) -> _Key | None:
    norm = _CAMEL.sub("_", name).lower()
    parts = [p for p in _SPLIT.split(norm) if p]
    if not parts:
        return None
    strong = None
    for strong in _STRONG.finditer(norm):                    # the last one: what follows it says what the name is about
        pass
    if strong is not None:
        rest = norm[strong.end():]
        plural = rest[:1] == "s" and not rest[1:2].isalpha()                       # tokens: 1500
        glued = re.match(r"[^\W\d_]*", rest[1:] if plural else rest).group()       # passwordlastset, secretname
        after = [p for p in _SPLIT.split(rest[len(glued) + plural:]) if p]
        before = [p for p in _SPLIT.split(norm[:strong.start()]) if p]
        if glued in _DESCRIBES or any(p in _DESCRIBES for p in after):
            return None
        about = (plural or glued.startswith(_ABOUT_GLUED) or any(p in _ABOUT for p in after)
                 or any(p in _COUNTED for p in before))
        return _Key(about=about, paths=strong.group() == "credential", ends=not glued and not after,
                    plural=plural and strong.group() != "credential")
    at, found = -1, None
    for i, part in enumerate(parts):
        if part in ("pass", "pw") or (_COMPOUND.fullmatch(part) and part not in _NOT_CREDS) or part in ("cred", "creds"):
            if not (part == "pass" and parts[i + 1:i + 2] and parts[i + 1] in _PASS_OF):
                at, found = i, _Key(paths=part.endswith(("cred", "creds")), passes=part.endswith("pass"), ends=i == len(parts) - 1)
        elif part == "key" and i and parts[i - 1] not in _KEY_OF and not {"public", "pub"} & set(parts[:i]) \
                and all(p in _KEY_TAIL or p.isdigit() for p in parts[i + 1:]):
            return _Key(paths=True, key=True)                # ENCRYPTION_KEY, tls.key, client-key-data
    if found is None:
        if norm.strip("-.") == "_auth":                      # .npmrc's _auth: user:password in base64
            return _Key()
        if query and _QUERY & set(parts):
            return _Key()
        return None
    after = parts[at + 1:]
    if any(p in _DESCRIBES for p in after):
        return None
    return found._replace(about=any(p in _ABOUT for p in after) or any(p in _COUNTED for p in parts[:at]))


# values that are no secret whatever the name: PasswordRequired : True, Kennwort erforderlich: Ja, and what
# a tool prints in a secret's place (wg show's "(hidden)", a form's ********)
_NO_SECRET = re.compile(r"[\"']?(?:true|false|yes|no|none|null|nil|never|enabled?|disabled?|on|off|n/a|ja|nein|oui|non|keine?"
                        r"|nie|jamais|not set|\*+|•+|[(<\[](?:hidden|none|empty|not set|null|redacted|removed)[)>\]])[\"']?[,;.)\]]*+", _I)
_DATE_WORD = (r"(?:[-+]?\d[\d/.:,+\-TZ]*|[AP]M|UTC|GMT|days?|hours?|minutes?|seconds?|weeks?|months?|years?|never|none"
              r"|(?:mon|tue|wed|thu|fri|sat|sun|jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]{0,6}[.,]?)")
_DATELIKE = re.compile(rf"{_DATE_WORD}(?:[ \t,]++{_DATE_WORD})*+[,;]?", _I)
_PATH = re.compile(r"[\"']?(?:[~.]{0,2}/|[A-Za-z]:\\|\\\\|%[A-Za-z]|\$(?:HOME|PWD|\{))")
_ADDRESS = re.compile(r"[\"']?(?:[a-z][a-z0-9+.-]*://|unix:)(?![^/\s]*@)", _I)     # proxy_pass: http://backend
# a *_key that holds no key: a public one, a small number, one short plain word (HandlePowerKey=poweroff, sort_key: name)
_PUBLIC = re.compile(r"[\"']?(?:ssh-(?:rsa|dss|ed25519)|ecdsa-sha2-|sk-(?:ssh|ecdsa)-|(?:\d{1,5}|[A-Za-z]?[a-z]{1,10})[\"']?$)")
# /etc/nsswitch.conf's `passwd: files systemd`, and what passwd(1) and its like say of themselves
_PROGRAMS = frozenset(("passwd", "chpasswd", "gpasswd", "smbpasswd", "kpasswd", "ldappasswd", "yppasswd", "shadow", "gshadow"))
_NSS = re.compile(r"(?:(?:files|compat|db|systemd|sss|ldap|nis|nisplus|winbind|altfiles|extrausers|cache|hesiod|dns)\b[ \t]*"
                  r"|\[[!A-Za-z=, ]+\][ \t]*)+")
_SAYS = re.compile(r"(?:password |all authentication|authentication |permission denied|user |unknown user|you may not|cannot "
                   r"|can't |unrecognized |unrecognised |invalid |module |have exhausted|only root|the password|no password"
                   r"|warning|error|success|expiry |bad |unable |failed|usage|unlocking |locking |changing |removing |deleting )", _I)


_TEST = re.compile(r"(?:[\w./-]*\btest|Test)[\w./:\[\]-]*+(?:[ \t]++\(?[\d.]++m?s\)?)?$|[\w./-]++\.(?:py|sh|t|js|ts|go|rb|pl|bats)\b")


def _holds(key: _Key, name: str, value: str) -> bool:
    """Whether `value`, found under a secret's name, is one."""
    v = value.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'`":
        v = v[1:-1]
    if not v or v.startswith("[REDACTED") or _NO_SECRET.fullmatch(v) or len(v) <= 3 and not re.search(r"\w", v):
        return False                                         # nothing, a word that says so, a full stop
    if key.about and (about := _DATELIKE.match(v)) and (about.end() == len(v) or v[about.end()] in " \t()]}"):
        return False                                         # PasswordAge=42, tokens: 1500 (of 4096)
    if key.paths and _PATH.match(v) or key.key and _PUBLIC.match(v) or key.passes and _ADDRESS.match(v):
        return False
    low = name.lower()
    if low in ("pwd", "oldpwd") and v[:1] in "/~":           # the working directory, in env output
        return False
    if low in _PROGRAMS and (_NSS.fullmatch(v) or " " in v and _SAYS.match(v)):
        return False
    if name == "PASS" and _TEST.match(v):                    # a test's result: `PASS: tests/test_login.py::test_reset`
        return False
    return True


# ---------------------------------------------------------------------------------------------- key = value
# A name, then = : => := or :: (LDIF's base64 mark), the name in quotes or not (JSON's "key":, PHP's
# 'key' =>). A name is a whole run of its characters, taken at once: read from every - or . inside a
# long one (a base64url blob), and backtracked through, a line took minutes. What is found is a
# candidate: _HINTED says whether the name can be a secret's, _key whether it is.
_PAIR = re.compile(r"(?<![\w.-])([\w.-]++)([\"']?[ \t]*+(=>|:=|::|==|[=:])[ \t]*+)")
_HINTED, _HINTED_INSIDE = (re.compile(hint, _I).search for hint in (_HINT, _HINT + "|" + _INNER_HINT))
# a quoted value ends at its quote, not at one escaped inside it (\" in JSON and a shell, `" and "" in
# PowerShell, '' in SQL and YAML); a ' may only span lines when nothing is escaped in it
_QUOTED = {'"': re.compile(r'"(?:[^"\\`]|\\.|`.|"")*+"', re.S),
           "'": re.compile(r"'(?:[^'\\\n]|\\.|'')*+'|'[^']*+'"),
           "`": re.compile(r"`[^`\n]*+`")}
_ON_LINE = re.compile(r'"(?:[^"\\`\n]|\\.|`.|"")*+"')
_UNTIL = {'"': re.compile(r'[^"\n]*+'), "'": re.compile(r"[^'\n]*+")}
_BARE = re.compile(r"[^\s,}\]]*+")                          # JSON's numbers and words
_IN_QUERY = re.compile(r"[^&\s\"'<>]*+")
_IN_STRING = re.compile(r"\{[^}\n]*+\}?|[^;\"\n]*+")         # a connection string's value, ODBC's {...} too
_IN_LIST = re.compile(r"[^\s,})\]]*+")
_IN_FLOW = re.compile(r"[^,}\n]*+")
_WORD = re.compile(r"\S*+")
# an unquoted value at the start of its line runs to the line's end, less a comment and less the
# other pairs of a connection string (Password=a b;Server=db)
_CUT = re.compile(r"[ \t]#|;[ \t]*+(?:$|[\w .-]{1,40}=)")
_COMMENT = re.compile(r"[ \t]#")
_LINE_START = re.compile(r"[ \t]*+(?:[-+*>|#!;][ \t]*+)?(?:(?:export|set|setx|setenv|declare(?:[ \t]++-\w++)*+|local|readonly"
                         r"|typeset|env|var|let|const|my|our|global)[ \t]++)?[$@%]?(?:(?:env|global|script|local):)?", _I)
# a prompt's words before the name: what follows on the line is the program's answer more often than a
# password, which a terminal doesn't echo, so one word is blanked as it always was
_PROMPT = re.compile(r"(?:enter|new|retype|re-enter|current|old|confirm|verify|again|unix|'s)[ \t]++$", _I)
_BLOCK = re.compile(r"[|>][-+0-9]*+[ \t]*+\r?\n")            # YAML's block scalars
_INDENTED = re.compile(r"([ \t]*+)([^\n]*+)")
_NEXT_QUOTED = re.compile(r"\r?\n[ \t]*+(?=[\"'])")
_BRACE = re.compile(r"[{}]")
_ARRAY = re.compile(r"\[[^\[\]{}]*+\]")
_ANY = _Key()


def _pairs(text: str) -> tuple[str, int]:
    """key=value and key: value, in env files, config files, JSON, a Python dict, YAML, a URL's query,
    a connection string, RouterOS's password=. The name stays, so the AI still knows what was there.

    Until Nov 2026 the value was one word, whatever the format: `password: correct horse battery` lost
    its first word and `Password=my secret;` likewise, `"ab\\"cd"` ended at the escaped quote, and
    `password := x` and LDIF's `userPassword:: ...` lost their second : or =. An unquoted value now runs
    as far as its format lets it: to the end of the line for a setting on a line of its own, to the ; of
    a connection string, the & of a query, the , or } of JSON and of an option list, and one word only
    where the pair stands in the middle of a line (a command's NAME=value argument)."""
    if "=" not in text and ":" not in text:
        return text, 0
    out: list[str] = []
    n = last = pos = inner_until = 0
    size = len(text)

    def blank(start: int, end: int, mask: str = MASK) -> None:
        nonlocal n, last, pos
        out.append(text[last:start])
        out.append(mask)
        n += 1
        last = pos = end

    find = _PAIR.search
    while (m := find(text, pos)) is not None:
        start, at = m.start(), m.end()
        pos = at
        name = m[1]
        if not (_HINTED_INSIDE if start < inner_until else _HINTED)(name):
            continue
        sep, op = m[2], m[3]
        opened = start > 0 and text[start - 1] in "\"'"      # the name's opening quote
        closed = sep[0] in "\"'"
        b = start - opened
        # where the name stands on its line: at its start (after `export `, a list's dash, a comment's #),
        # or after what; looked for in the 200 characters before, so a long line costs no more
        floor = max(0, b - 200)
        nl = text.rfind("\n", floor, b)
        line = nl + 1 if nl >= 0 or not floor else -1
        lead = text[max(line, floor):b].rstrip(" \t")
        prev = lead[-1] if lead else "\n" if line >= 0 else " "
        quoted = not closed and lead.count('"') % 2 == 1      # the pair stands inside a "string"
        if name.lower() in _INNER:
            key = _ANY if start < inner_until else None
        else:
            key = _key(name, prev in "?&")
        if key is None:
            continue
        anchored = line >= 0 and _LINE_START.fullmatch(text, line, b) is not None
        # in the middle of a line, `name:value` with no blank is a pair only when the name ends with its
        # word (/password:x, pass:x; not libsecret-0:0.21.8 or a package's name:amd64), and a plural
        # (org.freedesktop.secrets: timed out) holds a secret only in quotes
        inside = not anchored and not closed and prev not in "?&;,{[("
        if inside and op == ":" and sep[-1] == ":" and (key.key or not key.ends):
            continue

        if at >= size or text[at] in "\r\n":                 # nothing after the separator on this line
            if closed and (nx := _NEXT_QUOTED.match(text, at)):
                at = nx.end()                                # JSON, its value on the next line
            else:
                if op == ":" and line >= 0 and not closed and not text[line:b].strip(" \t"):
                    indent = text[line:b]
                    below = _INDENTED.match(text, text.find("\n", at) + 1) if "\n" in text[at:at + 2] else None
                    if below and below[2].strip() and len(below[1]) > len(indent) and below[1].startswith(indent):
                        body = below[2]
                        if re.search(r":(?:[ \t\r]|$)", body):       # a mapping under the key: its `value:` is the secret
                            p, lines = below.end() + 1, 0
                            while p < size and lines < 30:
                                more = _INDENTED.match(text, p)
                                if more[2].strip() and not (len(more[1]) > len(indent) and more[1].startswith(indent)):
                                    break
                                p, lines = more.end() + 1, lines + 1
                            inner_until = min(p, size)
                        elif not body.startswith(("- ", "[REDACTED")) and body.strip() != "-":
                            blank(below.start(2), below.start(2) + len(body.rstrip()))       # the value on the line under its key
                continue

        c = text[at]
        # ... which ends here, when no quote on the line closes this one: `askpass "bob's password:"`.
        # (Read as a value's opening quote, it took the lines down to the next " anywhere.)
        if c in "\"'`" and (q := (_ON_LINE if c == '"' and quoted else _QUOTED[c]).match(text, at)):
            if _holds(key, name, q[0]):
                blank(at, q.end())
            else:
                pos = q.end()
            continue
        if text.startswith("[REDACTED", at) or key.plural and not anchored or c == '"' and quoted:
            continue
        yaml = op == ":" and anchored and not closed and not opened
        if c in "|>" and yaml and not text[line:b].strip(" \t") and (block := _BLOCK.match(text, at)):
            indent, p, end = text[line:b], block.end(), -1   # `password: |` and the lines indented under it
            while p < size:
                more = _INDENTED.match(text, p)
                if not (more[2].strip() and len(more[1]) > len(indent) and more[1].startswith(indent)):
                    break
                end = p = min(more.end() + 1, size)
            if end > 0:
                blank(block.end(), end, indent + "  " + MASK + "\n")
            continue
        if c == "{" and (closed or op in (":", "=>")):       # an object: the secret is under its "value"
            brace = _BRACE.search(text, at + 1, at + 4000)
            inner_until = brace.start() if brace else min(size, at + 4000)
            pos = at + 1
            continue
        if c == "[" and (closed or yaml) and (array := _ARRAY.match(text, at)):
            if array[0][1:-1].strip():
                blank(at + 1, array.end() - 1)
            continue

        if opened and not closed:                            # "PASSWORD=x" inside quotes: to the quote
            end = _UNTIL[text[b]].match(text, at).end()
        elif closed:
            end = _BARE.match(text, at).end()
        elif prev in "?&":
            end = _IN_QUERY.match(text, at).end()
        elif prev == ";":
            end = _IN_STRING.match(text, at).end()
        elif anchored:
            end = text.find("\n", at)
            end = size if end < 0 else end
            cut = (_CUT if op != ":" else _COMMENT).search(text, at, end)
            if cut:
                end = cut.start()
        elif prev in ",{[(":
            end = (_IN_FLOW if op == ":" and sep[-1] in " \t" else _IN_LIST).match(text, at).end()
        elif op in (":", "::") and sep[-1] in " \t" and not _PROMPT.search(text, max(0, b - 16), b):
            end = text.find("\n", at)                        # a label in the middle of a line: `VNC password: a b`
            end = size if end < 0 else end
        else:
            end = _WORD.match(text, at).end()
        if quoted and (close := text.find('"', at, end)) >= 0:
            end = close
        value = text[at:end].rstrip()
        if value and _holds(key, name, value):
            blank(at, at + len(value))
    if not n:
        return text, 0
    out.append(text[last:])
    return "".join(out), n


# ---------------------------------------------------------------------------------------------- other shapes
def _named(name_group: int, value_group: int, mask: str = MASK):
    """A replacement for a pattern that finds a name and a value apart from the key=value form (an XML
    element, an option and its argument, FortiGate's `set NAME VALUE`): the value is blanked when the
    name is a secret's, by the same rules as key=value."""
    def repl(m: re.Match) -> str:
        key = _key(m[name_group])
        value = m[value_group]
        if key is None or not _holds(key, m[name_group], value):
            return m[0]
        return m.string[m.start():m.start(value_group)] + mask + m.string[m.end(value_group):m.end()]
    return repl


def _on_lines(start: str, part: str, flags: int = 0, repl=r"\1" + MASK):
    """A rule for what follows `start` on its line (a command and its arguments, one line of a device's
    configuration): each `part` there is replaced, however many the line has. A command whose name
    comes again and again on a line is read once, not from each."""
    outer = re.compile(rf"(?<![\w-])(?:{start})(?![\w-])[^\n]*+", flags)
    inner = re.compile(part, flags)

    def rule(text: str) -> tuple[str, int]:
        n = 0

        def line(m: re.Match) -> str:
            nonlocal n
            out, k = inner.subn(repl, m[0])
            n += k
            return out
        return outer.sub(line, text), n
    return rule


def _option(option: str, gap: str = r"[ \t]++") -> str:
    """A command's option and the argument that is the secret: -P SECRET."""
    return rf"((?<=\s){option}{gap}){_VALUE}"


_PUBLIC_PEM = re.compile(rb"-----BEGIN (?:CERTIFICATE|TRUSTED CERTIFICATE|X509 CRL|(?:NEW )?CERTIFICATE REQUEST|(?:RSA |EC |DSA )?"
                         rb"PUBLIC KEY|SSH2 PUBLIC KEY|PGP PUBLIC KEY BLOCK|PGP SIGNATURE|PKCS7|DH PARAMETERS|EC PARAMETERS)-----")


def _pem_in_base64(m: re.Match) -> str:
    """A PEM file in base64, as a Kubernetes secret's tls.key and a kubeconfig's client-key-data hold it:
    blanked unless its first line says it is a certificate or a public key."""
    head = m[0][:80].replace("-", "+").replace("_", "/").rstrip("=")
    try:
        first = base64.b64decode(head[:len(head) // 4 * 4])
    except (binascii.Error, ValueError):
        first = b""
    return m[0] if _PUBLIC_PEM.match(first) else KEY_MASK


_PS_ARG = re.compile(r"\"(?:[^\"`\n]|`.|\"\")*+\"|'(?:[^'\n]|'')*+'|[^\s|;)]++")


def _secure_string(m: re.Match) -> str:
    """ConvertTo-SecureString's plain text: after -String, or the first argument that is no option,
    wherever -AsPlainText and -Force stand. A variable ($pw) and an expression in brackets stay."""
    args = m[2]
    named = other = False                                    # -String came just before; another option's argument is next
    for arg in _PS_ARG.finditer(args):
        word = arg[0]
        if word.startswith("-") and len(word) > 1 and not named:
            option = word.lower()
            named = len(option) > 2 and "-string".startswith(option)
            other = not named and ("-key".startswith(option) or "-securekey".startswith(option))     # the key that decrypts
            continue
        if other:
            other = False
            continue
        if re.fullmatch(r"\$[\w:{}.]+", word) or word[0] in "(@" or word.startswith("[REDACTED"):
            break
        return m[1] + args[:arg.start()] + MASK + args[arg.end():]
    return m[0]


_FLAG = re.compile(r"(?:passwor[dt]|passwd|pwd|pass|pw|passphrase|secret|token|psk|(?:api|access|account|shared|auth|secret)[_-]?key"
                   r"|secret[_-]access[_-]key)$")
_FLAG_NOT = re.compile(r"[<\[]?(?:string|str|text|value|arg|is|are|was|and|or|to|the|for|if|not|but|also|option|options|flag|command"
                       r"|parameter|argument|switch|must|can|will|should|with|in|on|of)[>\]]?[.,]?", _I)


def _flag(m: re.Match) -> str:
    """An option named for a secret and its argument: --password X, PowerShell's -Password X. The name
    ends with the word (not --password-file, --show-secrets, or gpg's --edit-key, which names a key);
    the next option, a variable, an expression and a manual's "--password is ..." are not the secret."""
    name, value = m[1], m[3]
    norm = _CAMEL.sub("_", name).lower()
    key = _key(name) if _FLAG.search(norm) else None
    if key is None or key.plural or re.fullmatch(r"[\"']?(?:\$[\w:{}.]+|%\w+%)[\"']?", value) or _FLAG_NOT.fullmatch(value) \
            or value.strip("<>[]\"'").lower() == norm.rsplit("-", 1)[-1].rsplit("_", 1)[-1] or not _holds(key, name, value):
        return m[0]
    return name + m[2] + MASK


def _token_user(m: re.Match) -> str:
    """https://TOKEN@github.com/...: a URL's user that is a token and no name (long, or letters of both
    cases and digits)."""
    user = m[2]
    token = len(user) >= 20 or (re.search(r"\d", user) and re.search(r"[a-z]", user) and re.search(r"[A-Z]", user))
    return m[1] + MASK + "@" if token and not user.startswith("[REDACTED") else m[0]


def _element(m: re.Match) -> str:
    """An XML element named for a secret (<password>, <bindpw>, <pre-shared-key>, <keyMaterial>), pfSense's
    <prv> (a certificate's private key) and its <bcrypt-hash>: the content is blanked, CDATA or not."""
    name, value = m[1], m[3].strip()
    if value.startswith("<![CDATA[") and value.endswith("]]>"):
        value = value[9:-3]
    low = name.lower()
    key = _Key() if low == "prv" or low.endswith("hash") else _key(name)
    if key is None or not _holds(key, name, value):
        return m[0]
    mask = KEY_MASK if low == "prv" else HASH_MASK if low.endswith("hash") else MASK
    return f"<{name}{m[2]}>{mask}</{name}>"


def _label(m: re.Match) -> str:
    return m[1] + MASK if _holds(_Key(paths=True), "", m[2]) else m[0]


_KEY_OF_WHAT = re.compile(r"(?<![\w-])(?:api|secret|access|private|pre-?shared|shared|encryption|decryption|signing|master"
                          r"|licen[sc]e|product|recovery|activation|auth(?:entication)?|session|wpa\d?|wep|wi-?fi|wlan)$", _I)


def _piped(m: re.Match) -> str:
    return m[1] + MASK + " " + m[3]


_QUALIFIER = (r"(?:\d{1,2}|ascii-text|ascii|hex(?:adecimal)?|ENC|encrypted|plaintext|cleartext|sha-?1|sha-?256|md5"
              r"|level[ \t]++\d{1,2})")
# the words between a device's keyword and its secret, which say how it is stored: `wpa-psk ascii 0 X`,
# Junos's `pre-shared-key ascii-text "..."`, FortiGate's ENC, HP's `password manager sha1 ...`. Until
# Nov 2026 the first of them was blanked in the secret's place.
_QUALIFIERS = rf"(?:{_QUALIFIER}[ \t]++(?=\S)){{0,4}}+"
_PAM = r"(?!(?:requisite|required|sufficient|optional)[ \t]++\S|(?:include|substack)[ \t]++\S|\[[^\]\n]*+\][ \t]++\S)"
_NAME = rf"(?=[\w.:-]*?(?:{_HINT}))[A-Za-z_][\w.:-]*+"       # a name that may be a secret's, for _named

WHOLE = "whole"
# (words, pattern, replacement[, WHOLE]). A rule is tried only on text that holds one of its words, in
# any case, and only on the lines that hold one when they are few: its word is always part of what it
# finds. A rule marked WHOLE finds what spans lines (a key block, an XML element, YAML's value under
# its key) and reads the whole text. The replacement keeps the key name so the AI still understands
# context; it may be a function, which returns the match unchanged when it is no secret. A rule with
# no pattern is a function of the text, which returns it with the number of its redactions.
RULES: list[tuple] = [
    # --- private keys
    # PEM (PGP's too: PRIVATE KEY BLOCK), OpenVPN's static key, ssh.com's with four dashes; and a key
    # cut short (the head of a key file, output shortened): to its end
    (("private key", "static key", "tls-crypt-v2"),
     re.compile(r"-{4,5} ?BEGIN (?:[A-Z0-9-]++ ){0,4}?(?:PRIVATE KEY(?: BLOCK)?|Static key V\d|(?:client|server) key) ?-{4,5}.*?"
                r"(?:-{4,5} ?END (?:[A-Z0-9-]++ ){0,4}?(?:PRIVATE KEY(?: BLOCK)?|Static key V\d|(?:client|server) key) ?-{4,5}|\Z)",
                re.S | _I), KEY_MASK, WHOLE),
    # PuTTY's .ppk: the lines under Private-Lines
    (("private-lines",), re.compile(r"(Private-Lines:[ \t]*+\d++[ \t]*+\r?\n)(?:[A-Za-z0-9+/=]++[ \t]*+(?:\r?\n|\Z))++"),
     r"\1" + KEY_MASK + "\n", WHOLE),
    (("ls0tls1crudjti",), re.compile(r"LS0tLS1CRUdJTi[A-Za-z0-9+/=_-]*+"), _pem_in_base64),
    (("age-secret-key-",), re.compile(r"\bAGE-SECRET-KEY-1[0-9A-Z]{20,}"), MASK),

    # --- headers
    # an Authorization header, whatever its scheme (Bearer, Basic, Negotiate, NTLM, Digest...)
    (("authorization",), re.compile(r"(\bauthorization[ \t]*+:[ \t]*+)([A-Za-z][\w-]*+)[ \t]++(?!\[REDACTED)[^\r\n]++", _I),
     r"\1\2 " + MASK),
    (("bearer",), re.compile(r"\bbearer\s++[A-Za-z0-9._~+/=-]{12,}", _I), "Bearer " + MASK, WHOLE),
    (("cookie",), re.compile(r"(\b(?:set-)?cookie[ \t]*+:[ \t]*+)(?!\[REDACTED)[^\r\n]++", _I), r"\1" + MASK),     # sessions

    # --- tokens known by their form
    (("akia", "asia"), re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), MASK),
    (("sk-",), re.compile(r"\bsk-[A-Za-z0-9_-]{16,}"), MASK),
    (("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"), re.compile(r"\b(ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}"), MASK),
    (("xox", "xapp-"), re.compile(r"\b(?:xox[abeoprs]|xapp)-[A-Za-z0-9-]{10,}"), MASK),     # Slack's tokens, an app's too
    (("glpat-", "glptt-", "gldt-", "glrt-", "glcbt-"), re.compile(r"\bgl(?:pat|ptt|dt|rt|cbt)-[A-Za-z0-9_-]{20,}"), MASK),  # GitLab
    (("hf_",), re.compile(r"\bhf_[A-Za-z0-9]{30,}"), MASK),                         # Hugging Face
    (("npm_",), re.compile(r"\bnpm_[A-Za-z0-9]{30,}"), MASK),                       # npm
    (("pypi-",), re.compile(r"\bpypi-AgE[A-Za-z0-9_-]{50,}"), MASK),                # PyPI
    (("sg.",), re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}"), MASK),  # SendGrid
    (("k_live_", "k_test_"), re.compile(r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}"), MASK),        # Stripe's secret and restricted keys
    (("whsec_",), re.compile(r"\bwhsec_[A-Za-z0-9+/=]{20,}"), MASK),                # ... and its webhooks' signing secret
    (("aiza",), re.compile(r"\bAIza[0-9A-Za-z_-]{35}"), MASK),                      # Google's API keys,
    (("ya29.",), re.compile(r"\bya29\.[A-Za-z0-9._-]{20,}"), MASK),                 # its OAuth access tokens,
    (("1//0",), re.compile(r"\b1//0[A-Za-z0-9_-]{30,}"), MASK),                     # refresh tokens
    (("gocspx-",), re.compile(r"\bGOCSPX-[A-Za-z0-9_-]{20,}"), MASK),               # and client secrets
    (("8q~",), re.compile(r"(?<![\w~.-])[A-Za-z0-9_~.-]{3}8Q~[A-Za-z0-9_~.-]{31,}"), MASK),      # Entra ID's client secrets
    (("hvs.", "hvb.", "hvr."), re.compile(r"\bhv[sbr]\.[A-Za-z0-9_-]{20,}"), MASK),  # Vault
    (("_v1_",), re.compile(r"\bdo[opr]_v1_[A-Za-z0-9]{32,}"), MASK),                # DigitalOcean
    (("dckr_pat_",), re.compile(r"\bdckr_pat_[A-Za-z0-9_-]{20,}"), MASK),           # Docker Hub
    (("tskey-",), re.compile(r"\btskey-[a-z]++-[A-Za-z0-9-]{16,}"), MASK),          # Tailscale
    (("shpat_", "shpca_", "shppa_", "shpss_"), re.compile(r"\bshp(?:at|ca|pa|ss)_[A-Fa-f0-9]{32}"), MASK),          # Shopify
    (("atatt3",), re.compile(r"\bATATT3[A-Za-z0-9_=-]{20,}"), MASK),                # Atlassian
    (("pmak-",), re.compile(r"\bPMAK-[A-Za-z0-9-]{20,}"), MASK),                    # Postman
    (("sq0",), re.compile(r"\bsq0(?:atp|csp)-[A-Za-z0-9_-]{20,}"), MASK),           # Square
    (("sk",), re.compile(r"S(?<!\wS)K[0-9a-f]{32}\b"), MASK),                             # Twilio's API key secrets
    (("eyj",), re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), MASK),  # JWT
    # a BitLocker recovery key, with its label or without: eight groups of six digits
    (("-",), re.compile(r"\d(?<![\d-]\d)\d{5}(?:-\d{6}){7}(?![\d-])"), MASK),
    # webhooks, whose address is their key: Slack's, Discord's, Teams'
    (("hooks.slack.com",), re.compile(r"(\bhooks\.slack\.com/(?:services|workflows|triggers)/)[A-Za-z0-9/_-]++"), r"\1" + MASK),
    (("/api/webhooks/",), re.compile(r"(\bdiscord(?:app)?\.com/api/webhooks/\d++/)[A-Za-z0-9_-]++"), r"\1" + MASK),
    (("/webhook",), re.compile(r"((?:\boutlook\.office(?:365)?\.com/webhook|\.webhook\.office\.com/webhookb2)/)"
                               r"(?!\[REDACTED)[^\s\"'<>]++", _I), r"\1" + MASK),

    # --- password hashes
    # crypt(3)'s as in /etc/shadow and .htpasswd (MD5, bcrypt, SHA, yescrypt, scrypt, Apache's apr1, Argon2,
    # PBKDF2), Cisco's types 8 and 9, Junos's $9$, WordPress's and Drupal's
    (("$",), re.compile(r"\$(?:(?:1|2[abxy]?|5|6|7|8|9|y|gy|sha1|md5|apr1|argon2(?:id|i|d)|pbkdf2(?:-sha\d++)?|scrypt|bcrypt-sha256)"
                        r"\$[A-Za-z0-9./$=,+-]{8,}|[PH]\$[A-Za-z0-9./]{31}|S\$[A-Za-z0-9./]{52})"), HASH_MASK),
    # LDAP's and Dovecot's: {SSHA}..., {SHA}..., {CRYPT}...
    (("{ssha", "{sha", "{md5", "{smd5", "{crypt", "{pbkdf2", "{argon2", "{bcrypt", "{cleartext", "{plain}", "{nt}", "{lanman}"),
     re.compile(r"\{(?:S?SHA(?:-?\d{1,3})?|S?MD5|CRYPT|PBKDF2[\w-]*+|ARGON2|BCRYPT|CLEARTEXT|PLAIN|NT|LANMAN)\}"
                r"[A-Za-z0-9+/=.$,:-]{4,}", _I), HASH_MASK),
    (("*",), re.compile(r"(?<![\w*])\*[0-9A-Fa-f]{40}(?![0-9A-Za-z])"), HASH_MASK),         # MySQL's mysql.user
    (("md5",), re.compile(r"\bmd5[0-9a-f]{32}\b"), HASH_MASK),                              # PostgreSQL's pg_authid
    (("scram-sha-",), re.compile(r"\bSCRAM-SHA-(?:1|256|512)\$\d++:[A-Za-z0-9+/=]++\$[A-Za-z0-9+/=]++:[A-Za-z0-9+/=]++"), HASH_MASK),
    # Windows: a dumped account's line (user:rid:lm:nt:::), an NTLM hash by its label, Kerberos keys
    ((":::",), re.compile(r"^([ \t]*+[^:\n]{1,120}:\d{1,10}:)[0-9A-Fa-f]{32}:[0-9A-Fa-f]{32}(?=:)", _M),
     r"\1" + HASH_MASK + ":" + HASH_MASK),
    (("ntlm", "hash"), re.compile(r"(\b(?:NTLM|(?:NT|LM)[ _-]?hash)[ \t]*+:[ \t]*+)[0-9A-Fa-f]{32}\b", _I), r"\1" + HASH_MASK),
    (("-cts", "_cts", "-cbc-", "rc4-hmac", "rc4_hmac", "arcfour-hmac", "aes256_hmac", "aes128_hmac"),
     re.compile(r"(\b(?:aes(?:128|256)[-_]cts(?:[-_]hmac[-_]sha\d++(?:[-_]\d++)?)?|aes(?:128|256)_hmac|des3?-cbc-(?:md5|crc|sha1)"
                r"|rc4[-_]hmac(?:[-_](?:nt|md5|old|exp))*+|arcfour-hmac(?:-md5)?|camellia(?:128|256)-cts-cmac)"
                r"\)?[ \t]*+[:=]?[ \t]*+\(?(?:0x)?)[0-9A-Fa-f]{16,}\b", _I), r"\1" + MASK),

    # --- labels of more than one word
    # Wi-Fi keys, as `netsh wlan show profile name=... key=clear` prints them, in Windows' other languages
    # too, and French's "Mot de passe" (Passwort, Kennwort and Schlüsselinhalt are names: key=value's)
    (("key content", "contenu de la cl", "contenido de la clave", "contenuto chiave", "conteúdo da chave", "mot de passe"),
     re.compile(r"((?<!\w)(?:Key Content|Contenu de la clé|Contenido de la clave|Contenuto chiave|Conteúdo da chave|Mot de passe)"
                r"[ \t]*+[:=][ \t]*+)(?!\[REDACTED)(\S[^\r\n]*+)", _I), _label),
    # "API key: ...", and `wg show`'s "private key:" and "preshared key:" (not ssh's "Trying private
    # key: /home/..."; a public key stays)
    (("key",), re.compile(r"([ \t](?i:key)[ \t]*+[:=][ \t]*+)(?!\[REDACTED)(\S[^\r\n]*+)"),
     lambda m: _label(m) if _KEY_OF_WHAT.search(m.string, max(0, m.start() - 16), m.start()) else m[0]),

    # --- passwords on a command line, as a transcript or a history shows them
    # mysql -pSECRET (-p alone asks), sshpass -p SECRET
    (("mysql", "mariadb"),
     re.compile(r"(\b(?:mysql|mysqldump|mysqladmin|mariadb|mariadb-dump)\b(?:(?!\b(?:mysql|mariadb)\b)[^\n])*?\s-p)(?!\[REDACTED)(?=\S)\S++"),
     r"\1" + MASK),
    (("sshpass",), re.compile(r"(\bsshpass\s++(?:-\S++\s++)*?-p[ \t]*+)(?!\[REDACTED)\S++"), r"\1" + MASK, WHOLE),
    # curl -u user:password (and its proxy's), the password after the first colon
    (("curl", "wget"),
     re.compile(r"(\b(?:curl|wget)\b(?:(?!\b(?:curl|wget)\b)[^\n])*?\s(?:-u|--user|-U|--proxy-user)[ \t]*+=?[ \t]*+)(['\"])?([^\s:'\"]++:)(?!\[REDACTED)"
                r"(?(2)[^'\"\n]*+|[^\s'\"]++)"), r"\1\2\3" + MASK),
    (("sqlcmd", "osql", "bcp"), None, _on_lines(r"(?i:sqlcmd|osql|bcp)(?:\.exe)?", _option("-P", r"[ \t]*+"))),
    (("psexec", "paexec", "psservice", "pslist", "pskill", "psinfo", "psloggedon", "psshutdown", "pspasswd", "psfile"),
     None, _on_lines(r"(?i:psexec|paexec|ps(?:service|list|kill|info|loggedon|shutdown|passwd|file))(?:64)?(?:\.exe)?",
                     _option("(?i:-p)"))),
    (("schtasks",), None, _on_lines(r"(?i:schtasks)(?:\.exe)?", _option(r"(?i:/r?p)"))),
    (("freerdp",), None, _on_lines(r"(?i:(?:x|wl|sdl-)?freerdp\d?)(?:\.exe)?", _option(r"/(?i:g?p):", ""))),
    (("rdesktop",), None, _on_lines("rdesktop", _option("-p"))),
    (("winrs",), None, _on_lines(r"(?i:winrs)(?:\.exe)?", _option(r"[-/](?i:p(?:assword)?):", ""))),
    (("plink", "pscp", "psftp", "putty", "kitty"), None, _on_lines(r"(?i:plink|pscp|psftp|putty|kitty)(?:\.exe)?", _option("-pw"))),
    # samba's -U user%password
    (("smbclient", "rpcclient", "smbget", "smbcacls", "smbtree", "winexe", "net"), None,
     _on_lines("smbclient|rpcclient|smbget|smbcacls|smbtree|winexe|net",
               r"((?<=\s)(?:-U[ \t]*+|--user(?:name)?[= \t][ \t]*+)[\"']?[^\s%'\"]++%)(?!\[REDACTED)[^\s'\"]++")),
    (("ldap",), None, _on_lines("ldap(?:search|modify|add|delete|whoami|compare|modrdn|exop)", _option("-w", r"[ \t]*+"))),
    (("ldappasswd",), None, _on_lines("ldappasswd", _option("-[was]", r"[ \t]*+"))),
    (("docker", "podman", "nerdctl", "buildah", "skopeo", "helm", "oras", "crane", "oc ", "cf ", "az ", "ibmcloud", "doctl"),
     None, _on_lines(r"(?:docker|podman|nerdctl|buildah|skopeo|helm|oras|crane|oc|cf|az|ibmcloud|doctl)"
                                  r"(?:[ \t]++[\w-]++){0,2}?[ \t]++login", _option("-p"))),
    (("7z", "rar"), None, _on_lines(r"(?i:7z[arz]?|7zG|rar|unrar)(?:\.exe)?", rf"((?<=\s)-h?p){_NEW}(?=\S){_ARG}")),     # -pSECRET
    (("zip",), None, _on_lines("zip|unzip|zipcloak", _option("-P"))),
    (("ipmitool",), None, _on_lines("ipmitool", _option("-P", r"[ \t]*+"))),
    (("ipmi", "bmc-"), None, _on_lines(r"ipmi-\w++|ipmipower|ipmiconsole|ipmimonitoring|bmc-\w++", _option("-p"))),
    (("racadm",), None, _on_lines(r"(?i:racadm|idracadm\d?)(?:\.exe)?", _option("-p"))),
    # an SNMP community, and SNMPv3's two passphrases
    (("snmp",), None, _on_lines("snmp(?:walk|get|getnext|bulkwalk|bulkget|set|table|trap|inform|status|df|delta|netstat|test)",
                                _option("-[cAX]", r"[ \t]*+"))),
    (("mongo",), None, _on_lines("mongo(?:sh|dump|restore|export|import|stat|top|files)?", _option("-p", r"[ \t]*+"))),
    (("redis-cli",), None, _on_lines("redis-cli", _option("-a"))),
    (("mosquitto_",), None, _on_lines("mosquitto_(?:pub|sub|rr)", _option("-P"))),
    (("useradd", "usermod"), None, _on_lines("useradd|usermod", _option("-p"))),
    (("openssl",), None, _on_lines("openssl", _option("-k"))),
    (("lftp",), None, _on_lines("lftp", rf"((?<=\s)-u[ \t]++[^\s,]++,){_NEW}\S++")),
    (("nmcli",), None, _on_lines("nmcli", _option(r"(?:[\w-]++\.)?(?:password|psk|wep-key\d?|leap-password|private-key-password)"))),
    (("wpa_passphrase",), re.compile(rf"(\bwpa_passphrase[ \t]++{_ARG}[ \t]++){_VALUE}"), r"\1" + MASK),
    (("aws",), re.compile(rf"(\baws[ \t]++configure[ \t]++set[ \t]++)({_NAME})([ \t]++){_NEW}({_ARG})"), _named(2, 4)),
    # net use \\server\share PASSWORD /user:..., net user NAME PASSWORD (a * asks, a / is an option)
    (("net",), re.compile(r"(\bnet1?(?:\.exe)?[ \t]++use(?:[ \t]++(?:[A-Za-z]:|\*))?[ \t]++(?:\"\\\\[^\"\n]++\"|\\\\\S++)[ \t]++)"
                          rf"(?![/*]){_VALUE}", _I), r"\1" + MASK),
    (("net",), re.compile(r"(\bnet1?(?:\.exe)?[ \t]++user[ \t]++(?![/*])(?:\"[^\"\n]++\"|\S++)[ \t]++)"
                          rf"(?![/*]){_VALUE}(?=[ \t]*+(?:$|[/&|;)\r]))", _I | _M), r"\1" + MASK),
    # htpasswd -b FILE USER PASSWORD: the last word
    (("htpasswd",), re.compile(r"(\bhtpasswd[ \t]++-[A-Za-z0-9]*b[A-Za-z0-9]*+(?:[ \t]++-\S++)*+(?:[ \t]++\S++){1,2}?[ \t]++)"
                               rf"{_VALUE}(?=[ \t]*+(?:$|[&|;)\r]))", _M), r"\1" + MASK),
    # Oracle's user/password@database
    (("sqlplus", "sqlldr", "expdp", "impdp", "rman"),
     None, _on_lines(r"(?i:sqlplus|sqlldr|expdp|impdp|rman)(?:64)?(?:\.exe)?", rf"((?<=\s)[\w$#.]++/){_NEW}[^\s@/]++(?=@|\s|$)")),
    (("jdbc:oracle",), re.compile(r"(\bjdbc:oracle:\w++:[\w$#.]++/)(?!\[REDACTED)[^\s@/]++(?=@)", _I), r"\1" + MASK),
    # a password piped to what reads one: echo SECRET | sudo -S ..., echo 'user:SECRET' | chpasswd
    (("echo", "printf"),
     re.compile(r"(\b(?:echo|printf)[ \t]++(?:-[neE]++[ \t]++)*+)(?!\[REDACTED)((?:(?!\becho\b|\bprintf\b)[^|\n])++)"
                r"(\|[ \t]*+(?:sudo[ \t]++(?:-\S++[ \t]++)*?-[A-Za-z]*S|(?:sudo[ \t]++)?(?:cryptsetup|chpasswd|kinit|smbpasswd"
                r"|passwd[ \t]++--stdin|su)\b|[^|\n]*?--password-stdin))"), _piped),
    # .netrc on one line: machine HOST login NAME password SECRET
    (("password",), re.compile(r"^([ \t]*+(?:machine[ \t]++\S++|default)(?:[ \t]++(?:login|account|port)[ \t]++\S++)*+[ \t]++password[ \t]++)"
                               r"(?!\[REDACTED)\S++", _M), r"\1" + MASK),
    # ipsec.secrets: `1.2.3.4 5.6.7.8 : PSK "..."`
    (("psk", "xauth", "eap"), re.compile(rf"(:[ \t]*+(?:PSK|XAUTH|EAP)[ \t]++){_NEW}{_ARG}"), r"\1" + MASK),
    # reg query's lines: NAME    REG_SZ    VALUE (Winlogon's DefaultPassword)
    (("reg_",), re.compile(rf"^([ \t]*+)({_NAME})([ \t]++REG_(?:SZ|EXPAND_SZ|MULTI_SZ)[ \t]++){_NEW}(\S[^\r\n]*+)", _I | _M),
     _named(2, 4)),

    # --- network devices
    # FortiGate: set password ENC ..., set psksecret ..., set passwd ...; ENC marks a secret under any name
    (("set",), re.compile(rf"^([ \t]*+set[ \t]++)({_NAME})([ \t]++){_NEW}({_ARG})(?=[ \t\r]*+$)", _I | _M), _named(2, 4)),
    (("set",), re.compile(rf"^([ \t]*+set[ \t]++[\w-]++[ \t]++ENC[ \t]++){_NEW}{_ARG}", _M), r"\1" + MASK),
    # Cisco and its like
    # (line-anchored or type-digit forms only, so log lines like "Failed password for root" survive;
    # not kubectl's `get secret NAME`, which names one). Never an = or : for the value: `secret = X`
    # and `Password : X` are key=value forms, below, which blank X and not the separator
    (("enable", "username", "key-string", "pre-shared-key", "wpa-psk", "isakmp"),
     re.compile(r"(?<![\w.-])((?:enable[ \t]++(?:secret|password)|username[ \t]++\S++[ \t]++(?:privilege[ \t]++\d++[ \t]++)?secret"
                rf"|key-string|pre-shared-key|wpa-psk|isakmp[ \t]++key)[ \t]++{_QUALIFIERS})(?![=:-]){_NEW}{_ARG}", _I), r"\1" + MASK),
    # `secret ...` alone: with its type digit, with its value in quotes (Junos), or as a line of its own;
    # not kubectl's `get secret NAME`, which names one, nor a sentence's "the secret service"
    (("secret",), re.compile(rf"([sS](?<![\w.-][sS])(?i:ecret)[ \t]++)(?:(\d{{1,2}}[ \t]++(?=\S)){_NEW}{_ARG}|{_NEW}\"[^\"\n]*+\")"),
     lambda m: m[1] + (m[2] or "") + MASK),
    (("secret",), re.compile(rf"^([ \t]*+secret[ \t]++{_QUALIFIERS})(?![=:-]){_NEW}{_ARG}(?=[ \t\r;]*+(?:$|#))", _I | _M), r"\1" + MASK),
    (("password",), re.compile(rf"\b(password[ \t]++\d{{1,2}}[ \t]++){_NEW}{_ARG}", _I), r"\1" + MASK),
    # a line's own password; not the labels of `net user` output ("Password last set", "Password expires"),
    # nor PAM's `password requisite pam_pwquality.so`
    (("password",),
     re.compile(r"^([ \t]*+(?:username[ \t]++\S++[^\n]*?[ \t])?password[ \t]++"
                rf"(?:(?:{_QUALIFIER}|manager|operator|user-name[ \t]++\S++)[ \t]++(?=\S)){{0,4}}+)(?![=:]){_NEW}"
                r"(?!(?:last|expires|changeable|required|inactive|age|never|history|length|policy|must|may|for|is|was|has|reset|change)\b)"
                rf"{_PAM}{_ARG}", _I | _M), r"\1" + MASK),
    (("snmp-server",), re.compile(r"\bsnmp-server\s++community\s++\S++", _I), "snmp-server community " + MASK, WHOLE),
    (("snmp-server",), None, _on_lines(r"snmp-server[ \t]++user", r"((?<=\s)(?:auth[ \t]++(?:md5|sha[-\w]*+)"
                                       rf"|priv(?:[ \t]++(?:des|3des|aes(?:[ \t]++\d{{3}})?))?)[ \t]++){_VALUE}", _I)),
    # key 7 ..., a server's own `key ...` line, tacacs-server and radius-server keys
    (("key",), re.compile(rf"(k(?<!\wk)ey[ \t]++\d[ \t]++){_NEW}(?=\S{{4}}){_ARG}"), r"\1" + MASK),
    (("key",), re.compile(rf"^( ++key ){_NEW}(?!\d )(\S++)[ \t\r]*+$", _M), r"\1" + MASK),
    (("-server",), re.compile(rf"(\b(?:tacacs|radius)-server\b[^\n]*?[ \t]key[ \t]++(?:\d[ \t]++(?=\S))?+){_NEW}{_ARG}", _I), r"\1" + MASK),
    # routing and management protocols' shared secrets
    (("neighbor",), re.compile(rf"(\bneighbor[ \t]++\S++[ \t]++password[ \t]++(?:\d[ \t]++(?=\S))?+){_NEW}{_ARG}", _I), r"\1" + MASK),
    (("message-digest-key", "authentication-key"),
     re.compile(r"(\b(?:message-digest-key[ \t]++\d++[ \t]++md5|authentication-key(?:[ \t]++\d++[ \t]++md5)?)[ \t]++"
                rf"(?:\d[ \t]++(?=\S))?+)(?![=:]){_NEW}{_ARG}", _I), r"\1" + MASK),
    (("vtp",), re.compile(rf"^([ \t]*+vtp[ \t]++password[ \t]++){_NEW}{_ARG}(?=[ \t]*+(?:hidden|secret)?[ \t\r]*+$)", _I | _M), r"\1" + MASK),
    (("sent-username",), re.compile(rf"(\bsent-username[ \t]++\S++[ \t]++password[ \t]++(?:\d[ \t]++(?=\S))?+){_NEW}{_ARG}", _I), r"\1" + MASK),
    (("standby",), re.compile(rf"(\bstandby[ \t]++\d++[ \t]++authentication[ \t]++(?:text[ \t]++)?)(?!md5\b){_NEW}{_ARG}", _I), r"\1" + MASK),

    # --- PowerShell
    (("-",), re.compile(r"(-(Password|Secret|Token|ApiKey|Key|Credential)\s++)(['\"]).*?\3", _I), r"\1" + MASK, WHOLE),
    (("convertto-securestring",),
     re.compile(r"(\bConvertTo-SecureString)((?:[ \t]++(?:\"(?:[^\"`\n]|`.|\"\")*+\"|'(?:[^'\n]|'')*+'|[^\s|;)'\"]++))*+)", _I), _secure_string),
    # --password X, -Password X: an option named for a secret, and its argument
    (("-",), re.compile(rf"(-(?<![\w-]-)-?(?=[\w-]*?(?:{_HINT}))[A-Za-z][\w-]*+)([ \t]++){_NEW}"
                        r"(\"[^\"\n]*+\"|'[^'\n]*+'|[^\s'\"|;&<>()=:-][^\s|;&)]*+)", _I), _flag),

    # --- XML
    # web.config / app.config: <add key="DbPassword" value="..."/>
    (("key",), re.compile(rf"([kK](?<!\w[kK])(?i:ey[ \t]*+=[ \t]*+\"(?=[^\"]*?(?:{_STRONG.pattern}|connection[_-]?string))[^\"]*+\"[ \t]++value[ \t]*+=[ \t]*+\"))"
                          r"(?!\[REDACTED)[^\"]*+\""), r"\1" + MASK + '"', WHOLE),
    # an element named for a secret: pfSense's and OPNsense's config.xml (<password>, <bindpw>,
    # <pre-shared-key>, <radius_secret>), a Wi-Fi profile's <keyMaterial>; unattend.xml's
    # <AdministratorPassword><Value>; a property list's <key>Password</key><string>
    (("</",), re.compile(rf"<({_NAME}|prv|(?:bcrypt|md5|sha\d*+|nt|lm)[-_]hash)((?:\s[^<>]*+)?)>"
                         r"((?:[^<]++|<!\[CDATA\[(?:(?!\]\]>).)*+\]\]>)++)</\1\s*+>", _I | re.S),
     _element, WHOLE),
    (("<value>",), re.compile(rf"(<({_NAME})(?:\s[^<>]*+)?>\s*+<Value>)([^<]++)(?=</Value>)", _I), _named(2, 3), WHOLE),
    (("<string>",), re.compile(rf"(<key>({_NAME})</key>\s*+<string>)([^<]++)(?=</string>)", _I), _named(2, 3), WHOLE),
    # an OpenVPN profile's inline key, when it is no PEM block (a static key's hex)
    (("<key>", "<tls-auth>", "<tls-crypt>", "<tls-crypt-v2>", "<pkcs12>"),
     re.compile(r"(<(key|tls-auth|tls-crypt|tls-crypt-v2|pkcs12)>[ \t]*+\r?\n)(?!\s*+\[REDACTED)[^<]++(?=</\2>)"), r"\1" + KEY_MASK + "\n", WHOLE),

    # --- key=value / key: value, and YAML's values under their key
    (("pass", "pw", "secret", "token", "key", "cred", "psk", "_auth", "sig", "kennwort", "schl", "contrase", "senha",
      "wachtwoord"), None, _pairs, WHOLE),
    # a secret told by the name beside it: Kubernetes' `- name: DB_PASSWORD` / `value: ...`, and JSON's
    # {"name": "DB_PASSWORD", "value": "..."}
    (("value",), re.compile(rf"([nN](?<![\w.-][nN])(?i:ame[\"']?[ \t]*+:[ \t]*+[\"']?({_NAME})[\"']?[ \t]*+,?\s*+[\"']?value[\"']?[ \t]*+:[ \t]*+))"
                            rf"{_NEW}(\"(?:[^\"\\\n]|\\.)*+\"|'[^'\n]*+'|[^\s,}}][^\n,}}]*+)"), _named(2, 3), WHOLE),
    (("auth",), re.compile(r"([\"']auth[\"'][ \t]*+:[ \t]*+)(?!\[REDACTED)(\"[^\"]*+\"|'[^']*+')", _I), r"\1" + MASK, WHOLE),     # docker's config.json

    # --- credentials in URLs: scheme://user:pass@host, with no user too (redis://:pass@host), and a
    # token in the user's place
    (("://",), re.compile(r"((?<![a-z0-9+.-])[a-z][a-z0-9+.-]*+://[^\s:/@]*+:)(?!\[REDACTED)[^\s@/]++@", _I), r"\1" + MASK + "@"),
    (("://",), re.compile(r"((?<![a-z0-9+.-])[a-z][a-z0-9+.-]*+://)([^\s:/@]{12,})@(?=[\w.-])", _I), _token_user),
]


def _applies(pat: re.Pattern | None, repl):
    """A rule as a function of a text, which returns it with the number of its redactions."""
    if pat is None:
        return repl
    if not callable(repl):
        return lambda text: pat.subn(repl, text)

    def apply(text: str) -> tuple[str, int]:
        done = 0

        def counted(m: re.Match) -> str:
            nonlocal done
            out = repl(m)
            done += out != m.group(0)
            return out
        return pat.sub(counted, text), done
    return apply


_APPLY = [(rule[0], _applies(rule[1], rule[2]), WHOLE in rule[3:]) for rule in RULES]
_FEW = 64                           # lines: more of them holding a rule's words, and the rule reads the whole text


def _lines_with(low: str, words: tuple[str, ...]) -> list[tuple[int, int]] | None:
    """The lines of `low` that hold one of `words`, as (start, end) in order; None when they are many."""
    spans = set()
    for word in words:
        at = low.find(word)
        while at >= 0:
            end = low.find("\n", at)
            end = len(low) if end < 0 else end
            spans.add((low.rfind("\n", 0, at) + 1, end))
            if len(spans) > _FEW:
                return None
            at = low.find(word, end)
    return sorted(spans)


def redact(text: str) -> tuple[str, int]:
    """Return (redacted_text, number_of_redactions)."""
    total = 0
    low = text.lower()
    for words, apply, whole in _APPLY:
        if not any(word in low for word in words):
            continue
        # a few lines hold the rule's words: only they are read. (Not when lower-casing changed the
        # text's length, as it does for a few letters: a place in one is then no place in the other.)
        lines = None if whole or len(low) != len(text) else _lines_with(low, words)
        if lines is None:
            text, done = apply(text)
        else:
            out, last, done = [], 0, 0
            for start, end in lines:
                line, n = apply(text[start:end])
                if n:
                    out += [text[last:start], line]
                    last, done = end, done + n
            if done:
                out.append(text[last:])
                text = "".join(out)
        if done:
            total += done
            low = text.lower()
    return text, total
