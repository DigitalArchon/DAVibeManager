"""Local rules for commands that may expose sensitive data.

Separate from the risk level: `cat ~/.ssh/id_ed25519` changes nothing but prints a private key
into the terminal, the case record and (if sent) the AI's context. Two kinds are flagged:
commands that read or dump secrets, and commands that carry a secret in their own text, where
it lands in shell history, the process list and the case log. Output redaction
(safety/redact.py) is a best-effort net behind this; the flag warns before the command runs.
"""

from __future__ import annotations

import re

from .risk import bounded

_I = re.IGNORECASE

# Files whose contents are secret. Checked per command segment, so `ls /etc/ssl/private` or
# `stat .env` (names and metadata only) are not flagged but `cat` of the same path is.
SECRET_FILES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"/etc/g?shadow-?(?![\w.])"), "reads password hashes"),
    (re.compile(r"(?:^|[\s/\\'\"])(?:id_(?:rsa|dsa|ecdsa|ed25519)(?:_sk)?|ssh_host_\w+_key)(?![\w.])"), "reads a private SSH key"),
    (re.compile(r"(?:/ssl/private(?![\w.-])|/letsencrypt/(?:live|archive)(?:/?(?=[\s'\"]|$)|/\S*privkey)|\bpriv(?:ate)?[\w.-]*\.pem\b|\.key(?![\w.])|\.(?:p12|pfx|jks|keystore|kdbx|ppk)(?![\w.]))", _I),
     "reads a private key or key store"),
    (re.compile(r"(?:^|[\s/\\'\"=])\.env(?!\.(?:example|sample|dist|template)\b)(?:\.[\w-]+)?(?![\w/\\.-])"),
     "reads an environment file (often holds passwords)"),
    (re.compile(r"/proc/[\w$]+/environ\b"), "reads a process's environment (often holds secrets)"),
    # Windows paths too (\.aws\credentials); a NetworkManager connection is a file in its directory
    (re.compile(r"(?:\.netrc|\.pgpass|\.my\.cnf|\.git-credentials|\.aws[\\/]credentials|\.docker[\\/]config\.json|\.kube[\\/]config|"
                r"\.htpasswd|wp-config\.php|\bsecrets?\.(?:ya?ml|json|env|txt|toml)|\bcredentials?\.(?:json|xml|ya?ml|txt)|"
                r"/system-connections/\S*|wpa_supplicant[\w.-]*\.conf|\bunattend\.xml|\bsysprep\.inf|\bweb\.config|"
                r"\bdatabase\.yml|\bvault\.(?:ya?ml|json)|\.vault-token)(?![\w-])", _I),
     "reads a file that usually holds credentials"),
    (re.compile(r"(?:\.bash_history|\.zsh_history|\.mysql_history|\.psql_history|ConsoleHost_history\.txt)\b", _I),
     "reads shell history (often holds typed passwords)"),
    (re.compile(r"\bntds\.dit\b|\\config\\(?:SAM|SECURITY)\b", _I), "reads Windows credential stores"),
    # a VPN's keys and pre-shared secrets, and the secrets files of the services that log in for a machine
    (re.compile(r"/etc/wireguard/\S+|\.ovpn(?![\w.])|\bipsec\.secrets\b|\b(?:chap|pap)-secrets\b|\.psk(?![\w.])", _I),
     "reads a VPN configuration (holds private keys or pre-shared secrets)"),
    (re.compile(r"/etc/master\.passwd\b|/etc/security/opasswd\b|/smbpasswd(?![\w.-])|\.smbcredentials\b"
                r"|\bsasl_passwd\b|\.keytab(?![\w.])|\bsssd\.conf\b|\bldap\.secret\b|/etc/mysql/debian\.cnf\b|\brclone\.conf\b"
                r"|(?:^|[\s/\\'\"])\.(?:npmrc|pypirc)(?![\w.])|/etc/pve/priv/|\bupsd\.users\b|/freeradius/\S*clients\.conf\b"
                r"|\bsnmpd\.conf\b", _I), "reads a file that usually holds credentials"),
    (re.compile(r"\.tfstate(?!\w)|\.tfvars(?!\w)", _I), "reads Terraform state or variables (hold secrets in plain text)"),
    # a firewall's or router's whole configuration as a file: pfSense and OPNsense, VyOS and EdgeOS
    (re.compile(r"(?:/cf)?/conf/config\.xml\b|/usr/local/etc/config\.xml\b|/config/config\.boot\b"), "reads the device configuration (holds keys and passwords)"),
    (re.compile(r"\bunattend(?:ed)?\.xml\b|\bsysprep\.xml\b|\bGroups\.xml\b", _I),
     "reads a file that usually holds credentials"),
    # a person's own computer: their keys, browsers, passwords, mail and messages
    # a file in them or the folder whole (find ~/.ssh -exec cat, tar ~/.gnupg), not a public key,
    # which is made to be given out
    (re.compile(r"\.ssh(?:[\\/](?!\S*\.pub(?![\w.-]))|(?=[\s'\"]|$))"), "reads your SSH settings or keys"),
    (re.compile(r"\.gnupg(?:[\\/]|(?=[\s'\"]|$))"), "reads your encryption keys"),
    (re.compile(r"\.mozilla/|\.config/(?:google-chrome|chromium|BraveSoftware|vivaldi|opera|microsoft-edge)|"
                r"snap/(?:firefox|chromium)/|\.var/app/(?:org\.mozilla|com\.google\.Chrome|org\.chromium|com\.brave)", _I),
     "reads your browser data (history, saved passwords, cookies)"),
    (re.compile(r"\.local/share/keyrings|\.password-store|kwalletd|\.local/share/kwalletd"), "reads your saved passwords"),
    (re.compile(r"\.thunderbird/|\.local/share/evolution|\.config/evolution|\.var/app/org\.mozilla\.Thunderbird", _I),
     "reads your email"),
    (re.compile(r"\.config/(?:Signal|discord|Element|Slack|teams|WhatsApp)|\.var/app/(?:org\.signal|com\.discordapp|"
                r"im\.riot|org\.telegram)|TelegramDesktop", _I),
     "reads your messages"),
]

# Places whose very file names are private: flagged even for listings and searches.
PERSONAL_PLACES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"(?:~|\$HOME|\$\{HOME\}|/home/[\w.-]+)/(?:Documents|Desktop|Pictures|Photos|Videos|Music|Downloads|"
                r"Dokumente|Bilder|Schreibtisch)\b"), "looks at your personal files"),
    (re.compile(r"\b(?:find|tree|du|locate|grep\s+-\w*r\w*|ls\s+-\w*R\w*)\s+(?:~|\$HOME|\$\{HOME\}|/home(?:/[\w.-]+)?)/?(?=\s|$)"),
     "looks through your whole home folder"),
]

# First words that only look at names, sizes or metadata, never contents (or go to a folder).
_METADATA_ONLY = {"ls", "ll", "dir", "stat", "find", "file", "du", "getfacl", "lsattr", "namei", "realpath", "cd", "pushd",
                  "readlink", "test", "[", "wc", "md5sum", "sha1sum", "sha256sum", "sha512sum", "b2sum",
                  "chmod", "chown", "chgrp", "setfacl", "touch", "test-path", "get-acl", "get-item", "gi",
                  "get-childitem", "gci", "get-filehash", "icacls"}

# Whole-command rules: dumps of secrets or data, and secrets in the command text itself.
RULES: list[tuple[re.Pattern, str]] = [
    # dumping the environment or shell state
    (re.compile(r"(?:^|[;&|(]\s*|\bsudo\s+(?:-\S+\s+){0,8}|\bexec\b[^|;&\n]{0,400}?\s)(?:printenv|env)\s*(?:$|[|;&)>])", re.M), "prints environment variables (often hold secrets)"),
    (re.compile(r"(?:^|[;&|(]\s*)(?:set|export(?:\s+-p)?|declare(?:\s+-[px]+)?)\s*(?:$|[|;&)>])", re.M), "prints shell variables (often hold secrets)"),
    (re.compile(r"\b(?:Get-ChildItem|gci|dir|ls|Get-Item|gi)\s+env:(?!\w)", _I), "prints environment variables (often hold secrets)"),
    (re.compile(r"(?:^|[;&|(]\s*)history\b(?!\s+-[cdw])", re.M), "prints shell history (often holds typed passwords)"),
    (re.compile(r"\bGet-History\b|\bdoskey\s+/history\b", _I), "prints shell history (often holds typed passwords)"),
    # secret stores and credential dumping
    (re.compile(r"\bkubectl\s+(?:\S+\s+){0,12}?get\s+secrets?\b[^\n]{0,400}?(?:-o|--output)[\s=]*(?:ya?ml|json|jsonpath|go-template)", _I), "prints Kubernetes secrets"),
    (re.compile(r"\bkubectl\s+(?:\S+\s+){0,12}?get\s+secrets?\b[^|;&\n]{0,400}?--template\b", _I), "prints Kubernetes secrets"),
    (re.compile(r"\bkubectl\s+config\s+view\b[^\n]{0,400}?--raw\b"), "prints kubeconfig credentials"),
    (re.compile(r"\b(?:docker|podman)\s+(?:container\s+|image\s+)?inspect\b|\bdocker\s+compose\s+config\b|\bdocker-compose\s+config\b"),
     "shows container settings (environment variables often hold secrets)"),
    (re.compile(r"\b(?:docker|podman|kubectl)\s+exec\b[^|;&\n]{0,400}?\s(?:env|printenv)\b"), "prints environment variables (often hold secrets)"),
    # one variable, named like a secret, printed
    (re.compile(r"\b(?:echo|printf|Write-Output|Write-Host)\b[^|;&\n]{0,400}?\$\{?(?:env:)?\w*(?:PASSWORD|PASSWD|_PWD|SECRET|TOKEN|API_?KEY|ACCESS_KEY|PRIVATE_KEY)"
                r"|\bprintenv\s+\w*(?:PASSWORD|PASSWD|_PWD|SECRET|TOKEN|API_?KEY|ACCESS_KEY|PRIVATE_KEY)"
                r"|(?:^|[;|(][ \t]*)\$env:\w*(?:PASSWORD|PASSWD|_PWD|SECRET|TOKEN|API_?KEY|ACCESS_KEY|PRIVATE_KEY)\w*[ \t]*(?:$|[|;)])", _I | re.M),
     "prints a variable that holds a secret"),
    (re.compile(r"\b(?:vault\s+(?:kv\s+)?(?:read|get)|aws\s+secretsmanager\s+get-secret-value|aws\s+ssm\s+get-parameters?\b[^\n]{0,400}?--with-decryption|"
                r"az\s+keyvault\s+secret\s+show|gcloud\s+secrets\s+versions\s+access|pass\s+show|gpg\s+(?:-d|--decrypt)"
                r"|gopass\s+show|secret-tool\s+lookup|op\s+read|bw\s+get\s+(?:password|item|totp)|lpass\s+show|keyring\s+get"
                r"|security\s+find-(?:generic|internet)-password|Get-AzKeyVaultSecret|Get-Secret)\b", _I),
     "reads a secret from a secret store"),
    # the tools that hand out their own keys and tokens when asked
    (re.compile(r"\bterraform\s+(?:output|show|state\s+(?:pull|show))\b|\bpulumi\b[^|;&\n]{0,400}?--show-secrets\b|\bhelm\s+get\s+(?:values|all)\b", _I),
     "prints infrastructure state or values (hold secrets in plain text)"),
    (re.compile(r"\baws\s+configure\s+get\s+\S*secret|\baws\s+(?:sts\s+get-session-token|ecr\s+get-login-password|iam\s+create-access-key)\b"
                r"|\baz\s+(?:account\s+get-access-token|storage\s+account\s+keys\s+list|ad\s+sp\s+credential\s+reset)\b|\bGet-AzStorageAccountKey\b"
                r"|\bgcloud\s+auth\s+print-(?:access|identity)-token\b|\bgh\s+auth\s+(?:token|status\s+(?:\S+\s+){0,12}?(?:-t|--show-token))\b"
                r"|\bgpg2?\s+(?:\S+\s+){0,12}?--export-secret-(?:sub)?keys\b|\bredis-cli\b[^|;&\n]{0,400}?\bconfig\s+get\s+(?:requirepass|masterauth)\b", _I),
     "prints an access key or token"),
    (re.compile(r"\bwg\s+showconf\b|\bwg\s+show\s+\S+\s+(?:private-key|preshared-keys|dump)\b"
                r"|\bnmcli\s+(?:\S+\s+){0,12}?(?:-s|--show-secrets)\b|\bnmcli\s+dev(?:ice)?\s+wifi\s+show-password\b", _I),
     "prints network keys (Wi-Fi or VPN)"),
    (re.compile(r"\bgetent\s+g?shadow\b|\bpdbedit\s+(?:\S+\s+){0,12}?-\w*w|\bslapcat\b"), "reads password hashes"),
    (re.compile(r"\b(?:mimikatz|sekurlsa|lsadump|secretsdump|procdump\S*\s[^\n]{0,400}?\blsass|comsvcs\S*\s+MiniDump|ntdsutil|"
                r"Get-ADReplAccount|DSInternals|LaZagne|vaultcmd\s+/listcreds)\b", _I), "dumps Windows credentials"),
    (re.compile(r"\breg(?:\.exe)?\s+(?:save|export)\s+HKLM\\(?:SAM|SECURITY|SYSTEM)\b", _I), "exports a registry hive holding credentials"),
    (re.compile(r"\bnetsh\s+wlan\s+(?:show|export)\s+profiles?\b[^\n]{0,400}?\bkey\s*=\s*clear\b", _I), "prints Wi-Fi passwords"),
    (re.compile(r"\bGet-LapsADPassword\b|\bms-Mcs-AdmPwd\b|\bmsLAPS-Password\b|\bGet-AdmPwdPassword\b", _I), "reads a LAPS password"),
    (re.compile(r"\bmanage-bde(?:\.exe)?\s+(?:\S+\s+){0,12}?-protectors\s+(?:\S+\s+){0,12}?-get\b|\bGet-BitLockerVolume\b[^\n]{0,400}?\bKeyProtector\b"
                r"|\bmsFVE-RecoveryPassword\b|\bGet-BitLockerVolume\b[^;\n]*\|\s*(?:fl|Format-List)\s+\*", _I), "prints BitLocker recovery keys"),
    (re.compile(r"\bGet-GPPPassword\b|\bcpassword\b|\breg(?:\.exe)?\s+query\b[^|;&\n]{0,400}?(?:DefaultPassword\b|/f\s+pass)|\bSecureStringToBSTR\b", _I),
     "reveals a stored credential"),
    (re.compile(r"\bConvertFrom-SecureString\b[^\n]{0,400}?-AsPlainText\b|\.GetNetworkCredential\(\)\.Password\b", _I), "reveals a stored credential"),
    # whole databases and device configurations
    (re.compile(r"\b(?:mysqldump|mariadb-dump|pg_dump|pg_dumpall|mongodump|mongoexport|redis-cli\s+[^\n]{0,400}?--rdb)\b"), "dumps a database (customer data)"),
    # `sh run` and `sho run` as it is typed at the console, the files the same text is kept in, and what other makers call it
    (re.compile(r"^[ \t]*(?:do\s+)?sh(?:ow?)?\s+(?:run(?:ning)?(?:-config)?|start(?:up)?(?:-config)?|full-configuration|configuration|tech(?:-support)?)"
                r"(?!\s+interface)(?:\s|$)|^[ \t]*more\s+(?:system:running-config|nvram:startup-config)\b"
                r"|^[ \t]*dis(?:play)?\s+(?:current-configuration|saved-configuration)\b", _I | re.M),
     "prints the device configuration (holds keys and passwords, some weakly hashed)"),
    (re.compile(r"^[ \t]*(?:do\s+)?sh(?:ow?)?\s+(?:snmp\s+community|crypto\s+isakmp\s+key|crypto\s+key\b|aaa-server)\b", _I | re.M),
     "prints keys or community strings from the device configuration"),
    # RouterOS before 7 exports its secrets unless told to hide them; 7 hides them unless told to show them
    (re.compile(r"^[ \t]*/(?:[\w-]+[ \t/]+)*export\b(?![^\n]{0,400}?\bhide-sensitive\b)", _I | re.M),
     "prints the RouterOS configuration (with its secrets, unless hide-sensitive is given)"),
    (re.compile(r"^[ \t]*/(?:ppp[ \t/]+secret|ip[ \t/]+ipsec[ \t/]+(?:identity|peer)|interface[ \t/]+wireless[ \t/]+security-profiles)\b[^\n]{0,400}?\bprint\b",
                _I | re.M), "prints RouterOS secrets"),
    # a secret in the command text itself: kept in shell history, the process list and the case log
    (re.compile(r"\b(?:mysql|mysqldump|mysqladmin|mariadb|mariadb-dump)\b[^|;&\n]{0,400}?\s-p(?!\s)\S+"), "puts a password in the command line"),
    (re.compile(r"(?<![\w-])--(?:password|passwd|pass|pw|token|api-?key|apikey|secret|client-secret|secret-key|access-key|auth-token)"
                r"(?!-(?:stdin|file|env|prompt))(?:=|\s+)(?![-$])\S+", _I), "puts a secret in the command line"),
    # grepping config for credentials prints them; auth-log searches ("Failed password") don't
    (re.compile(r"\A(?!.*\b(?:failed|accepted|invalid)\s+pass).*?\b(?:grep|egrep|rg|ag|Select-String|sls|findstr)\b"
                r"(?:(?!\b(?:grep|egrep|rg|ag|Select-String|sls|findstr)\b)[^|;&\n])*?"
                r"(?:pass(?:word|wd)?|secret|token|api[_-]?key|credential|private.key)", _I | re.S),
     "searches files for credentials"),
    (re.compile(r"\b(?:curl|wget)\b[^|;&\n]{0,400}?\s(?:-u|--user)\s*['\"]?[^\s:'\"]+:[^\s'\"]+", _I), "puts a password in the command line"),
    (re.compile(r"\bwget\b[^|;&\n]{0,400}?--(?:http-)?password[= ]\S+", _I), "puts a password in the command line"),
    (re.compile(r"\b[a-z][a-z0-9+.-]{0,20}://[^\s:/@'\"]+:[^\s@/'\"]+@", _I), "puts a password in a URL"),
    (re.compile(r"\bsshpass\s+-p\s*\S+|\bhtpasswd\s+(?:-\w+\s+){0,8}-\w*b\b|\bpass(?:in|out)?\s+pass:\S+|\s-pass(?:in|out)\s+pass:\S+", _I),
     "puts a password in the command line"),
    (re.compile(r"(?:^|[\s;&|(])(?:export\s+)?[A-Z0-9_]*(?:PASSWORD|PASSWD|_PWD|SECRET|TOKEN|API_?KEY|ACCESS_KEY)[A-Z0-9_]*=(?![\s$;&|]|\"\$|'')\S+", re.M),
     "puts a secret in the command line"),
    (re.compile(r"\becho\b[^|\n]{0,400}?\|\s*(?:sudo\s+)?(?:chpasswd|passwd\s+--stdin)\b"), "puts a password in the command line"),
    (re.compile(r"-(?:Password|Secret|Token|ApiKey)\s+['\"][^'\"]+['\"]|\bConvertTo-SecureString\b[^|;\n]{0,400}?['\"][^'\"]+['\"]", _I),
     "puts a password in the command line"),
    (re.compile(r"\bnet\s+use\b[^|;&\n]{0,400}?/user:\S+\s+(?![*/])\S+", _I), "puts a password in the command line"),
    (re.compile(r"\bnet\s+user\s+\S+\s+(?![*/])\S+", _I), "puts a password in the command line"),
]

_SEGMENTS = re.compile(r"\|\||&&|[;|&\n]")
_PREFIX = re.compile(r"^\s*(?:(?:sudo|doas)\s+(?:-\S+\s+)*|(?:nice|nohup|time|command|exec|xargs)\s+(?:-\S+\s+)*|[A-Za-z_]\w*=\S*\s+)*")


def _reads_through_find(segment: str) -> bool:
    """`find ... -exec cat {}` prints what it finds: find looks at names, its -exec may not."""
    m = re.search(r"\bfind\b(?:(?!\bfind\b).)*?\s-(?:exec|execdir|ok|okdir)\s+(\S+)", segment)
    return bool(m) and m.group(1).rsplit("/", 1)[-1].lower() not in _METADATA_ONLY


def _first_word(segment: str) -> str:
    rest = segment[_PREFIX.match(segment).end():]
    word = rest.split(None, 1)[0] if rest.strip() else ""
    return word.rsplit("/", 1)[-1].strip("(")


def sensitive(command: str) -> list[str]:
    """Reasons this command may expose secrets or private data, de-duplicated; [] if none."""
    out: list[str] = []
    command = bounded(command)[0]            # a bounded copy, as the risk rules read: a command can be megabytes long
    for seg in _SEGMENTS.split(command):
        if not seg.strip():
            continue
        if _first_word(seg).lower() in _METADATA_ONLY and not _reads_through_find(seg):
            continue
        for pat, why in SECRET_FILES:
            if why not in out and pat.search(seg):
                out.append(why)
    for pat, why in PERSONAL_PLACES + RULES:
        if why not in out and pat.search(command):
            out.append(why)
    return out
