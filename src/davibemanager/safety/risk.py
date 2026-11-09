"""Local risk classifier.

The model labels each proposed command with a risk level, but a model's self-assessment
is not trustworthy (it can be wrong, or steered by prompt injection in command output).
These rules can only *raise* the level the model gave, never lower it.
"""

from __future__ import annotations

import re

LEVELS = ("read_only", "modifying", "disruptive")

_I = re.IGNORECASE

# Position where a new command starts: a line's start; after a separator, `{`, `$(` or a backtick;
# after an opening quote (only ever seen where the command hands the quoted text to a shell,
# _REPARSES: elsewhere quoted text is blanked first); after `do`, `then` or `else`; after
# `ssh [options] host`, or find's -exec. Then any prefixes that run the next word as the
# command (sudo, pkexec or run0 and their options, env, a variable set for it, nohup, timeout 5,
# systemd-run, xargs...), and the command may be named by its path (/bin/rm) or escaped (\rm).
_SSH_HOST = r"\bssh\s+(?:-[46AaCfGgKkMNnqsTtVvXxYy]+\s+|-[BbcDEeFIiJLlmOoPpQRSWw]\s*\S+\s+)*[^\s-]\S*\s+"
# options, each perhaps with its argument (sudo -u root, nice -n 19, xargs -a list, timeout -s KILL,
# systemd-run -p MemoryMax=1G --scope), which is never a prefix's own word nor a variable set for
# the command (A=1 before the command, not before another option): a command has one reading, read
# in linear time (`xargs -0 xargs -0 ...` isn't tried every way)
_RUNS_NEXT = r"(?:sudo|doas|pkexec|run0|nohup|exec|time|nice|ionice|stdbuf|systemd-run|xargs|command|builtin|env|timeout)"
_OPTS = r"(?:-\S+(?:\s+(?!-)(?!" + _RUNS_NEXT + r"\s)(?![A-Za-z_]\w*=\S*\s++(?!-))\S+)?\s+)*"
_AS_ROOT = r"(?:sudo|doas|pkexec|run0)\s+" + _OPTS
_PREFIX = (r"(?:" + _AS_ROOT + r"|(?:nohup|exec|time|nice|ionice|stdbuf|systemd-run|xargs)\s+" + _OPTS
           + r"|command\s+(?:-p\s+)?|builtin\s+|env\s+" + _OPTS + r"(?:\w+=\S*\s+)*+|timeout\s+" + _OPTS + r"\S+\s+"
           r"|(?:[A-Za-z_]\w*=\S*\s+)++)")
CMD = (r"(?:^|[;&|(`{]\s*|[\"'](?=\S)|\$\(\s*|\b(?:do|then|else)\s+|" + _SSH_HOST + r"|\s-(?:exec|execdir|ok|okdir)\s+"
       r"|\b" + _AS_ROOT + r")" + _PREFIX + r"{0,16}(?:\\|(?:[^\s/]*+/)*+)")

# Each entry: (pattern, reason). Patterns are matched against the whole command text.
DISRUPTIVE: list[tuple[re.Pattern, str]] = [
    # the flags may end the line (`xargs rm -f`)
    (re.compile(r"\brm\s+(?:-\S+\s+)*(?:-[a-z]*[rf][a-z]*|--recursive|--force)\b", _I), "recursive/forced delete"),
    (re.compile(r"\b(mkfs(\.\w+)?|mke2fs|mkswap|wipefs|fdisk|sfdisk|parted|sgdisk|gdisk|blkdiscard|lvremove|vgremove|pvremove)\b"),
     "disk/partition tool"),
    (re.compile(r"\b(zpool|zfs)\s+destroy\b|\bmdadm\b.*--zero-superblock\b|\bcryptsetup\s+(\S+\s+)*(luksErase|erase|luksKillSlot)\b"
                r"|\bnvme\s+(format|sanitize)\b|\bhdparm\b.*--security-erase", _I), "erases a disk or volume"),
    # each dd on the line by itself: a later `of=/dev/null` excuses only its own dd
    (re.compile(r"\bdd\b[^;&|\n]*\bof=(?!/dev/null\b)", _I), "dd writing to a target"),
    # deleting by other means than rm -r: what's found, a list of files, what's not in the copy, a
    # repository's work, settings, a session, every process
    (re.compile(r"\bfind\b[^;&|\n]*\s-(?:delete\b|(?:exec|execdir|ok|okdir)\s+(?:\S*/)?(?:rm|shred|unlink)\b)"),
     "find deleting what it finds"),
    (re.compile(r"\bxargs\s+" + _OPTS + r"(?:\S*/)?(?:rm|shred|unlink)\b"), "deleting a list of files"),
    (re.compile(r"\brsync\b[^;&|\n]*\s--(?:delete|remove-source-files)"), "rsync deleting files"),
    (re.compile(r"\bgit\b[^;&|\n]*\s(?:reset\s+--hard|clean\s+-[a-z]*f)"), "a repository's changes discarded"),
    (re.compile(r"\bdconf\s+reset\s+-f\b"), "desktop settings reset"),
    (re.compile(r"\bflatpak\s+(?:uninstall|remove)\b[^;&|\n]*\s--all\b"), "every Flatpak removed"),
    (re.compile(CMD + r"unlink\s", re.M), "file destroyed"),
    (re.compile(r"\bloginctl\s+(?:terminate|kill)-(?:session|user)\b"), "session ended"),
    (re.compile(r"\bkill\s+-(?:KILL|9|TERM|15)?\s*-1\b"), "every process killed"),
    (re.compile(r">\s*/dev/(sd|nvme|vd|hd|mmcblk)"), "write to block device"),
    (re.compile(CMD + r"(shutdown|reboot|poweroff|halt)\b", re.M), "shutdown/reboot"),
    (re.compile(CMD + r"(telinit|init)\s+[06]\b", re.M), "runlevel change"),
    # the same asked of systemd over D-Bus (logind's Reboot, PowerOff...)
    (re.compile(r"\b(?:busctl|dbus-send|gdbus|qdbus)\b[^;&|\n]*[\s.](?:Reboot|PowerOff|Halt|KExec|SoftReboot)\w*\b"),
     "shutdown/reboot"),
    (re.compile(r"\bsystemctl\s+(\S+\s+)*(stop|restart|disable|mask|kill|isolate|reboot|poweroff|halt)\b"), "service stop/restart"),
    (re.compile(r"\bservice\s+\S+\s+(stop|restart)\b"), "service stop/restart"),
    (re.compile(r"\b(kill\s+-9|killall|pkill)\b"), "process kill"),
    (re.compile(r"\b(iptables|ip6tables)\s+(-[a-z]*\s+)*-(F|X|P)\b"), "firewall flush/policy"),
    (re.compile(r"\bnft\s+(flush|delete)\b"), "firewall flush"),
    (re.compile(r"\bufw\s+(disable|reset)\b"), "firewall disable"),
    (re.compile(r"\b(chmod|chown)\s+-R\b.*\s/(\s|$)"), "recursive permission change on /"),
    (re.compile(r"\b(userdel|deluser)\b"), "user deletion"),
    (re.compile(r"\bcrontab\s+-r\b"), "crontab removal"),
    (re.compile(r"\bdrop\s+(database|table|schema)\b", _I), "SQL drop"),
    (re.compile(r"\btruncate\s+table\b", _I), "SQL truncate"),
    (re.compile(r"\bip\s+link\s+set\s+\S+\s+down\b"), "interface down"),
    (re.compile(r"\bdocker\s+(system\s+prune|volume\s+(rm|prune)|rm\s+-f)\b"), "docker destructive"),
    (re.compile(r"\bkubectl\s+delete\b"), "kubernetes delete"),
    # code fetched from the network or decoded at runtime and executed: unreviewable
    (re.compile(r"\b(curl|wget|fetch|Invoke-WebRequest|iwr)\b[^|;]*\|\s*" + _PREFIX + r"{0,16}(\S*/)?(ba|z|k|da|)sh\b", _I),
     "pipe to shell"),
    (re.compile(r"\b(ba|z|k|da|)sh\s+(-c\s+)?[\"']?\s*\$\((curl|wget)\b", _I), "shell runs downloaded script"),
    (re.compile(r"\b(ba|z|k|da|)sh\s+<\s*\((curl|wget)\b", _I), "shell runs downloaded script"),
    (re.compile(r"\bbase64\s+(-d|--decode)\b[^|;]*\|\s*" + _PREFIX + r"{0,16}(\S*/)?(ba|z|k|da|)sh\b", _I),
     "decoded payload piped to shell"),
    (re.compile(r"\bshred\b"), "secure erase"),
    # a function piping itself to itself: `:(){ :|:& };:`, `bomb(){ bomb|bomb& }`. The name is
    # taken whole (possessive, from a word's start): backtracking into a long word (a tool
    # transfer's base64) at every position took minutes
    (re.compile(r"(?<!\w)(\w++|:)\s*\(\)\s*\{[^}]*?\1\s*\|\s*\1"), "fork bomb"),
    (re.compile(r"\bhistory\s+-c\b"), "history clear"),
    (re.compile(r"\b(nc|ncat|netcat)\b.*\s-e\s", _I), "reverse shell"),
    (re.compile(r"\bchmod\s+(-R\s+)?[0-7]*777\b"), "world-writable permissions"),
    # PowerShell / Windows
    (re.compile(r"\b(Invoke-Expression|iex)\b", _I), "Invoke-Expression"),
    (re.compile(r"(?<!\S)-(EncodedCommand|enc|ec)\s+\S+", _I), "encoded PowerShell"),
    # -e, -en, -enc... are -EncodedCommand too (not -ExecutionPolicy: -ex...)
    (re.compile(r"\b(powershell|pwsh)(\.exe)?\b.*\s-(e|ec|en\w*)\s+[A-Za-z0-9+/=]{8,}", _I), "encoded PowerShell"),
    (re.compile(r"\b(Invoke-WebRequest|iwr|curl|wget|Invoke-RestMethod|irm)\b.*\|\s*(iex|Invoke-Expression)\b", _I), "download and execute"),
    (re.compile(r"\bDownloadString\s*\(", _I), "download and execute"),
    (re.compile(r"\bRemove-Item\b.*-Recurse\b", _I), "recursive delete"),
    (re.compile(CMD + r"(ri|del|erase|rd|rmdir)\b[^;|\n]*\s-r(ec(urse)?)?\b|" + CMD + r"(del|erase|rd|rmdir)\s+(?:/\S+\s+)*/s\b",
                _I | re.M), "recursive delete"),
    (re.compile(CMD + r"format(\.com)?\s+[a-z]:", _I | re.M), "disk format"),
    (re.compile(r"\bvssadmin(\.exe)?\s+(delete|resize)\s+shadow\w*|\bwmic(\.exe)?\s+shadowcopy\s+delete\b"
                r"|\bwbadmin(\.exe)?\s+delete\s+(catalog|systemstatebackup|backup)\b", _I), "deletes backups or shadow copies"),
    (re.compile(r"\b(Format-Volume|Clear-Disk|Initialize-Disk|Remove-Partition)\b", _I), "disk operation"),
    (re.compile(r"\b(Stop-Computer|Restart-Computer)\b", _I), "shutdown/reboot"),
    (re.compile(r"\b(Stop-Service|Restart-Service|Stop-Process)\b", _I), "service/process stop"),
    (re.compile(r"\b(Disable-NetAdapter|Remove-NetIPAddress|Remove-NetRoute)\b", _I), "network change"),
    (re.compile(r"\bRemove-AD\w+\b", _I), "Active Directory removal"),
    (re.compile(r"\b(Clear-EventLog|wevtutil\s+cl)\b", _I), "event log clear"),
    (re.compile(r"\bnet\s+stop\b", _I), "service stop"),
    (re.compile(r"\b(bcdedit|diskpart)\b", _I), "boot/disk configuration"),
    (re.compile(r"\breg(\.exe)?\s+delete\b", _I), "registry delete"),
    (re.compile(r"\btaskkill\b", _I), "process kill"),
    # Network devices (Cisco IOS / NX-OS / Junos / MikroTik / FortiOS)
    (re.compile(r"^\s*reload\b", _I | re.M), "device reload"),
    (re.compile(r"\b(write\s+erase|erase\s+(startup|nvram|flash))", _I), "config erase"),
    (re.compile(r"\bformat\s+(flash|disk|bootflash|usb)\S*", _I), "storage format"),
    (re.compile(r"\bdelete\s+/force\b", _I), "forced delete"),
    (re.compile(r"\brequest\s+system\s+(reboot|halt|power-off|zeroize)\b", _I), "device reboot/zeroize"),
    (re.compile(r"/system\s+(reboot|shutdown|reset-configuration)\b", _I), "device reboot/reset"),
    (re.compile(r"\bexecute\s+(reboot|shutdown|factoryreset|formatlogdisk)\b", _I), "device reboot/reset"),
]

MODIFYING: list[tuple[re.Pattern, str]] = [
    # options may come before the verb, and the match stays within one command: no ; | & or quotes
    # (with quoted text blanked first, _SHELL_SYNTAX: `echo "not a flatpak/snap install"` installs nothing)
    (re.compile(r"\b(apt|apt-get|yum|dnf|zypper|pacman|snap|flatpak)\s+(?:[^\s;|&'\"()]+\s+){0,10}"
                r"(install|remove|purge|upgrade|dist-upgrade|update|autoremove|-S|-R)\b"), "package change"),
    (re.compile(r"\bpip3?\s+(install|uninstall)\b"), "package change"),
    (re.compile(r"\bsystemctl\s+(\S+\s+)*(start|enable|reload|daemon-reload|edit|set-property)\b"), "service change"),
    (re.compile(r"\bsed\s+(-[a-z]*\s+)*-i"), "in-place file edit"),
    (re.compile(r"\btee\b"), "file write"),
    (re.compile(r"(?<![0-9&>=-])>{1,2}(?!&)\s*(?!/dev/null\b)[^\s|&;]"), "output redirect to file"),
    (re.compile(CMD + r"(mv|cp|rm|rmdir|chmod|chown|chgrp|mkdir|touch|ln|install|truncate)\b", re.M), "filesystem change"),
    (re.compile(r"\b(useradd|usermod|groupadd|groupmod|chpasswd|visudo)\b"), "account change"),
    # passwd is also a file (/etc/passwd) and a getent database, so only as the command itself
    (re.compile(CMD + r"passwd\b(?![.-])", re.M), "account change"),       # CMD takes a path (/usr/bin/passwd)
    (re.compile(r"\bgit\s+(commit|push|reset|checkout|merge|rebase|pull|clean)\b"), "repository change"),
    (re.compile(r"\bdocker\s+(rm|rmi|stop|restart|kill|run|start|pull|compose\s+(up|down|restart))\b"), "container change"),
    (re.compile(r"\bkubectl\s+(apply|create|scale|rollout|patch|edit|label|annotate|cordon|drain)\b"), "kubernetes change"),
    (re.compile(r"\b(ip\s+(addr|route|link)\s+(add|del|change|replace|set|flush)|ifdown|ifup"
                r"|nmcli\s+(con|connection|dev|device)\s+(up|down|modify|delete|add|disconnect|reapply)|nmcli\s+(networking|radio\s+\S+)\s+(on|off)"
                r"|ifconfig\s+\S+\s+(down|up)|route\s+(add|del|delete|change|flush)|(dhclient|dhcpcd)\s+(-\S+\s+)*-[rxk])\b"), "network change"),
    # firewall tools, except when they only list rules
    (re.compile(r"\bip6?tables\b(?!-save\b)(?![^|;&\n]*\s(-[a-zA-Z]*[LS][a-zA-Z]*|--list(-rules)?)\b)"
                r"|\bnft\b(?!\s+(-\S+\s+)*list\b)|\bufw\b(?!\s+(status|show|app\s+list)\b)"
                r"|\bfirewall-cmd\b(?!(\s+--(zone=\S+|permanent))*\s+--(state|get-\S+|list-\S+|query-\S+|info-\S+)\b)"),
     "firewall"),
    # mount alone, or with only -t/-l, lists what is mounted
    (re.compile(CMD + r"mount\b(?!\s*($|[|;&)]))(?!(\s+(-l|-t\s+\S+))+\s*($|[|;&)]))", re.M), "mount change"),
    (re.compile(r"\b(umount|swapoff|swapon)\b"), "mount change"),
    (re.compile(r"\bsysctl\s+-w\b"), "kernel parameter change"),
    (re.compile(CMD + r"eval\b", re.M), "eval"),
    (re.compile(r"\b(python[23]?|perl|ruby|node|php)\s+-[ce]\s", _I), "inline interpreter code"),
    (re.compile(CMD + r"(su|sudo\s+-i|sudo\s+su)\b(?!\S)", re.M), "switch user"),
    (re.compile(r"\bkill\b"), "signal process"),
    # PowerShell / Windows
    (re.compile(r"\b(?!(New-(Object|TimeSpan|Guid|PSSessionOption|CimSessionOption)|Start-Sleep|Clear-(Host|Variable)|"
                r"Set-(Variable|Location|StrictMode)|Add-Member)\b)"
                r"(Set|New|Add|Remove|Enable|Disable|Start|Install|Uninstall|Update|Rename|Move|Copy|Clear|Reset|Register|Unregister|Grant|Revoke|Restore)-[A-Za-z]+\b", _I), "state-changing cmdlet"),
    (re.compile(r"\breg\s+(add|import|load|unload|restore)\b", _I), "registry change"),
    (re.compile(r"\bnetsh\b.*\b(set|add|delete|reset)\b", _I), "network change"),
    (re.compile(r"\bipconfig\s+/(release|renew|flushdns|registerdns)\b", _I), "network change"),
    (re.compile(r"\bsc(\.exe)?\s+(config|stop|start|delete|create)\b|\bnet\s+start\s+[^\s|;&]", _I), "service/account change"),
    # net user/localgroup/share on their own only list; these switches, a share=path or a password change things
    (re.compile(r"\bnet\s+(user|localgroup|share)\b[^|;&\n]*(/(add|delete|del|active|expires|passwordreq|passwordchg|times|grant|remark|unlimited|users|cache)\b|\s\S+=)"
                r"|\bnet\s+user\s+[^/\s|;&]\S*\s+[^/\s|;&]", _I), "service/account change"),
    (re.compile(r"\b(gpupdate|DISM|sfc\s+/scannow|chkdsk\s+.*/[fr])\b", _I), "system repair"),
    # Network devices
    (re.compile(r"^\s*(conf(igure)?(\s+t(erminal)?)?|config\s+system)\b", _I | re.M), "configuration mode"),
    (re.compile(r"\b(write\s+mem(ory)?|copy\s+run(ning-config)?\s+start(up-config)?|commit)\b", _I), "config save/commit"),
    (re.compile(r"^\s*clear\s+", _I | re.M), "clear counters/sessions"),
    (re.compile(r"^\s*/\S+.*\s(set|add|remove|disable|enable)\b", _I | re.M), "RouterOS change"),
    (re.compile(r"^\s*(no\s+)?shutdown\s*$", _I | re.M), "interface shutdown"),
]


# Commands that cut the connection you are issuing them over. Keyed by session kind.
# (These are the classic self-inflicted outages of remote work.)
_SSH_CUTS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\bsystemctl\s+(\S+\s+)*(stop|restart|disable|mask|kill)\s+(\S+\s+)*(ssh|sshd|openssh-server|networking|NetworkManager|systemd-networkd|network|wicked|netbird|tailscaled|wg-quick@\S+)\b"), "stops or restarts the SSH/network service you are connected through"),
    (re.compile(r"\bservice\s+(ssh|sshd|networking|network|NetworkManager)\s+(stop|restart)\b"), "stops or restarts the SSH/network service you are connected through"),
    (re.compile(r"\b(pkill|killall)\s+(-\S+\s+)*(sshd?|ssh-agent)\b"), "kills sshd"),
    (re.compile(r"\bip\s+link\s+set\s+(dev\s+)?\S+\s+down\b"), "brings an interface down"),
    (re.compile(r"\b(ifdown|nmcli\s+(dev|device|con|connection)\s+down|nmcli\s+(dev|device)\s+disconnect|ifconfig\s+\S+\s+down)\b"),
     "brings an interface down"),
    (re.compile(r"\bnmcli\s+networking\s+off\b"), "turns networking off"),
    (re.compile(r"\broute\s+(del|delete)\s+(default|0\.0\.0\.0)\b"), "removes the default route"),
    (re.compile(r"\b(dhclient|dhcpcd)\s+(-\S+\s+)*-[rxk]\b"), "releases the DHCP lease"),
    (re.compile(r"\bip\s+(addr|address|route)\s+(flush|del|delete)\b"), "removes addresses or routes"),
    (re.compile(r"\b(iptables|ip6tables)\s+(\S+\s+)*-P\s+INPUT\s+DROP\b"), "default-drops inbound traffic"),
    (re.compile(r"\b(iptables|ip6tables)\s+(\S+\s+)*-[AI]\s+INPUT\b(?!.*--dport\s+(?!22\b))(?=.*-j\s+(DROP|REJECT))"), "drops inbound traffic, possibly including SSH"),
    (re.compile(r"\b(iptables|ip6tables)\s+(\S+\s+)*-F\b"), "flushes the firewall (default policy may drop SSH)"),
    (re.compile(r"\bnft\s+(flush|delete)\s+(ruleset|table)\b"), "flushes the firewall"),
    (re.compile(r"\bufw\s+(enable|reset|deny\s+(22|ssh)\b|default\s+deny\s+incoming)"), "may block SSH"),
    (re.compile(r"\bfirewall-cmd\b.*--remove-service=ssh\b"), "removes the SSH firewall allowance"),
    (re.compile(r"\bsed\s+(-\S+\s+)*-i\b.*\bsshd_config\b"), "edits sshd_config in place (a bad edit locks you out on restart)"),
    (re.compile(r"\b(usermod\s+-L|passwd\s+-l|chage\s+-E\s*0)\b.*\b(root|\$USER)\b"), "locks the account you may be using"),
    (re.compile(r"\b(shutdown|reboot|poweroff|halt|init\s+[06]|telinit\s+[06])\b"), "reboots or halts the host"),
    (re.compile(r"\b(wg-quick\s+down|tailscale\s+down|openvpn\b.*--rmtun|ipsec\s+(stop|down))\b"), "tears down the VPN this session may traverse"),
]
_WINRM_CUTS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\b(Stop|Restart)-Service\b.*\bWinRM\b", _I), "stops or restarts WinRM, which carries this session"),
    (re.compile(r"\b(Disable|Restart)-NetAdapter\b", _I), "disables or restarts a network adapter"),
    (re.compile(r"\b(Disable-PSRemoting|winrm\s+delete|Remove-Item\b.*\bWSMan:)", _I), "disables PowerShell remoting"),
    (re.compile(r"\bSet-NetFirewallProfile\b.*-DefaultInboundAction\s+Block", _I), "blocks inbound traffic by default"),
    (re.compile(r"\b(Disable-NetFirewallRule|Remove-NetFirewallRule)\b.*\b(WinRM|WINRM|5985|5986)\b", _I), "removes the WinRM firewall rule"),
    (re.compile(r"\bNew-NetFirewallRule\b.*-Direction\s+Inbound\b.*-Action\s+Block", _I), "adds an inbound block rule"),
    (re.compile(r"\b(Remove-NetIPAddress|Remove-NetRoute|Set-NetIPInterface\b.*-Dhcp\s+Disabled)", _I), "changes the addressing this session depends on"),
    (re.compile(r"\b(Restart-Computer|Stop-Computer|shutdown\s+/[rs])\b", _I), "reboots or halts the host"),
    (re.compile(r"\bipconfig\s+/release\b", _I), "releases the DHCP lease"),
    (re.compile(r"\bnetsh\s+(interface|int)\b.*\b(disable|disabled)\b", _I), "disables an interface"),
    (re.compile(r"\bnet\s+stop\s+winrm\b", _I), "stops WinRM"),
    (re.compile(r"\bsc(\.exe)?\s+stop\s+winrm\b", _I), "stops WinRM"),
]
_NETDEV_CUTS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"^\s*reload\b", _I | re.M), "reloads the device"),
    (re.compile(r"^(?!\s*(do\s+)?(show|sh)\b)[^\n]*\b(no\s+)?(ip\s+ssh|line\s+vty|transport\s+input)\b", _I | re.M),
     "changes vty/SSH access"),
    (re.compile(r"^\s*shutdown\s*$", _I | re.M), "shuts the interface you may be connected through"),
    (re.compile(r"\b(no\s+ip\s+address|no\s+ip\s+route|no\s+interface)\b", _I), "removes addressing or routing"),
    (re.compile(r"\b(write\s+erase|erase\s+startup)", _I), "erases the configuration"),
    (re.compile(r"/system\s+(reboot|reset-configuration)|/ip\s+service\s+(disable|set).*ssh|/ip\s+firewall\s+filter\s+(remove|add\s+.*action=drop)", _I), "cuts management access"),
]


# Typed into a window on a remote desktop: the network-wide WinRM rules apply, plus the
# ways to lose the desktop itself.
_RDP_CUTS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\b(Stop|Restart)-Service\b.*\b(TermService|UmRdpService)\b", _I), "stops Remote Desktop Services, which carries this session"),
    (re.compile(r"\bnet\s+stop\s+termservice\b|\bsc(\.exe)?\s+stop\s+termservice\b", _I), "stops Remote Desktop Services"),
    (re.compile(r"\b(logoff|tsdiscon|shutdown\s+/l)\b", _I), "logs off or disconnects this desktop session"),
    (re.compile(r"fDenyTSConnections\b.*\b1\b", _I), "disables Remote Desktop connections"),
    (re.compile(r"\b(Disable-NetFirewallRule|Remove-NetFirewallRule)\b.*\b(RemoteDesktop|Remote Desktop|3389)\b", _I), "removes the Remote Desktop firewall rule"),
] + [r for r in _WINRM_CUTS if "WinRM" not in r[1] and "remoting" not in r[1]]


# Pasted into a remote-support tool's window (ScreenConnect, TeamViewer, AnyDesk...): the
# network rules apply, plus stopping the tool's own agent and ending the desktop session.
_REMOTE_AGENTS = r"(ScreenConnect|ConnectWise|TeamViewer|AnyDesk|Splashtop|RustDesk|ITSPlatform|LMIGuardian|LogMeIn|Bomgar|BeyondTrust|DWAgent)"
_WINDOW_CUTS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\b(Stop|Restart)-Service\b.*" + _REMOTE_AGENTS, _I), "stops the remote-support agent this session runs through"),
    (re.compile(r"\b(net|sc(\.exe)?)\s+stop\b.*" + _REMOTE_AGENTS, _I), "stops the remote-support agent this session runs through"),
    (re.compile(r"\b(taskkill|Stop-Process|kill|pkill|killall)\b.*" + _REMOTE_AGENTS, _I), "kills the remote-support agent this session runs through"),
    (re.compile(r"\b(Uninstall-Package|msiexec\s+/x|wmic\b.*\buninstall)\b.*" + _REMOTE_AGENTS, _I), "uninstalls the remote-support agent"),
    (re.compile(r"\b(logoff|tsdiscon|shutdown\s+/l)\b", _I), "logs off or disconnects this desktop session"),
] + [r for r in _WINRM_CUTS if "WinRM" not in r[1] and "remoting" not in r[1]]


def session_impact(command: str, session_kind: str) -> str | None:
    """Reason this command would cut the session it is run in, or None.

    session_kind is "local", "ssh", "winrm", "rdp" (typed into a window on the remote desktop),
    "window" (pasted into a remote-support tool's window). SSH sessions may reach a network
    device rather than a Linux host, so device rules are checked too."""
    if session_kind == "ssh":
        rules = _SSH_CUTS + _NETDEV_CUTS
    elif session_kind == "winrm":
        rules = _WINRM_CUTS
    elif session_kind == "rdp":
        rules = _RDP_CUTS
    elif session_kind == "window":
        rules = _WINDOW_CUTS
    else:
        return None
    for pat, why in rules:
        if pat.search(command):
            return why
    return None


# Rules about shell syntax (redirects, where a command starts). Inside quotes these characters
# are data, e.g. `awk 'NR>1{...}'`, so they are matched against the command with quoted text blanked.
_SHELL_SYNTAX = {r[0] for r in DISRUPTIVE + MODIFYING if r[0].pattern.startswith(CMD)} | {
    r[0] for r in MODIFYING if r[1] in ("output redirect to file", "package change")}

# Commands that hand quoted text to a shell again: their quotes hide nothing.
_REPARSES = re.compile(
    r"\b((ba|z|k|da|)sh|su|runuser|script|env)\s+(\S+\s+)*-c\b|\b(ssh|eval|xargs|watch|nohup|timeout|chroot|parallel)\b"
    r"|\bfind\b.*\s-exec(dir)?\b|\b(powershell|pwsh)(\.exe)?\b|\bcmd(\.exe)?\s+/[ck]\b", _I)

# awk can write files and run commands from inside its program text.
_AWK = re.compile(r"\b[gmn]?awk\b")
_AWK_WRITES = re.compile(r"\bprintf?\b[^;}]*?(>|\|)|\bsystem\s*\(|\|\s*getline\b|\bfflush\s*\(\s*\"")


def _quoted(command: str) -> tuple[str, list[str]] | None:
    """(command with the contents of '...' and "..." blanked, the quoted texts), or None when
    the quoting can't be read with confidence (unterminated, or $(...)/backticks inside "...",
    which the shell does run)."""
    out, texts, i, n = [], [], 0, len(command)
    while i < n:
        c = command[i]
        if c == "\\" and i + 1 < n:
            out.append(command[i:i + 2])
            i += 2
        elif c in "'\"":
            j, k = i + 1, None
            while j < n:
                if command[j] == "\\" and c == '"':
                    j += 2
                    continue
                if command[j] == c:
                    k = j
                    break
                j += 1
            if k is None:
                return None
            text = command[i + 1:k]
            if c == '"' and ("$(" in text or "`" in text):
                return None
            texts.append(text)
            out.append(c + " " * len(text) + c)
            i = k + 1
        else:
            out.append(c)
            i += 1
    return "".join(out), texts


def classify(command: str) -> tuple[str, list[str]]:
    """Return (level, reasons) for the command according to local rules."""
    q = None if _REPARSES.search(command) else _quoted(command)
    shell = q[0] if q else command

    def hits(rules):
        return [why for pat, why in rules if pat.search(shell if pat in _SHELL_SYNTAX else command)]

    reasons = hits(DISRUPTIVE)
    if reasons:
        return "disruptive", reasons
    reasons = hits(MODIFYING)
    if _AWK.search(command) and any(_AWK_WRITES.search(t) for t in (q[1] if q else [command])):
        reasons.append("awk writes a file or runs a command")
    if reasons:
        return "modifying", reasons
    return "read_only", []


def effective(model_level: str, command: str) -> tuple[str, list[str]]:
    """Combine the model's label with local rules; the higher level wins."""
    local, reasons = classify(command)
    model_level = model_level if model_level in LEVELS else "modifying"
    level = max(model_level, local, key=LEVELS.index)
    return level, reasons
