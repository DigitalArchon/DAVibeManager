"""Local risk classifier.

The model labels each proposed command with a risk level, but a model's self-assessment
is not trustworthy (it can be wrong, or steered by prompt injection in command output).
These rules can only *raise* the level the model gave, never lower it.

Two lists work together. The deny-list (DISRUPTIVE, MODIFYING) names what a command does
when it is known to change or break something, and decides between the amber and the red
confirmation. The allow-list (`reads_only`, further down) names the commands known only to
read: `read_only` is the level that runs without a dialog and can be put on a watch, so it
stands only for a command the allow-list can confirm, whatever the model said. Until Nov
2026 there was only the deny-list, and a command it had never heard of kept the model's label.
"""

from __future__ import annotations

import functools
import re

LEVELS = ("read_only", "modifying", "disruptive")
UNKNOWN = "not a command the local rules know as read-only"
TOO_LONG = "too long for the local rules to read in full"

_I = re.IGNORECASE


# ---------------------------------------------------------------------------------------
# What the rules read. A command can be megabytes long (a tool sent over WinRM is one command
# holding the whole file as base64) and every rule runs on the app's one event loop, so the
# rules read a bounded copy: a long run of base64 or hex counts as one word and keeps only its
# two ends, and of what is then still longer than _READ characters the rules see the head and
# the tail. A command cut that way is never rated read-only.
_READ = 32_000
_RUN = re.compile(r"[A-Za-z0-9+/=_-]{400,}")
_GAP = "…"                 # stands for what was left out; no rule has a word for it


@functools.lru_cache(maxsize=4)
def bounded(command: str) -> tuple[str, bool]:
    """(the command as the rules read it, whether its middle was left out)."""
    text = _RUN.sub(lambda m: m.group()[:48] + _GAP + m.group()[-48:], command) if len(command) > 400 else command
    if len(text) <= _READ:
        return text, False
    return text[:_READ // 2] + "\n" + _GAP + "\n" + text[-_READ // 2:], True


# Position where a new command starts: a line's start; after a separator, `{`, `$(` or a backtick;
# after an opening quote (only ever seen where the command hands the quoted text to a shell,
# _REPARSES: elsewhere quoted text is blanked first); after `do`, `then` or `else`; after
# `ssh [options] host`, find's -exec, a shell's -c, a here-string, or `docker exec name`. Then any
# prefixes that run the next word as the command (sudo, pkexec or run0 and their options, env, a
# variable set for it, nohup, timeout 5, systemd-run, xargs...), and the command may be named by
# its path (/bin/rm) or escaped (\rm).
_SSH_HOST = r"\bssh\s+(?:-[46AaCfGgKkMNnqsTtVvXxYy]+\s+|-[BbcDEeFIiJLlmOoPpQRSWw]\s*\S+\s+)*[^\s-]\S*\s+"
# a shell, or what starts one elsewhere, told its command with -c (-lc, -ec, /c): `bash -c reboot`,
# `su - root -c reboot`, `cmd /c shutdown /r`, `powershell -Command shutdown /r`, `wsl -e bash -c ...`
_SHELLS = r"(?:(?:ba|z|k|da|a|fi|c|tc)?sh|su|runuser|script|powershell|pwsh|cmd)"
_SHELL_C = r"\b" + _SHELLS + r"\b[^\s;&|]{0,8}(?:\s+[^\s;&|]+){0,8}?\s+(?:-[A-Za-z]*c|-[Cc]ommand|/[ckCK])\s+"
_IN_CONTAINER = (r"\b(?:docker|podman|nerdctl)\s+(?:compose\s+)?exec\s+(?:-\S+\s+){0,8}[^\s-]\S*\s+"
                 r"|\b(?:kubectl|oc|k)\s+(?:[^\s;&|]+\s+){0,12}?--\s+")
# options, each perhaps with its argument (sudo -u root, nice -n 19, xargs -a list, timeout -s KILL,
# systemd-run -p MemoryMax=1G --scope), which is never a prefix's own word nor a variable set for
# the command (A=1 before the command, not before another option): a command has one reading, read
# in linear time (`xargs -0 xargs -0 ...` isn't tried every way)
_RUNS_NEXT = (r"(?:sudo|doas|pkexec|run0|nohup|exec|time|nice|ionice|stdbuf|systemd-run|xargs|parallel|command|builtin|env|timeout"
              r"|busybox|toybox|setsid|strace|ltrace|unshare|nsenter|eval|watch|chroot|flock|chrt|taskset|start|call|saps|Start-Process|wsl|psexec|runuser)")
_OPTS = r"(?:-\S+(?:\s+(?!-)(?!" + _RUNS_NEXT + r"\s)(?![A-Za-z_]\w*=[^\s'\"]*+\s++(?!-))\S+)?\s+)*"
_AS_ROOT = r"(?:sudo|doas|pkexec|run0)\s+" + _OPTS
_PREFIX = (r"(?:" + _AS_ROOT + r"|(?:nohup|exec|time|nice|ionice|stdbuf|systemd-run|xargs|parallel|setsid|strace|ltrace|unshare|nsenter|watch|wsl|runuser)\s+" + _OPTS
           + r"|command\s+(?:-p\s+)?|builtin\s+|eval\s+|busybox\s+|toybox\s+|call\s+|env\s+" + _OPTS + r"(?:\w+=[^\s'\"]*+\s+)*+"
           r"|(?:timeout|chroot|flock|chrt|taskset)\s+" + _OPTS + r"\S+\s+"
           r"|(?:start|saps|Start-Process)\s+(?:[-/]\w+\s+){0,4}|psexec\s+(?:[-/\\]\S+\s+){0,8}"
           r"|(?:[A-Za-z_]\w*=[^\s'\"]*+\s+)++)")
# a path's parts are words of their own: none holds a separator or a quote, so a line of nothing
# but `;` or `'` isn't read to its end from every one of them
_PATH = r"(?:\\|(?:[^\s/;&|(){}<>'\"`]{0,255}+/)*+)"
_DIR = r"(?:[^\s/;&|(){}<>'\"`]{0,255}+/)*+"
CMD = (r"(?:^|[;&|(`{]\s*|[\"'](?=\S)|\$\(\s*|<<<\s*[\"']?|\b(?:do|then|else)\s+|" + _SSH_HOST + r"|\s-(?:exec|execdir|ok|okdir)\s+"
       r"|" + _SHELL_C + r"[\"']?(?:&\s*\{\s*)?|" + _IN_CONTAINER + r"|\b" + _AS_ROOT + r")" + _PREFIX + r"{0,16}" + _PATH)


def _later(first: str, then: str) -> str:
    """`first`, and `then` after it in the same command (no ; & | or line break between). The
    search from one `first` stops at the next, so a line of nothing but `first` is read once."""
    return first + r"(?:(?!" + first + r")[^;&|\n])*?" + then


_END = r"\s*(?:$|[;&|)\n])"                    # the command ends here
_WORDS = r"(?:[^\s;&|]+\s+)"                   # one more word of the same command

# Each entry: (pattern, reason). Patterns are matched against the whole command text.
DISRUPTIVE: list[tuple[re.Pattern, str]] = [
    # the flags may end the line (`xargs rm -f`) or follow the path (`rm /srv/x -rf`), but not `--`
    (re.compile(r"\brm\s+(?:(?!--\s|rm\s)[^\s;&|]+\s+)*?(?:-[a-zA-Z]*[rRf][a-zA-Z]*|--recursive|--force|--no-preserve-root)(?![\w-])"),
     "recursive/forced delete"),
    (re.compile(r"\b(mkfs(\.\w+)?|mke2fs|mkswap|wipefs|fdisk|sfdisk|parted|sgdisk|gdisk|blkdiscard|lvremove|vgremove|pvremove)\b"),
     "disk/partition tool"),
    (re.compile(r"\b(zpool|zfs)\s+destroy\b|" + _later(r"\bmdadm\b", r"--zero-superblock\b")
                + r"|\bcryptsetup\s+" + _WORDS + r"{0,8}?(luksErase|erase|luksKillSlot)\b"
                r"|\bnvme\s+(format|sanitize)\b|" + _later(r"\bhdparm\b", r"--security-erase"), _I), "erases a disk or volume"),
    # more ways to lose a volume or what is on it: shrunk, taken offline, pulled out of its array or
    # pool, its header written over, its blocks discarded
    (re.compile(r"\b(?:lvreduce|vgreduce|sg_format|sg_sanitize|ddrescue|nwipe|sfill|srm)\b"
                r"|\blvresize\s+" + _WORDS + r"{0,8}?-L\s*-|\b(?:vgchange|lvchange)\s+" + _WORDS + r"{0,8}?-a\s*n\b"
                r"|\bresize2fs\s+\S+\s+\S|\bxfs_repair\s+" + _WORDS + r"{0,8}?-L\b|\bbtrfs\s+check\s+" + _WORDS + r"{0,8}?--repair\b"
                r"|\bbtrfs\s+(?:subvolume\s+delete|device\s+(?:remove|delete)|filesystem\s+resize\s+-)"
                r"|\bzfs\s+(?:rollback|unmount\s+-a|umount\s+-a)\b|\bzpool\s+(?:export|labelclear|offline|detach|create|remove|replace)\b"
                r"|" + _later(r"\bmdadm\b", r"\s(?:--stop|-S|--fail|-f|--remove|-r|--create|-C)\b")
                + r"|\bcryptsetup\s+" + _WORDS + r"{0,8}?(?:luksFormat|close|luksClose|luksRemoveKey|reencrypt|luksHeaderRestore)\b"
                r"|\bumount\s+" + _WORDS + r"{0,8}?(?:-[a-zA-Z]*a[a-zA-Z]*\b|/" + _END + r")|\bmount\s+" + _WORDS + r"{0,8}?remount,ro\S*\s+/" + _END
                + r"|\bpartx\s+" + _WORDS + r"{0,8}?(?:-d|--delete)\b|\bdmsetup\s+(?:remove|remove_all|wipe_table)\b"
                r"|" + _later(r"\bhdparm\b", r"\s(?:-Y|--trim-sector-ranges|--make-bad-sector)\b")
                + r"|\bnvme\s+(?:delete-ns|reset)\b|\bbadblocks\s+" + _WORDS + r"{0,8}?-[a-zA-Z]*w|\bwipe\s+-|\bscrub\s+/dev/"
                r"|\bgrub2?-install\b|\befibootmgr\s+" + _WORDS + r"{0,8}?(?:-B|--delete-bootnum)\b|\b(?:rmmod|modprobe\s+" + _WORDS + r"{0,4}?(?:-r|--remove))\b"),
     "removes a volume, takes it offline or writes over it"),
    # each dd on the line by itself: a later `of=/dev/null` excuses only its own dd
    (re.compile(_later(r"\bdd\b", r"\bof=(?!/dev/null\b)"), _I), "dd writing to a target"),
    # deleting by other means than rm -r: what's found, a list of files, what's not in the copy, a
    # repository's work, settings, a session, every process
    (re.compile(_later(r"\bfind\b", r"\s-(?:delete\b|(?:exec|execdir|ok|okdir)\s+" + _DIR + r"(?:rm|shred|unlink)\b)")),
     "find deleting what it finds"),
    (re.compile(r"\b(?:xargs|parallel)\s+" + _OPTS + _DIR + r"(?:rm|shred|unlink)\b"), "deleting a list of files"),
    (re.compile(_later(r"\brsync\b", r"\s--(?:del\b|delete|remove-source-files)")), "rsync deleting files"),
    (re.compile(_later(r"\bgit\b", r"\s(?:reset\s+(?:-\S+\s+)*--hard|clean\s+(?:-\S+\s+)*(?:-[a-z]*f|--force)|checkout\s+(?:--\s+)?\." + _END
                       + r"|restore\s+(?:-\S+\s+)*\." + _END + r"|stash\s+(?:drop|clear)\b|branch\s+(?:-\S+\s+)*-D\b|switch\s+(?:-f|--force|--discard-changes)\b"
                       r"|push\s+" + _WORDS + r"{0,8}?(?:-f|--force\S*|--delete|--mirror)\b|reflog\s+expire\b|filter-branch\b|filter-repo\b|update-ref\s+-d\b)")),
     "a repository's changes discarded"),
    (re.compile(r"\bdconf\s+reset\s+-f\b"), "desktop settings reset"),
    (re.compile(_later(r"\bflatpak\s+(?:uninstall|remove)\b", r"\s--all\b")), "every Flatpak removed"),
    (re.compile(CMD + r"unlink\s", re.M), "file destroyed"),
    (re.compile(r"\bloginctl\s+(?:terminate|kill)-(?:session|user)\b"), "session ended"),
    (re.compile(r"\bkill\s+(?:-[A-Za-z0-9]+\s+|-s\s+\S+\s+|--\s+)+-1\b"), "every process killed"),
    (re.compile(r"(?:>\s*|\btee\s+(?:-\S+\s+){0,4})/dev/(sd|nvme|vd|hd|xvd|mmcblk|dm-|md\d|mapper/|disk/|loop\d)"
                r"|\b(?:cp|mv)\s+" + _WORDS + r"{1,8}?/dev/(?:sd|nvme|vd|hd|xvd|mmcblk|dm-|md\d|mapper/|disk/)\S*" + _END), "write to block device"),
    (re.compile(r"(?:>\s*|\btee\s+(?:-\S+\s+){0,4})(?:/proc/sysrq-trigger|/sys/block/\S+/device/delete)\b"), "kernel told to reboot, crash or drop a disk"),
    (re.compile(CMD + r"(shutdown|reboot|poweroff|halt|kexec|pm-suspend|pm-hibernate|rtcwake|psshutdown|tsshutdn)\b", re.M), "shutdown/reboot"),
    # Windows' own, however it is capitalised, with its switches (/r, -s...): `Shutdown.exe /r /t 0`
    (re.compile(CMD + r"shutdown\s+[/-][a-z]", _I | re.M), "shutdown/reboot"),
    (re.compile(CMD + r"(telinit|init)\s+[06]\b", re.M), "runlevel change"),
    # the same asked of systemd over D-Bus (logind's Reboot, PowerOff...)
    (re.compile(_later(r"\b(?:busctl|dbus-send|gdbus|qdbus)\b", r"[\s.](?:Reboot|PowerOff|Halt|KExec|SoftReboot)\w*\b")),
     "shutdown/reboot"),
    # systemctl's options come before the verb; the verb is a word of this command, not of the next one
    (re.compile(r"\bsystemctl\s+(?:(?!systemctl\b)[^\s;&|]+\s+){0,12}?(stop|restart|try-restart|reload-or-restart|try-reload-or-restart|condrestart|disable|mask"
                r"|kill|isolate|reboot|poweroff|halt|kexec|rescue|emergency|suspend|hibernate|hybrid-sleep|suspend-then-hibernate|soft-reboot|exit"
                r"|switch-root|freeze)(?![\w-])"), "service stop/restart"),
    (re.compile(r"\bservice\s+\S+\s+(stop|restart)\b|(?<![\w-])/etc/init\.d/\S+\s+(stop|restart)\b|\b(?:rc-service\s+\S+|sv|initctl)\s+(?:stop|restart|down)\b"
                r"|\bsupervisorctl\s+(?:stop|restart|shutdown)\b|\bpm2\s+(?:delete|restart|stop|kill)\b|\b(?:apachectl|apache2ctl)\s+(?:-k\s+)?(?:stop|restart)\b"
                r"|\bnginx\s+-s\s+(?:stop|quit)\b|\bpg_ctl(?:cluster)?\s+" + _WORDS + r"{0,6}?(?:stop|restart)\b|\bmysqladmin\s+" + _WORDS + r"{0,8}?(?:shutdown|drop)\b"
                r"|\brabbitmqctl\s+(?:stop|stop_app|reset|force_reset|shutdown)\b"), "service stop/restart"),
    (re.compile(r"\b(kill\s+(?:-9|-KILL|-SIGKILL|-s\s+(?:9|KILL|SIGKILL))|killall5?|pkill|skill|xkill)\b|\bfuser\s+" + _WORDS + r"{0,4}?-[a-zA-Z]*k"
                r"|\bkill\s+(?:-\S+\s+)*1" + _END), "process kill"),
    (re.compile(r"\b(?:iptables|ip6tables)\s+" + _WORDS + r"{0,8}?(?:-[FXP]\b|--(?:flush|delete-chain|policy)\b)"), "firewall flush/policy"),
    (re.compile(r"\bnft\s+(?:-\S+\s+){0,6}(flush|delete)\b"), "firewall flush"),
    (re.compile(r"\bufw\s+(?:--\S+\s+){0,4}(disable|reset)\b|\bfirewall-cmd\b[^;&|\n]{0,200}?--panic-on\b"), "firewall disable"),
    (re.compile(r"\b(?:chmod|chown|chgrp)\s+" + _WORDS + r"{0,6}?(?:-[a-zA-Z]*R[a-zA-Z]*|--recursive)\s+" + _WORDS + r"{0,6}?/(?:\s+--\S+)*" + _END),
     "recursive permission change on /"),
    (re.compile(r"\b(userdel|deluser)\b"), "user deletion"),
    (re.compile(r"\bcrontab\s+(?:-u\s*\S+\s+|-[a-qs-z]+\s+){0,4}-[a-z]*r[a-z]*\b"), "crontab removal"),
    (re.compile(r"\bdrop\s+(database|table|schema)\b", _I), "SQL drop"),
    (re.compile(r"\btruncate\s+table\b", _I), "SQL truncate"),
    (re.compile(r"\bip\s+(?:-\S+\s+){0,6}l(?:i(?:nk?)?)?\s+s(?:et?)?\s+(?:dev\s+)?\S+\s+" + _WORDS + r"{0,8}?down\b"), "interface down"),
    (re.compile(r"\b(?:docker|podman|nerdctl)\s+(?:(?:system|container|image|volume|network|builder)\s+prune|system\s+reset|volume\s+(?:rm|remove)"
                r"|(?:container\s+|pod\s+)?rm\s+" + _WORDS + r"{0,6}?(?:-[a-z]*f|--force)\b|(?:container\s+)?(?:stop|kill|restart|pause)\b"
                r"|(?:swarm\s+leave|service\s+(?:rm|scale\s+\S+=0)|stack\s+rm|node\s+rm)\b"
                r"|compose\s+" + _WORDS + r"{0,6}?(?:down|rm|stop|kill|restart)\b)|\bdocker-compose\s+" + _WORDS + r"{0,6}?(?:down|rm|stop|kill|restart)\b"
                r"|\bcrictl\s+(?:rm|rmp|stop|stopp)\b|\blxc\s+(?:delete|stop|restart)\b"),
     "containers stopped or removed"),
    # a virtual machine or its host's part in a cluster
    (re.compile(r"\bvirsh\s+(?:-\S+\s+(?:\S+\s+)?){0,3}(?:destroy|shutdown|undefine|reboot|reset|snapshot-revert|vol-delete|net-destroy|pool-destroy|pool-delete|managedsave|suspend)\b"
                r"|\b(?:qm|pct)\s+(?:stop|destroy|shutdown|reboot|reset|rollback|suspend)\b|\bpvecm\s+delnode\b"
                r"|\bVBoxManage\s+(?:controlvm\s+\S+\s+(?:poweroff|reset|pause|savestate|acpipowerbutton)|unregistervm)\b|\bvagrant\s+(?:destroy|halt|reload)\b"
                r"|\bxl\s+(?:destroy|shutdown|reboot)\b|\bvim-cmd\s+vmsvc/power\.(?:off|reset|shutdown|reboot|suspend)\b", _I),
     "a virtual machine stopped, reset or removed"),
    (re.compile(r"\b(?:kubectl|oc|k|k3s\s+kubectl|microk8s\s+kubectl)\s+" + _WORDS + r"{0,8}?(?:delete|drain|evict|replace\s+" + _WORDS + r"{0,6}?--force"
                r"|rollout\s+(?:restart|undo)|scale\s+" + _WORDS + r"{0,8}?--replicas[= ]0\b|taint\s+" + _WORDS + r"{0,6}?\S*:NoExecute|adm\s+drain)\b"
                r"|\bhelm\s+" + _WORDS + r"{0,4}?(?:uninstall|delete|rollback)\b|\bkubeadm\s+(?:reset|upgrade\s+apply)\b|\bk3s-(?:killall|uninstall)\.sh\b"
                r"|\b(?:minikube|kind|k3d)\s+(?:cluster\s+)?delete\b|\betcdctl\s+" + _WORDS + r"{0,6}?del\b"), "kubernetes delete"),
    # what was built is torn down, by the tool that built it or the cloud's own
    (re.compile(r"\b(?:terraform|tofu)\s+" + _WORDS + r"{0,4}?(?:destroy|apply\s+" + _WORDS + r"{0,6}?-(?:auto-approve|destroy)|state\s+rm)\b|\bpulumi\s+(?:destroy|stack\s+rm)\b"
                r"|\baws\s+" + _WORDS + r"{1,6}?(?:terminate-\S+|stop-instances|reboot-instances|delete-\S+|deregister-\S+|rb\b|rm\b)"
                r"|" + _later(r"\baws\s+s3\s+sync\b", r"\s--delete\b")
                + r"|\b(?:az|gcloud|doctl|hcloud|linode-cli|oci)\s+" + _WORDS + r"{1,8}?(?:delete|purge|deallocate|stop|restart|reset|terminate)\b"
                r"|\bgsutil\s+" + _WORDS + r"{0,4}?(?:rm|rb)\b|" + _later(r"\bgsutil\s", r"\brsync\s+" + _WORDS + r"{0,4}?-[a-zA-Z]*d")
                + r"|\brclone\s+" + _WORDS + r"{0,4}?(?:purge|sync|delete|deletefile|rmdirs?|cleanup)\b|\bmc\s+(?:rm|rb)\b|\bs3cmd\s+(?:del|rm|rb)\b"
                r"|\brestic\s+" + _WORDS + r"{0,6}?(?:forget|prune|restore)\b|\bborg\s+(?:delete|prune)\b|\bduplicity\s+remove-\S+"
                r"|\btimeshift\s+" + _WORDS + r"{0,4}?--(?:delete\S*|restore)\b|\bsnapper\s+" + _WORDS + r"{0,4}?(?:delete|rollback)\b"),
     "deletes or stops what runs in a cloud, or removes backups"),
    (re.compile(_later(r"\b(?:ansible|salt)\b", r"\b(?:reboot|shutdown|state=absent|system\.(?:reboot|shutdown|poweroff|halt))\b")), "reboots or removes across hosts"),
    (re.compile(r"\bredis-cli\b[^;&|\n]{0,200}?\b(?:flushall|flushdb|shutdown)\b|\b(?:dropdb|dropuser|pg_resetwal|pg_dropcluster)\b"
                r"|\bpg_restore\s+" + _WORDS + r"{0,8}?(?:-c|--clean)\b|\bmongo(?:sh)?\b[^;&|\n]{0,300}?\.(?:dropDatabase|drop|deleteMany|remove|shutdownServer)\s*\("
                r"|\b(?:ldapdelete|dsrm|dcpromo)\b|\bsamba-tool\s+(?:user\s+delete|domain\s+demote|computer\s+delete|group\s+delete)\b|\bsmbpasswd\s+-x\b"
                r"|\bipa\s+\S+-del\b|\bkadmin\S*\s[^;&|\n]{0,200}?\bdelprinc\b|\brealm\s+leave\b|\bnet\s+ads\s+leave\b|\bjournalctl\s+" + _WORDS + r"{0,6}?--vacuum-\S+"
                r"|\bdo-release-upgrade\b|\bfwupdmgr\s+(?:update|install)\b|\bnix-collect-garbage\b|\bpacman\s+-R\w*dd|\bdnf\s+system-upgrade\s+reboot\b"
                r"|\brpm-ostree\s+rollback\b", _I), "deletes data, accounts or a directory's objects"),
    # code fetched from the network or decoded at runtime and executed: unreviewable
    (re.compile(r"\b(curl|wget|fetch|Invoke-WebRequest|iwr)\b(?:(?!\b(?:curl|wget|fetch|Invoke-WebRequest|iwr)\b)[^|;])*?\|\s*" + _PREFIX
                + r"{0,16}" + _DIR + r"(?:(?:ba|z|k|da|a|fi|c|tc)?sh|python[23]?|perl|ruby|node|php|source)\b", _I), "pipe to shell"),
    (re.compile(r"\b(ba|z|k|da|)sh\s+(-[a-z]*c\s+)?[\"']?\s*\$\((curl|wget)\b", _I), "shell runs downloaded script"),
    (re.compile(r"(?:\b(ba|z|k|da|)sh|\bsource|(?:^|[;&|]\s*)\.)\s+<\s*\((curl|wget)\b", _I | re.M), "shell runs downloaded script"),
    (re.compile(r"\bbase64\s+(-d|--decode)\b(?:(?!\bbase64\s)[^|;])*?\|\s*" + _PREFIX + r"{0,16}" + _DIR + r"(ba|z|k|da|)sh\b", _I),
     "decoded payload piped to shell"),
    # text piped into a shell or an interpreter that is given nothing else to run: it runs the text
    (re.compile(r"\|\s*" + _PREFIX + r"{0,16}" + _DIR + r"(?:(?:ba|z|k|da|a|fi|c|tc)?sh|python[23]?|perl|ruby|node|php)(?:\s+-(?:s|[xveu]+)?)*" + _END),
     "text piped into a shell or interpreter, which runs it"),
    (re.compile(r"\bshred\b"), "secure erase"),
    # a function piping itself to itself: `:(){ :|:& };:`, `bomb(){ bomb|bomb& }`. The name is
    # taken whole (possessive, from a word's start), and the body of such a thing is short
    (re.compile(r"(?<!\w)(\w++|:)\s*\(\)\s*\{[^}]{0,200}?\1\s*\|\s*\1"), "fork bomb"),
    (re.compile(r"\bhistory\s+-c\b"), "history clear"),
    (re.compile(_later(r"\b(?:nc|ncat|netcat)\b", r"\s-e\s"), _I), "reverse shell"),
    (re.compile(r"\bchmod\s+(?:-\S+\s+){0,4}[0-7]*777\b"), "world-writable permissions"),
    # PowerShell / Windows
    (re.compile(r"\b(Invoke-Expression|iex)\b|\[scriptblock\]::Create\b|\.InvokeScript\s*\(", _I), "Invoke-Expression"),
    (re.compile(r"(?<!\S)[-/](EncodedCommand|Encoded\w*|enc|ec)[\s:]+\S+", _I), "encoded PowerShell"),
    # -e, -en, -enc... are -EncodedCommand too (not -ExecutionPolicy: -ex...), with a dash or a slash
    (re.compile(_later(r"\b(?:powershell|pwsh)\b", r"\s[-/](?:e|ec|en\w*)[\s:]+[\"']?[A-Za-z0-9+/=]{8,}"), _I), "encoded PowerShell"),
    (re.compile(r"\b(Invoke-WebRequest|iwr|curl|wget|Invoke-RestMethod|irm)\b(?:(?!\b(?:Invoke-WebRequest|iwr|curl|wget|Invoke-RestMethod|irm)\b)[^\n])*?"
                r"\|\s*(iex|Invoke-Expression|&|powershell|pwsh|sal\b)", _I),
     "download and execute"),
    (re.compile(r"\bDownloadString\s*\(", _I), "download and execute"),
    (re.compile(_later(r"\b(?:Remove-Item|ri|rm|del|erase|rd|rmdir)\b", r"\s-r(?:e(?:c(?:u(?:r(?:se?)?)?)?)?)?\b"), _I), "recursive delete"),
    # a folder listed with everything under it and the list handed to what deletes: `gci C:\Data -Recurse | Remove-Item`
    (re.compile(r"\s-r(?:e(?:c(?:u(?:r(?:se?)?)?)?)?)?\b[^;\n]{0,300}?\|\s*(?:(?:foreach|%|ForEach-Object)\s*\{\s*)?(?:Remove-Item|ri|rm|del|erase|rd|rmdir)\b", _I),
     "recursive delete"),
    # cmd's own: del /s, rd /s, with the switch before or after the path
    (re.compile(CMD + _later(r"(?:del|erase|rd|rmdir)\b", r"\s/s\b"), _I | re.M), "recursive delete"),
    (re.compile(r"\[(?:System\.)?IO\.Directory\]::Delete\s*\([^)]{0,200},\s*\$true|\.Delete\s*\(\s*\$true\s*\)"
                r"|\b(?:shutil\.)?rmtree\s*\(|\brmSync\s*\([^)]{0,200}recursive", _I), "recursive delete"),
    (re.compile(CMD + r"format(\.com)?\s+[a-z]:", _I | re.M), "disk format"),
    (re.compile(r"\bvssadmin\s+(delete|resize)\s+shadow\w*|\bwmic\b[^;&|\n]{0,200}?\bshadowcopy\s+delete\b|\bWin32_ShadowCopy\b[^\n]{0,200}?(?:\.Delete\s*\(|Remove-CimInstance)"
                r"|\bwbadmin\s+(?:delete\s+(catalog|systemstatebackup|backup)|start\s+(?:recovery|sysrecovery|systemstaterecovery))\b", _I),
     "deletes backups or shadow copies"),
    (re.compile(r"\b(Format-Volume|Clear-Disk|Initialize-Disk|Remove-Partition|Resize-Partition|Repair-Volume|Reset-PhysicalDisk|Enable-BitLocker|Lock-BitLocker)\b"
                r"|\bSet-Disk\b[^|;\n]{0,200}?-IsOffline\b|\bmanage-bde\s+" + _WORDS + r"{0,4}?-(?:off|on|forcerecovery|lock|wipefreespace|protectors\s+" + _WORDS
                + r"{0,4}?-delete)\b|\bcipher\s+/[we]\b|\bmountvol\s+\S+\s+/[dp]\b|\bfsutil\s+(?:usn\s+deletejournal|volume\s+dismount)\b"
                r"|\bconvert\s+[a-z]:\s+/fs:|\b(?:bootrec|bootsect|bcdboot)\b|\bdism\b[^;&|\n]{0,200}?/apply-image\b|\bchkdsk\b[^;&|\n]{0,100}?\s/[rx]\b", _I),
     "disk operation"),
    (re.compile(r"\b(Stop-Computer|Restart-Computer)\b|\bwmic\b[^;&|\n]{0,200}?\bos\b[^;&|\n]{0,200}?\bcall\s+(?:reboot|shutdown|win32shutdown)\b"
                r"|\bWin32_OperatingSystem\b[^\n]{0,200}?\b(?:Reboot|Shutdown|Win32Shutdown)\b|\bpowrprof(?:\.dll)?,\s*SetSuspendState\b"
                r"|\b[A-Za-z]+-[A-Za-z][A-Za-z0-9]*\b[^|;\n]{0,300}?\s-(?:Restart|AutoReboot|ForceReboot)\b(?!:\s*\$false)", _I), "shutdown/reboot"),
    # every Stop-, Restart- and Suspend- cmdlet (a service, a VM, a site, a cluster's node, a job on a
    # server) but the three that end only something of this console's own
    (re.compile(r"\b(?!Stop-(?:Transcript|Job|PSBreakpoint)\b)(?:Stop|Restart|Suspend)-[A-Za-z][A-Za-z0-9]*\b|\b(?:spsv|spps)\b|\bSave-VM\b"
                r"|\bSet-Service\b[^|;\n]{0,200}?-Status\s+[\"']?(?:Stopped|Paused)\b|\)\.(?:Stop|Kill|Terminate|StopService)\s*\(|\$_\.(?:Stop|Kill|Terminate|StopService|Delete)\s*\(", _I),
     "service/process stop"),
    # every Remove- cmdlet (an account, a zone, a share, a VM, a rule, a feature) but those that take
    # away one file, one value, or something that lives only in this console
    (re.compile(r"\b(?!Remove-(?:Item|ItemProperty|Variable|Module|PSSession|CimSession|Job|PSDrive|TypeData|Event|PSBreakpoint|Alias|AppxPackage|PSReadLineKeyHandler)\b)"
                r"Remove-[A-Za-z][A-Za-z0-9]*\b|\bUninstall-(?:ADDS\w+|WindowsFeature)\b|\bMove-ADDirectoryServerOperationMasterRole\b"
                r"|\bDismount-(?:VHD|Volume|Database|Storage\w*)\b|\bRestore-VMSnapshot\b|\bReset-ComputerMachinePassword\b|\bDisable-(?:BitLocker|PnpDevice|PSRemoting|NetAdapterBinding)\b"
                r"|\bClear-RecycleBin\b|\bSet-MpPreference\b[^|;\n]{0,200}?-Disable\w+\s+\$?true\b|\bSet-NetFirewallProfile\b[^|;\n]{0,200}?-Enabled\s+\$?False\b"
                r"|\bDisable-NetFirewallRule\b|\bRemove-Item\s+[\"']?(?:Cert|HKLM|HKCU):", _I), "removes or disables part of the system"),
    (re.compile(r"\b(Disable-NetAdapter|Remove-NetIPAddress|Remove-NetRoute)\b|\bipconfig\s+/release\b|\broute\s+(?:-f\b|delete\s+(?:0\.0\.0\.0|\*))"
                r"|\bnetsh\s+advfirewall\b[^;&|\n]{0,200}?(?:\bstate\s+off\b|\breset\b|\bdelete\s+rule\s+name=all\b)|\bnetsh\s+firewall\s+set\s+opmode\s+disable\b"
                r"|\bnetsh\s+(?:interface|int)\b[^;&|\n]{0,200}?(?:\bdisabled?\b|\breset\b|\bset\s+address\b)|\bnetsh\s+winsock\s+reset\b"
                r"|\bnetsh\s+wlan\s+(?:delete\s+profile|disconnect)\b|\bnetsh\s+http\s+delete\b|\bwinrm\s+delete\b", _I), "network change"),
    (re.compile(r"\bRemove-AD\w+\b|\bnetdom\s+(?:remove|resetpwd)\b|\brepadmin\s+" + _WORDS + r"{0,4}?/removelingeringobjects\b|\bdnscmd\s+" + _WORDS
                + r"{0,4}?/(?:zonedelete|recorddelete)\b|\bntdsutil\b|\bnet1?\s+(?:user|group|localgroup|computer|session)\b[^;&|\n]{0,200}?\s/del(?:ete)?\b", _I),
     "Active Directory removal"),
    (re.compile(r"\b(Clear-EventLog|Remove-EventLog|wevtutil\s+(?:cl|clear-log))\b|\.ClearLog\s*\(|\bauditpol\s+/clear\b", _I), "event log clear"),
    (re.compile(r"\bnet1?\s+(?:stop|pause)\b|\bsc\s+(?:\\\\\S+\s+|//\S+\s+)?(?:stop|delete|pause)\b|\bwmic\b[^;&|\n]{0,300}?\b(?:call\s+(?:terminate|stopservice|uninstall|create)|delete)\b"
                r"|\b(?:logoff|rwinsta|tskill)\b|\breset\s+session\b|\bschtasks\b[^;&|\n]{0,200}?\s/(?:delete|end)\b", _I), "service stop"),
    # bcdedit alone, or with /enum or /v, only lists the boot entries
    (re.compile(r"\bbcdedit\b(?!\s*(?:$|[|;&)\n]|/enum\b|/v\b))|\bdiskpart\b", _I | re.M), "boot/disk configuration"),
    (re.compile(r"\breg\s+(?:delete|restore)\b", _I), "registry delete"),
    (re.compile(r"\btaskkill\b", _I), "process kill"),
    (re.compile(r"\brobocopy\b[^;&|\n]{0,400}?\s/(?:MIR|PURGE|MOVE?)\b", _I), "robocopy deleting files"),
    (re.compile(r"\bmsiexec\s+" + _WORDS + r"{0,4}?/(?:x|uninstall)\b|\bwusa\s+" + _WORDS + r"{0,4}?/uninstall\b|\bpnputil\s+/delete-driver\b|\bdevcon\s+(?:remove|disable)\b"
                r"|\bslmgr\S*\s+/upk\b|\bcertutil\s+" + _WORDS + r"{0,4}?-delstore\b|\bwsl\s+--(?:unregister|shutdown)\b|\bgpupdate\b[^;&|\n]{0,100}?/(?:boot|logoff)\b"
                r"|\b(?:icacls|takeown)\s[^;&|\n]{0,200}?(?:[a-z]:\\?\s[^;&|\n]{0,200}?/t\b|/r\b)|\b(?:assoc|ftype)\s+\.?(?:exe|bat|cmd|com|exefile|batfile|cmdfile)=", _I),
     "removes software or a part of Windows it needs"),
    # Network devices (Cisco IOS / NX-OS / Junos / MikroTik / FortiOS)
    (re.compile(r"^[ \t]*reload\b", _I | re.M), "device reload"),
    (re.compile(r"\b(write\s+erase|erase\s+(startup|nvram|flash))", _I), "config erase"),
    (re.compile(r"\bformat\s+(flash|disk|bootflash|usb)\S*", _I), "storage format"),
    (re.compile(r"\bdelete\s+/force\b", _I), "forced delete"),
    (re.compile(r"\brequest\s+system\s+(reboot|halt|power-off|zeroize)\b", _I), "device reboot/zeroize"),
    (re.compile(r"/system\s+(reboot|shutdown|reset-configuration)\b", _I), "device reboot/reset"),
    (re.compile(r"\bexecute\s+(reboot|shutdown|factoryreset|formatlogdisk)\b", _I), "device reboot/reset"),
]

# SQL that deletes or rewrites rows, looked for only where a database's own client runs it: the
# words are too ordinary to rate on their own (`drop table` and `truncate table`, above, are not)
_SQL_CLIENT = re.compile(r"\b(?:psql|mysql|mariadb|sqlcmd|osql|sqlite3|Invoke-Sqlcmd|cqlsh|influx|clickhouse-client|sqlplus|cockroach|duckdb|mongo(?:sh)?)\b", _I)
_SQL: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\bdelete\s+from\b|\bupdate\s+\S+\s+set\b|\btruncate\s+(?:only\s+)?\w|\bdrop\s*(?:/\*.*?\*/\s*)?(?:\s+if\s+exists)?\s*(?:database|table|schema|user|role|login|owned|keyspace"
                r"|measurement|index|view|tablespace)\b|\balter\s+(?:table|database)\b[^;]{0,200}?\b(?:drop|offline)\b|\bshutdown\b|\brestore\s+database\b"
                r"|\b(?:reset\s+master|purge\s+binary\s+logs)\b|\bpg_terminate_backend\b|\bto\s+program\b|\bxp_cmdshell\b", _I),
     "SQL that deletes, rewrites or shuts down"),
]

MODIFYING: list[tuple[re.Pattern, str]] = [
    # options may come before the verb, and the match stays within one command: no ; | & or quotes
    # (with quoted text blanked first, _SHELL_SYNTAX: `echo "not a flatpak/snap install"` installs nothing)
    (re.compile(r"\b(apt|apt-get|yum|dnf|zypper|pacman|snap|flatpak)\s+(?:[^\s;|&'\"()]+\s+){0,10}"
                r"(install|reinstall|remove|purge|upgrade|full-upgrade|dist-upgrade|update|refresh|autoremove|erase|downgrade|"
                r"-S(?![silgp]+\b)\w*|-R\w*|-U)(?![\w-])"), "package change"),
    (re.compile(r"\bpip3?\s+(install|uninstall)\b|\b(?:dpkg|rpm)\s+" + _WORDS + r"{0,4}?(?:-[a-zA-Z]*[irPeUF][a-zA-Z]*\b|--(?:install|remove|purge|erase|upgrade|configure)\b)"
                r"|\b(?:npm|yarn|pnpm|gem|cargo|brew|apk|choco|winget|scoop)\s+(?:i|install|add|remove|rm|uninstall|del|upgrade|update)\b"), "package change"),
    (re.compile(r"\bsystemctl\s+(?:(?!systemctl\b)[^\s;&|]+\s+){0,12}?(start|enable|reload|daemon-reload|daemon-reexec|edit|set-property|unmask|revert|reset-failed"
                r"|set-default|preset\S*|link|set-environment|import-environment|clean)(?![\w-])"), "service change"),
    (re.compile(r"\bsed\s+(?:-[^\s;&|]*\s+|'[^']{0,200}'\s+){0,8}?(?:-[a-zA-Z]*i|--in-place)"), "in-place file edit"),
    (re.compile(r"\btee\b"), "file write"),
    # to a file: `>`, `>>`, `>|`, `&>`, `>&file`, behind a descriptor's number or not (`2>/etc/x`); not
    # to another descriptor (`2>&1`) nor to nowhere (/dev/null, PowerShell's $null, cmd's nul)
    (re.compile(r"(?<![>&])(?:&>>?|>>?\|?(?!&)|>&(?=[^\d\s-]))\s*(?!(?:/dev/(?:null|stdout|stderr|tty)|\$null|nul)(?![\w.]))[^\s|&;>]", _I),
     "output redirect to file"),
    (re.compile(CMD + r"(mv|cp|rm|rmdir|chmod|chown|chgrp|mkdir|touch|ln|install|truncate)\b", re.M), "filesystem change"),
    (re.compile(_later(r"\bfind\b", r"\s-(?:fprint0?|fprintf|fls)\b")), "find writing a file"),
    (re.compile(r"\b(useradd|usermod|groupadd|groupmod|chpasswd|visudo)\b"), "account change"),
    # passwd is also a file (/etc/passwd) and a getent database, so only as the command itself
    (re.compile(CMD + r"passwd\b(?![.-])", re.M), "account change"),       # CMD takes a path (/usr/bin/passwd)
    (re.compile(r"\bgit\s+(commit|push|reset|checkout|merge|rebase|pull|clean|restore|stash|apply|am|cherry-pick|revert|clone|fetch|add|rm|mv|init|tag\s+-d)\b"), "repository change"),
    (re.compile(r"\b(?:docker|podman)\s+(rm|rmi|stop|restart|kill|run|start|pull|push|build|create|cp|compose\s+(up|down|restart))\b"), "container change"),
    (re.compile(r"\bkubectl\s+" + _WORDS + r"{0,6}?(apply|create|scale|rollout|patch|edit|label|annotate|cordon|uncordon|drain|set|expose|run|cp)\b"), "kubernetes change"),
    (re.compile(r"\b(ip\s+(addr|route|link)\s+(add|del|change|replace|set|flush)|ifdown|ifup"
                r"|nmcli\s+(con|connection|dev|device)\s+(up|down|modify|delete|add|disconnect|reapply)|nmcli\s+(networking|radio\s+\S+)\s+(on|off)"
                r"|ifconfig\s+\S+\s+(down|up)|route\s+(add|del|delete|change|flush)|(dhclient|dhcpcd)\s+(-\S+\s+)*-[rxk]|netplan\s+(?:apply|try))\b"), "network change"),
    # firewall tools, except when they only list rules
    (re.compile(r"\bip6?tables\b(?!-save\b)(?!(?:(?!ip6?tables\b)[^|;&\n])*\s(-[a-zA-Z]*[LS][a-zA-Z]*|--list(-rules)?)\b)"
                r"|\bnft\b(?!\s+(-\S+\s+){0,6}list\b)|\bufw\b(?!\s+(status|show|app\s+list)\b)"
                r"|\bfirewall-cmd\b(?!(\s+--(zone=\S+|permanent)){0,4}\s+--(state|get-\S+|list-\S+|query-\S+|info-\S+)\b)"),
     "firewall"),
    # mount alone, or with only -t/-l, lists what is mounted
    (re.compile(CMD + r"mount\b(?!\s*($|[|;&)]))(?!(\s+(-l|-t\s+\S+)){1,4}\s*($|[|;&)]))", re.M), "mount change"),
    (re.compile(r"\b(umount|swapoff|swapon)\b"), "mount change"),
    (re.compile(r"\bsysctl\s+" + _WORDS + r"{0,4}?(?:-w\b|--write\b|-p\b|--load\b|--system\b|[\w.]+=)"), "kernel parameter change"),
    (re.compile(CMD + r"eval\b", re.M), "eval"),
    (re.compile(r"\b(python[23]?|perl|ruby|node|php)\s+-[cer]\s", _I), "inline interpreter code"),
    (re.compile(CMD + r"(su|sudo\s+-i|sudo\s+su)\b(?!\S)", re.M), "switch user"),
    (re.compile(r"\bkill\b"), "signal process"),
    # anything but `crontab -l`: a table installed from a file or from what is piped in, or edited
    (re.compile(CMD + r"crontab\b(?!\s+(?:-u\s*\S+\s+)?-l\b)", re.M), "crontab change"),
    # PowerShell / Windows
    (re.compile(r"\b(?!(New-(Object|TimeSpan|Guid|PSSessionOption|CimSessionOption)|Start-Sleep|Clear-(Host|Variable)|"
                r"Set-(Variable|Location|StrictMode)|Add-Member)\b)"
                r"(Set|New|Add|Remove|Enable|Disable|Start|Install|Uninstall|Update|Rename|Move|Copy|Clear|Reset|Register|Unregister|Grant|Revoke|Restore)"
                r"-[A-Za-z][A-Za-z0-9]*\b", _I), "state-changing cmdlet"),          # a noun may hold digits: Remove-DhcpServerv4Scope
    (re.compile(r"\breg\s+(add|import|load|unload|restore|copy)\b|\bregedit\b|\bregini\b", _I), "registry change"),
    (re.compile(_later(r"\bnetsh\b", r"\b(set|add|delete|reset)\b"), _I), "network change"),
    (re.compile(r"\bipconfig\s+/(release|renew|flushdns|registerdns)\b", _I), "network change"),
    (re.compile(r"\bsc\s+(?:\\\\\S+\s+|//\S+\s+)?(config|stop|start|delete|create|failure|sdset|pause|continue)\b|\bnet1?\s+start\s+[^\s|;&]", _I), "service/account change"),
    # net user/localgroup/share on their own only list; these switches, a share=path or a password change things
    (re.compile(r"\bnet1?\s+(user|localgroup|group|share|accounts|use)\b[^|;&\n]{0,300}?(/(add|delete|del|active|expires|passwordreq|passwordchg|times|grant|remark|unlimited|users|cache"
                r"|maxpwage|minpwage|minpwlen|uniquepw|lockoutthreshold|persistent)\b|\s\S+=)"
                r"|\bnet1?\s+user\s+[^/\s|;&]\S*\s+[^/\s|;&]", _I), "service/account change"),
    (re.compile(r"\b(gpupdate|DISM|sfc\s+/scannow)\b|" + _later(r"\bchkdsk\b", r"/[frxb]\b"), _I), "system repair"),
    (re.compile(CMD + r"(?:robocopy|xcopy|copy|move|ren|rename|md|del|erase|mklink|setx|attrib|icacls|takeown|cacls|wusa|msiexec)\b", _I | re.M),
     "file or system change"),
    (re.compile(r"\bschtasks\s+/(?:create|change|run)\b", _I), "scheduled task change"),
    # Network devices
    (re.compile(r"^[ \t]*(conf(igure)?(\s+t(erminal)?)?|config\s+system)\b", _I | re.M), "configuration mode"),
    (re.compile(r"\b(write\s+mem(ory)?|copy\s+run(ning-config)?\s+start(up-config)?|commit)\b", _I), "config save/commit"),
    (re.compile(r"^[ \t]*clear\s+", _I | re.M), "clear counters/sessions"),
    (re.compile(r"^[ \t]*/\S*+[^\n]*?\s(set|add|remove|disable|enable)\b", _I | re.M), "RouterOS change"),
    (re.compile(r"^[ \t]*(no\s+)?shutdown[ \t]*$", _I | re.M), "interface shutdown"),
]


# Commands that cut the connection you are issuing them over. Keyed by session kind.
# (These are the classic self-inflicted outages of remote work.)
_SSH_CUTS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\bsystemctl\s+(\S+\s+){0,12}?(stop|restart|try-restart|disable|mask|kill)\s+(\S+\s+){0,12}?(ssh|sshd|openssh-server|networking|NetworkManager|network-manager|systemd-networkd|network|wicked|netbird|tailscaled|wg-quick@\S+)\b"), "stops or restarts the SSH/network service you are connected through"),
    # the targets and sleep states that end every login, by systemctl's own verbs
    (re.compile(r"\bsystemctl\s+(\S+\s+){0,12}?(isolate|rescue|emergency|suspend|hibernate|hybrid-sleep|suspend-then-hibernate|kexec|soft-reboot)\b"),
     "leaves the state this login runs in (rescue, sleep or a restart)"),
    (re.compile(r"\bservice\s+(ssh|sshd|networking|network|NetworkManager)\s+(stop|restart)\b"), "stops or restarts the SSH/network service you are connected through"),
    (re.compile(r"\b(pkill|killall)\s+(-\S+\s+){0,8}(sshd?|ssh-agent)\b"), "kills sshd"),
    # ip takes options before the object and any unambiguous start of a word: `ip l s eth0 down`,
    # `ip -4 a f dev eth0`, `ip r d default` (link's `s` is set, as iproute2 reads it)
    (re.compile(r"\bip\s+(?:-\S+\s+){0,8}l(?:i(?:nk?)?)?\s+s(?:et?)?\s+(?:dev\s+)?\S+\s+(?:[^\s;&|]+\s+){0,12}?down\b"), "brings an interface down"),
    (re.compile(r"\bip\s+(?:-\S+\s+){0,8}l(?:i(?:nk?)?)?\s+d(?:el(?:ete)?)?\s"), "removes an interface"),
    (re.compile(r"\bnetplan\s+(?:--\S+\s+){0,4}(apply|try)\b"), "reapplies the network configuration (a mistake in it takes the host off the network)"),
    (re.compile(r"\brfkill\s+block\s+(all|wifi|wlan)\b|\bnmcli\s+radio\s+(all|wifi|wwan)\s+off\b"), "turns the radio off"),
    (re.compile(r"\b(ifdown|nmcli\s+(dev|device|con|connection)\s+down|nmcli\s+(dev|device)\s+disconnect|ifconfig\s+\S+\s+down)\b"),
     "brings an interface down"),
    (re.compile(r"\bnmcli\s+networking\s+off\b"), "turns networking off"),
    (re.compile(r"\broute\s+(del|delete)\s+(default|0\.0\.0\.0)\b"), "removes the default route"),
    (re.compile(r"\b(dhclient|dhcpcd)\s+(-\S+\s+){0,8}-[rxk]\b"), "releases the DHCP lease"),
    (re.compile(r"\bip\s+(?:-\S+\s+){0,8}(?:a(?:d(?:d(?:r(?:e(?:ss?)?)?)?)?)?|r(?:o(?:u(?:te?)?)?)?)\s+(?:f(?:l(?:u(?:sh?)?)?)?|d(?:e(?:l(?:e(?:te?)?)?)?)?)\b"),
     "removes addresses or routes"),
    (re.compile(r"\b(iptables|ip6tables)\s+(\S+\s+){0,12}?(-P|--policy)\s+INPUT\s+DROP\b"), "default-drops inbound traffic"),
    (re.compile(r"\b(iptables|ip6tables)\s+(\S+\s+){0,12}?(-D|--delete)\s+INPUT\b"), "deletes an inbound rule, possibly the one that lets SSH in"),
    (re.compile(r"\b(iptables|ip6tables)\s+(\S+\s+){0,12}?-[AI]\s+INPUT\b(?![^\n]{0,400}?--dport\s+(?!22\b))(?=[^\n]{0,400}?-j\s+(DROP|REJECT))"), "drops inbound traffic, possibly including SSH"),
    (re.compile(r"\b(iptables|ip6tables)\s+(\S+\s+){0,12}?(-F|--flush)\b"), "flushes the firewall (default policy may drop SSH)"),
    (re.compile(r"\bnft\s+(-\S+\s+){0,8}(flush|delete)\s+(ruleset|table|chain)\b"), "flushes the firewall"),
    (re.compile(r"\bufw\s+(--\S+\s+){0,4}(enable|reset|(delete\s+(allow|limit)|deny|reject)\s+(\S+\s+){0,12}?(22|ssh|OpenSSH)\b|default\s+(deny|reject)\s+incoming)"),
     "may block SSH"),
    (re.compile(r"\bfirewall-cmd\b[^\n]{0,400}?--remove-(service=ssh|port=22/tcp)\b"), "removes the SSH firewall allowance"),
    (re.compile(r"\bfirewall-cmd\b[^\n]{0,400}?--panic-on\b"), "drops all traffic (panic mode)"),
    (re.compile(r"\bsed\s+(-\S+\s+){0,8}-i\b[^\n]{0,400}?\bsshd_config\b"), "edits sshd_config in place (a bad edit locks you out on restart)"),
    # the keys that let you in and the server's configuration, removed, moved away or written over
    (re.compile(r"\b(rm|mv|shred|unlink|truncate)\s[^;&|\n]{0,400}?(authorized_keys|sshd_config)\b"
                r"|(?<![>&])(?:&>>?|>>?\|?)\s*[^\s;&|]*(authorized_keys|sshd_config)\b|\btee\s[^;&|\n]{0,400}?(authorized_keys|sshd_config)\b"),
     "removes or rewrites the SSH keys or configuration that let you in"),
    (re.compile(r"\b(pkill|killall)\s+(-\S+\s+){0,8}-u\s*(\$USER|\$LOGNAME|\$\(whoami\)|\$\(id -un\))|\bkill\s+(-\S+\s+){0,8}(\$PPID|\$\$)(?!\w)"),
     "kills your own login's processes, this shell among them"),
    (re.compile(r"\b(usermod\s+-L|passwd\s+-l|chage\s+-E\s*0)\b[^\n]{0,400}?\b(root|\$USER)\b"), "locks the account you may be using"),
    (re.compile(r"\b(shutdown|reboot|poweroff|halt|init\s+[06]|telinit\s+[06])\b"), "reboots or halts the host"),
    (re.compile(r"\b(wg-quick\s+down|tailscale\s+down|openvpn\b[^\n]{0,400}?--rmtun|ipsec\s+(stop|down))\b"), "tears down the VPN this session may traverse"),
]
_WINRM_CUTS: list[tuple[re.Pattern, str]] = [
    # the service named before the cmdlet too (`Get-Service WinRM | Restart-Service`), by alias, or
    # stopped through Set-Service
    (re.compile(r"\b(Stop-Service|Restart-Service|spsv)\b[^\n]{0,400}?\bWinRM\b|\bWinRM\b[^;\n]{0,400}?\|\s*(Stop-Service|Restart-Service|spsv)\b"
                r"|\bSet-Service\b[^|;\n]{0,400}?\bWinRM\b[^|;\n]{0,400}?\b(Stopped|Disabled)\b", _I), "stops or restarts WinRM, which carries this session"),
    (re.compile(r"\b(Stop-Process|spps|kill|taskkill(\.exe)?)\b[^\n]{0,400}?\bwsmprovhost\b", _I), "kills the WinRM host process this session runs in"),
    (re.compile(r"\bSet-Item\b[^\n]{0,400}?\bWSMan:|\bwinrm(\.cmd)?\s+set\b", _I), "changes the WinRM configuration this session depends on"),
    (re.compile(r"\bSet-NetConnectionProfile\b[^\n]{0,400}?-NetworkCategory\s+Public\b", _I),
     "makes the network Public, where the firewall keeps WinRM out by default"),
    (re.compile(r"\b(Disable|Restart)-NetAdapter\b", _I), "disables or restarts a network adapter"),
    (re.compile(r"\b(Disable-PSRemoting|winrm\s+delete|Remove-Item\b[^\n]{0,400}?\bWSMan:)", _I), "disables PowerShell remoting"),
    (re.compile(r"\bSet-NetFirewallProfile\b[^\n]{0,400}?-DefaultInboundAction\s+Block|\bnetsh(\.exe)?\s+advfirewall\b[^\n]{0,400}?\bblockinbound", _I),
     "blocks inbound traffic by default"),
    (re.compile(r"\b(Disable-NetFirewallRule|Remove-NetFirewallRule)\b[^\n]{0,400}?(\bWinRM\b|Windows Remote Management|\b5985\b|\b5986\b)"
                r"|\bnetsh(\.exe)?\s+advfirewall\b[^\n]{0,400}?(Windows Remote Management|winrm)[^\n]{0,400}?\b(enable=no|delete)\b", _I), "removes the WinRM firewall rule"),
    (re.compile(r"\b(Disable-NetFirewallRule|Remove-NetFirewallRule)\s+(-\w+\s+\S+\s+){0,6}-All\b", _I), "disables or removes every firewall rule"),
    (re.compile(r"\bNew-NetFirewallRule\b[^\n]{0,400}?-Direction\s+Inbound\b[^\n]{0,400}?-Action\s+Block", _I), "adds an inbound block rule"),
    (re.compile(r"\b(Remove-NetIPAddress|Remove-NetRoute|New-NetIPAddress|Set-NetIPAddress|Set-NetIPInterface\b[^\n]{0,400}?-Dhcp\s+Disabled)"
                r"|\bnetsh(\.exe)?\s+(interface|int)\s+(ip|ipv4|ipv6)\s+set\s+address\b", _I), "changes the addressing this session depends on"),
    # shutdown's switches with a slash or a dash (/r, -r, /s, /h, /g, /p, /sg, /fw, /o), not /a (abort) nor /l (log off)
    (re.compile(r"\b(Restart-Computer|Stop-Computer)\b|\bshutdown(\.exe)?\s+(?:[/-]\S+\s+){0,8}[/-](?:r|s|h|g|p|sg|fw|o)\b", _I), "reboots or halts the host"),
    (re.compile(r"\bwmic(\.exe)?\b[^\n]{0,400}?\bos\b[^\n]{0,400}?\bcall\s+(reboot|shutdown|win32shutdown)\b"
                r"|\bWin32_OperatingSystem\b[^\n]{0,400}?\b(Reboot|Shutdown|Win32Shutdown)\b", _I), "reboots or halts the host"),
    # a cmdlet told to restart the host when it is done (Rename-Computer, Add-Computer, Install-WindowsFeature...)
    (re.compile(r"\b[A-Za-z]+-[A-Za-z0-9]+\b[^|;\n]{0,400}?\s-(Restart|AutoReboot|ForceReboot)\b(?!:\s*\$false)", _I), "restarts the host when it has finished"),
    (re.compile(r"\bipconfig\s+/release\b", _I), "releases the DHCP lease"),
    (re.compile(r"\bnetsh\s+(interface|int)\b[^\n]{0,400}?\b(disable|disabled)\b", _I), "disables an interface"),
    (re.compile(r"\bnet1?(\.exe)?\s+stop\s+winrm\b", _I), "stops WinRM"),
    (re.compile(r"\bsc(\.exe)?\s+stop\s+winrm\b", _I), "stops WinRM"),
]
_NETDEV_CUTS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"^[ \t]*reload\b", _I | re.M), "reloads the device"),
    (re.compile(r"^(?![ \t]*(do\s+)?(show|sh)\b)[^\n]*\b(no\s+)?(ip\s+ssh|line\s+vty|transport\s+input)\b", _I | re.M),
     "changes vty/SSH access"),
    (re.compile(r"^[ \t]*shutdown[ \t]*$", _I | re.M), "shuts the interface you may be connected through"),
    (re.compile(r"\b(no\s+ip\s+address|no\s+ip\s+route|no\s+interface)\b", _I), "removes addressing or routing"),
    (re.compile(r"\b(write\s+erase|erase\s+startup)", _I), "erases the configuration"),
    (re.compile(r"/system\s+(reboot|reset-configuration)|/ip\s+service\s+(disable|set)[^\n]{0,400}?ssh|/ip\s+firewall\s+filter\s+(remove|add\s+[^\n]{0,400}?action=drop)", _I), "cuts management access"),
]


# Typed into a window on a remote desktop: the network-wide WinRM rules apply, plus the
# ways to lose the desktop itself.
_RDP_CUTS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\b(Stop|Restart)-Service\b[^\n]{0,400}?\b(TermService|UmRdpService)\b", _I), "stops Remote Desktop Services, which carries this session"),
    (re.compile(r"\bnet\s+stop\s+termservice\b|\bsc(\.exe)?\s+stop\s+termservice\b", _I), "stops Remote Desktop Services"),
    (re.compile(r"\b(logoff|tsdiscon|shutdown\s+/l)\b", _I), "logs off or disconnects this desktop session"),
    (re.compile(r"fDenyTSConnections\b[^\n]{0,400}?\b1\b", _I), "disables Remote Desktop connections"),
    (re.compile(r"\b(Disable-NetFirewallRule|Remove-NetFirewallRule)\b[^\n]{0,400}?\b(RemoteDesktop|Remote Desktop|3389)\b", _I), "removes the Remote Desktop firewall rule"),
] + [r for r in _WINRM_CUTS if "WinRM" not in r[1] and "remoting" not in r[1]]


# Pasted into a remote-support tool's window (ScreenConnect, TeamViewer, AnyDesk...): the
# network rules apply, plus stopping the tool's own agent and ending the desktop session.
_REMOTE_AGENTS = r"(ScreenConnect|ConnectWise|TeamViewer|AnyDesk|Splashtop|RustDesk|ITSPlatform|LMIGuardian|LogMeIn|Bomgar|BeyondTrust|DWAgent)"
_WINDOW_CUTS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\b(Stop|Restart)-Service\b[^\n]{0,120}?" + _REMOTE_AGENTS, _I), "stops the remote-support agent this session runs through"),
    (re.compile(r"\b(net|sc(\.exe)?)\s+stop\b[^\n]{0,120}?" + _REMOTE_AGENTS, _I), "stops the remote-support agent this session runs through"),
    (re.compile(r"\b(taskkill|Stop-Process|kill|pkill|killall)\b[^\n]{0,120}?" + _REMOTE_AGENTS, _I), "kills the remote-support agent this session runs through"),
    (re.compile(r"\b(Uninstall-Package|msiexec\s+/x|wmic\b[^\n]{0,400}?\buninstall)\b[^\n]{0,120}?" + _REMOTE_AGENTS, _I), "uninstalls the remote-support agent"),
    (re.compile(r"\b(logoff|tsdiscon|shutdown\s+/l)\b", _I), "logs off or disconnects this desktop session"),
] + [r for r in _WINRM_CUTS if "WinRM" not in r[1] and "remoting" not in r[1]]


# ---------------------------------------------------------------------------------------
# The allow-list: whether a command only reads.
#
# The command is read the way a shell would read it, into commands, their words and what the
# words nest, and every command in it has to be one the tables below know, in a form that
# reads. The rules don't know which shell will get the line (a POSIX shell, PowerShell,
# cmd.exe, a switch's console), so they keep to what means the same in all of them and give
# up on the rest: anything given up on is "not confirmed", which costs a confirmation and
# nothing more. What can't be confirmed, by design:
#   - a command the tables don't name, or name only in other forms (`sed -i`, `ip link set`);
#   - output sent to a file; a here-document; a backtick; `$'...'`;
#   - a backslash before a quote, a space or an operator, which a POSIX shell and PowerShell
#     read differently (`echo a\; reboot` prints in one and reboots in the other);
#   - a command named by a variable, a quoted string or a path outside the system's own;
#   - an expansion where it could turn into an option of a command that has dangerous ones;
#   - an interpreter or a shell given code the rules can't read (`python -c`, a script file).
# What a shell runs from inside a word is read too and must pass on its own: `$(...)`,
# `<(...)`, `bash -c '...'`, `ssh host ...`, find's -exec, a PowerShell script block.

class _No(Exception):
    """Not something the allow-list can confirm."""


class _Open(_No):
    """A quote that never closes, in this reading of the quotes."""


class _W:
    """One word of a command. `s` is its text without quotes and escapes, an expansion's or a
    group's place held by \\0; `raw` is the word as written (a group as `()` or `{}`); `plain`
    when nothing in it is quoted, escaped or expanded; `lead` says what it starts with ("lit",
    "str", "var", "paren", "brace", "hash"); `exps` are its expansions, as (name or None,
    quoted, at the word's start, known harmless); `groups` what it nests, to be checked."""
    __slots__ = ("s", "raw", "plain", "lead", "exps", "groups")

    def __init__(self, s: str = "", raw: str | None = None) -> None:
        self.s, self.raw, self.plain, self.lead = s, s if raw is None else raw, True, "lit" if s else ""
        self.exps: list[tuple] = []
        self.groups: list[tuple] = []


class _Build:
    """The commands read so far at one level of nesting: a script is a list of pipelines, a
    pipeline a list of stages, a stage its words and the words its input comes from."""
    __slots__ = ("script", "pipe", "words", "side", "cur", "pending", "ended", "joined", "called")

    def __init__(self) -> None:
        self.script, self.pipe, self.words, self.side = [], [], [], []
        self.cur: _W | None = None
        self.pending = ""            # ">" or "<": the next word is a redirect's target
        self.ended = False           # find's `\;` was read: nothing more may belong to this command
        self.joined = False          # the line ends in a backslash: a POSIX shell reads the next line as more arguments
        self.called = False          # the command follows a single `&`: PowerShell's call operator

    def lit(self, text: str, raw: str | None = None, plain: bool = True, lead: str = "lit") -> _W:
        w = self.cur
        if w is None:
            w = self.cur = _W()
            w.lead = lead
        w.s += text
        w.raw += text if raw is None else raw
        if not plain:
            w.plain = False
        return w

    def word(self) -> None:
        w, self.cur = self.cur, None
        if w is None:
            return
        if self.pending == ">":
            if w.raw.lower() not in _NOWHERE:
                raise _No
        elif self.pending == "<":
            self.side.append(w)
        elif self.ended:
            raise _No
        else:
            self.words.append(w)
        self.pending = ""

    def stage(self) -> None:
        self.word()
        if self.pending:
            raise _No
        for flag in ("joined", "called"):
            if getattr(self, flag):
                mark = _W()
                mark.lead = flag
                self.side.append(mark)
        self.pipe.append((self.words, self.side))
        self.words, self.side, self.ended, self.joined, self.called = [], [], False, False, False

    def pipeline(self) -> None:
        self.stage()
        self.script.append(self.pipe)
        self.pipe = []


_NOWHERE = {"/dev/null", "$null", "nul", "nul:", "/dev/stdout", "/dev/stderr"}
_PLAIN = re.compile(r"[^\s'\"\\`$;&|<>(){}#!]+")
_DQ_PLAIN = re.compile(r"[^\"\\`$!]+")
_VAR = re.compile(r"(?:[A-Za-z_]\w*:)?[A-Za-z_]\w*|[0-9]+|[?$!#@*_-]")
_ARITH = re.compile(r"[\w \t+\-*/%()<>=!&|^~?:,.$]*")
_NAMES = re.compile(r"[A-Za-z_]\w*")
# ${...} in the forms that only read a variable: its value or length, an element by number, a default, a prefix
# or suffix cut off, a replacement, a change of case, a slice by numbers. Not ${!name} nor a subscript or an
# offset that is an expression: bash evaluates those, and what they name, as arithmetic, which can run a command.
_BRACED = re.compile(r"#?(?:(?:(?:env|global|script|local|private|using):)?[A-Za-z_]\w*|\d+|[@*?$#-])(?:\[(?:[@*]|\d+)\])?(?:(?::?[-+=?]|##?|%%?|//?)[^}]*|\^\^?|,,?|:\d+(?::\d+)?)?")
_FD = re.compile(r"\d+|-")
_CALL = re.compile(r"(?:\.|::)([A-Za-z_]\w*)$")
_ESCAPED_OK = set("\\/._-:+,@%=~*?[]^!")
_CMD_OPS = re.compile(r"[&|<>]")
_BRACE_BAD = re.compile(r"[\s;&|<>()$`'\"\\]")
_DASHED_LINE = re.compile(r"\s*(?:-[^;&|`$()<>\n]*|\|[^;&`$()<>\n]*)")    # (or with a `|`, which it would refuse to read)
_BEFORE_PAREN = {"if", "elseif", "while", "foreach", "for", "switch", "until"}
_BEFORE_BRACE = {"else", "try", "finally", "do", "catch"}
# find's \( ... \): parentheses as words to a POSIX shell; to PowerShell a group, which would run a
# command that started it. Accepted when what starts it is an option or a number, which run nothing.
_ESCAPED_PAREN = re.compile(r"\\\(\s*(?:[-!]|\d+\\\))")


class _Lexer:
    """Reads a command into scripts of pipelines of stages of words. `bs` says how a backslash
    inside double quotes is read: as a POSIX shell's escape, or (False) as the plain character
    it is to PowerShell and cmd.exe, where `\\"` ends the string."""

    def __init__(self, text: str, bs: bool, parent: "_Lexer | None" = None) -> None:
        self.t, self.bs = text, bs
        self.depth = parent.depth if parent else 0
        self.ambiguous = False
        self.quoted: list[str] = []          # what stood in single quotes, for cmd.exe's reading of them

    def script(self, i: int, close: str) -> tuple[list, int]:
        t, n, b = self.t, len(self.t), _Build()
        self.depth += 1
        if self.depth > 24:
            raise _No
        while i < n:
            m = _PLAIN.match(t, i)
            if m:
                b.lit(m.group())
                i = m.end()
                continue
            c = t[i]
            if c in " \t\r":
                b.word()
                i += 1
            elif c == "\n":
                b.pipeline()
                i += 1
            elif c == "'":
                j = t.find("'", i + 1)
                if j < 0:
                    raise _Open
                self.quoted.append(t[i + 1:j])
                b.lit(t[i + 1:j], t[i:j + 1], plain=False, lead="str")
                i = j + 1
            elif c == '"':
                i = self._dq(b, i)
            elif c == "\\":
                i = self._backslash(b, i)
            elif c == "$":
                i = self._dollar(b, i, False)
            elif c == "`":
                # PowerShell's escape, which at a line's end joins the next line on; a POSIX shell's command
                # substitution, up to the next backtick. Read each way (the reading the command isn't written
                # for must at least be harmless): for a POSIX shell, lines joined on like this are
                # "commands" that start with a dash, which it would not find
                self.ambiguous = True
                if not self.bs:
                    if t[i + 1:i + 2] != "\n":
                        raise _No
                    b.word()
                    i += 2
                else:
                    j = t.find("`", i + 1)
                    if j < 0:
                        raise _Open
                    if not _DASHED_LINE.fullmatch(t, i + 1, j):
                        raise _No
                    b.word()
                    i = j + 1
            elif c == "!":
                i = self._bang(b, i, False)
            elif c == "#":
                if b.cur is None:            # a comment, to a POSIX shell and PowerShell; cmd.exe would read on
                    j = t.find("\n", i)
                    j = n if j < 0 else j
                    if _CMD_OPS.search(t, i, j):
                        raise _No
                    i = j
                else:
                    b.lit("#")
                    i += 1
            elif c == ";":
                if t.startswith(";;", i):
                    raise _No
                b.pipeline()
                i += 1
            elif c == "&":
                if t.startswith("&&", i):
                    b.pipeline()
                    i += 2
                elif t.startswith("&>", i):
                    b.word()
                    i = self._redirect(b, i + 1)
                else:                            # the next command starts here; to PowerShell, `&` calls what follows
                    b.pipeline()
                    b.called = True
                    i += 1
            elif c == "|":
                if t.startswith("||", i):
                    b.pipeline()
                    i += 2
                else:
                    b.stage()
                    i += 2 if t.startswith("|&", i) else 1
            elif c == ">":
                i = self._redirect(b, i)
            elif c == "<":
                if t.startswith("<(", i):                # stands for a file's name: one word, no option
                    inner, i = self.script(i + 2, ")")
                    self._exp(b, None, False, "()", safe=True).groups.append(("sub", inner))
                elif t.startswith("<<<", i):
                    b.word()
                    b.pending, i = "<", i + 3
                elif t.startswith("<<", i) or t.startswith("<#", i):
                    raise _No
                else:
                    if b.cur is not None and b.cur.plain and b.cur.raw.isdigit():
                        b.cur = None
                    b.word()
                    if b.pending:
                        raise _No
                    b.pending, i = "<", i + (2 if t.startswith("<&", i) else 1)
            elif c == "(":
                w = b.cur
                if w is not None and w.plain and w.raw.lower() in _BEFORE_PAREN:
                    b.word()                     # if(...), foreach(...): PowerShell's keywords need no space
                    w = None
                if w is None or w.raw.endswith(("@", "=", ",", "(", "]", "!", "/", "*", "+", "-", "%")):
                    inner, i = self.script(i + 1, ")")
                    w = b.lit("\0", "()", plain=False, lead="paren")
                    w.groups.append(("paren", inner))
                else:
                    m = _CALL.search(w.raw)      # .Name( or ::Name( is a method; name( is a function being defined
                    if not m:
                        raise _No
                    inner, i = self.script(i + 1, ")")
                    w.groups.append(("call", m.group(1), inner))
                    b.lit("\0", "()", plain=False)
            elif c == ")" or c == "}":
                if close != c:
                    raise _No
                b.pipeline()
                self.depth -= 1
                return b.script, i + 1
            elif c == "{":
                w = b.cur
                if t.startswith("{}", i):
                    b.lit("{}")
                    i += 2
                elif w is None or w.raw in ("%", "?") or w.raw.endswith(("@", "=", ",", "(", ")")) or (w.plain and w.raw.lower() in _BEFORE_BRACE):
                    kind = "hash" if w is not None and w.raw.endswith("@") else "brace"
                    if w is not None and (w.raw in ("%", "?") or w.raw.endswith(")") or w.raw.lower() in _BEFORE_BRACE):
                        b.word()                 # `%{`, `){`, `else{`: the block is a word of its own
                    spaced = t[i + 1:i + 2] in (" ", "\t", "\n")
                    inner, i = self.script(i + 1, "}")
                    b.lit("\0", "{}", plain=False, lead=kind).groups.append((kind, inner, spaced))
                    if i < n and (t[i].isalnum() or t[i] in "{("):
                        b.word()                 # `}else{`
                else:                            # inside a word: a{b,c} or x{1..3}, plain text to every shell
                    j = t.find("}", i)
                    if j < 0 or _BRACE_BAD.search(t, i, j):
                        raise _No
                    w = b.lit(t[i:j + 1])
                    if "," in t[i:j] or ".." in t[i:j]:
                        w.exps.append((None, False, True, False))    # bash makes several words of it, any of which may be an option
                    i = j + 1
            else:                                # nothing _PLAIN leaves out is unhandled; kept for safety
                raise _No
        if close:
            raise _No
        b.pipeline()
        self.depth -= 1
        return b.script, i

    def _exp(self, b: _Build, name: str | None, quoted: bool, raw: str, safe: bool = False) -> _W:
        at_start = b.cur is None or b.cur.raw in ('"', "")
        w = b.lit("\0", raw, plain=False, lead="var" if name is not None else "sub")
        w.exps.append((name, quoted, at_start, safe))
        return w

    def _dq(self, b: _Build, i: int) -> int:
        t, n, k = self.t, len(self.t), i + 1
        b.lit("", '"', plain=False, lead="str")
        while k < n:
            m = _DQ_PLAIN.match(t, k)
            if m:
                b.lit(m.group(), plain=False)
                k = m.end()
                continue
            c = t[k]
            if c == '"':
                b.cur.raw += '"'
                return k + 1
            if c == "\\":
                nx = t[k + 1:k + 2]
                if nx == '"':
                    self.ambiguous = True
                if not self.bs:
                    b.lit("\\", plain=False)
                    k += 1
                elif not nx:
                    raise _Open
                else:
                    b.lit(nx if nx in '"$`\\' else "" if nx == "\n" else "\\" + nx, "\\" + nx, plain=False)
                    k += 2
            elif c == "!":
                k = self._bang(b, k, True)
            elif c == "`":                       # a command to a POSIX shell, an escape to PowerShell
                self.ambiguous = True
                if self.bs:
                    raise _No if t.find("`", k + 1) >= 0 else _Open
                b.lit(t[k + 1:k + 2], t[k:k + 2], plain=False)
                k += 2
            else:
                k = self._dollar(b, k, True)
        raise _Open

    def _dollar(self, b: _Build, i: int, quoted: bool) -> int:
        t = self.t
        nx = t[i + 1:i + 2]
        if nx == "(":
            if t.startswith("$((", i):
                j = t.find("))", i)
                if j < 0 or not _ARITH.fullmatch(t, i + 3, j) or "$(" in t[i + 3:j]:
                    raise _No
                # the variables it names are evaluated as arithmetic themselves, to any depth: _Check.inert
                self._exp(b, None, quoted, t[i:j + 2], safe=True).groups.append(("arith", _NAMES.findall(t, i + 3, j)))
                return j + 2
            w = self._exp(b, None, quoted, "$()")
            inner, j = self.script(i + 2, ")")
            w.groups.append(("sub", inner))
            return j
        if nx == "{":
            j = t.find("}", i)
            if j < 0 or "$(" in t[i + 2:j] or "`" in t[i + 2:j] or not _BRACED.fullmatch(t, i + 2, j):
                raise _No
            m = _VAR.match(t, i + 2)
            self._exp(b, m.group() if m and m.end() == j else "?", quoted, t[i:j + 1])
            return j + 1
        if (nx in ("'", '"') and not quoted) or nx == "[":
            raise _No                            # $'...' has escapes of its own; $[...] is arithmetic
        m = _VAR.match(t, i + 1)
        if not m:
            b.lit("$", plain=not quoted)         # a lone $: the end of a pattern, a prompt
            return i + 1
        self._exp(b, m.group(), quoted, t[i:m.end()])
        return m.end()

    def _bang(self, b: _Build, i: int, quoted: bool) -> int:
        """`!`: bash, at a terminal, rewrites the line from its history before running it. `!!`, `!-2`, `!ssh`
        bring back whole commands; `!$` and `!*` their words, which is an expansion like any other."""
        nx = self.t[i + 1:i + 2]
        if nx.isalnum() or nx in ("!", "?") or (nx == "-" and self.t[i + 2:i + 3].isdigit()):
            raise _No
        w = b.lit("!", plain=not quoted)
        if nx and nx in "$*^:":
            w.exps.append((None, quoted, w.raw == "!", False))
            w.plain = False
        return i + 1

    def _backslash(self, b: _Build, i: int) -> int:
        nx = self.t[i + 1:i + 2]
        if nx == ";":                            # ends find's -exec for a POSIX shell; PowerShell ends the command here
            b.word()
            b.lit(";", "\\;", plain=False)
            b.word()
            b.ended = True
            return i + 2
        if nx.isalnum() or nx in _ESCAPED_OK:    # the same character to every shell, or a Windows path's separator
            b.lit(nx, "\\" + nx, plain=False)
            return i + 2
        if not nx or nx in " \t":                # `dir C:\ /s`: the end of a Windows path. A POSIX shell would join the
            b.lit("\\", plain=False)             # next word on; read apart, each word is checked for what it could be
            return i + 1
        if nx == ")" or (nx == "(" and _ESCAPED_PAREN.match(self.t, i)):
            b.lit(nx, "\\" + nx, plain=False)
            return i + 2
        if nx == "\n":
            # a POSIX shell joins the next line on as more arguments; PowerShell and cmd.exe start a new
            # command there. So the next line must pass as a command of its own, and this one must be a
            # command that reads whatever its arguments (_Check.command, `joined`)
            if b.cur is not None:
                b.lit("\\", plain=False)
            b.joined = True
            b.pipeline()
            return i + 2
        raise _No

    def _redirect(self, b: _Build, i: int) -> int:
        t, w = self.t, b.cur
        if w is not None and w.plain and (w.raw.isdigit() or w.raw == "*"):
            b.cur = None                         # the descriptor's number (2>, PowerShell's *>)
        else:
            b.word()
        if b.pending:
            raise _No
        i += 1
        if t.startswith(">", i):
            i += 1
        if t.startswith("|", i):
            i += 1
        if t.startswith("(", i):
            raise _No
        if t.startswith("&", i):
            m = _FD.match(t, i + 1)              # >&2, >&-: to another descriptor, no file
            if m:
                return m.end()
            i += 1
        b.pending = ">"
        return i


# Variables whose values the system sets and that hold one word that is no option.
_AMBIENT = {"HOME", "USER", "LOGNAME", "HOSTNAME", "UID", "EUID", "PPID", "RANDOM", "SECONDS", "$", "?", "!", "#"}
_AMBIENT_PS = {"null", "true", "false", "env:computername", "env:username", "env:userdomain", "env:userdnsdomain",
               "env:temp", "env:tmp", "env:systemroot", "env:windir", "env:systemdrive", "env:programfiles", "env:programdata",
               "env:userprofile", "env:appdata", "env:localappdata", "env:logonserver", "env:homedrive", "env:homepath"}
# Variables PowerShell defines itself, which a statement may begin with in any session: a POSIX shell
# holds nothing under these names unless a line set it, and no line confirmed as read-only does (assign).
_PS_OWN_NAMES = {"env", "psversiontable", "host", "error", "pshome", "psculture", "psuiculture", "psedition", "iswindows",
                 "islinux", "ismacos", "true", "false", "null", "myinvocation", "executioncontext", "psscriptroot",
                 "pscommandpath", "psboundparameters", "args", "input", "matches", "foreach", "this", "_"}
_PS_OWN_VAR = re.compile(r"(?i)^\$(?:env:[A-Za-z_(][\w()]*|\{env:[^}]+\}|(?:" + "|".join(sorted(n for n in _PS_OWN_NAMES if n not in ("env", "_")))
                         + r")(?![\w:])|_[.\[])")
# Variables that change what a later command runs or loads: never set by a command confirmed as read-only.
_RISKY_VAR = re.compile(r"(?i)^(?:PATH|IFS|ENV|HOME|SHELL|TERMINFO|TMPDIR|CDPATH|GLOBIGNORE|CLASSPATH|DISPLAY|NETRC|WGETRC|INPUTRC|ZDOTDIR|FPATH|PSModulePath|PATHEXT|COMSPEC"
                        r"|PS\d|PROMPT_COMMAND|EDITOR|VISUAL|BROWSER|\w*PAGER|MAN\w*|LESS\w*|LD_\w+|DYLD_\w+|BASH_\w+|PYTHON\w*|PERL\w*|RUBY\w*|NODE_\w+|GIT_\w+"
                        r"|KUBE\w+|DOCKER_\w+|AWS_\w+|AZURE_\w+|GOOGLE_\w+|SSH_\w+|RSYNC_\w+|SUDO_\w+|SYSTEMD_\w+|DBUS_\w+|XDG_\w+|HIST\w+|GREP_\w+|JAVA_\w+|_JAVA\w+"
                        r"|ANSIBLE_\w+|TF_\w+|HELM_\w+|CURL_\w+|OPENSSL_\w+|SSL_\w+|REQUESTS_\w+|GNUPGHOME|POSIXLY_CORRECT|\w*_proxy)$")
_ASSIGN = re.compile(r"([A-Za-z_]\w*)\+?=")
_SAFE_VALUE = re.compile(r"[\w./:@%+,~][\w./:@%+,~=-]*|")
_TYPE = r"\[[\w.]+(?:\[[\w., ]*\])?\]"              # [type], [type[]], [type[a,b]]
_PS_ASSIGN = re.compile(r"(?:" + _TYPE + r")?\$((?:[A-Za-z_]\w*:)?\w+)\s*(?:[-+*/%]|\?\?)?=(?!=)")
_STATIC_CALL = re.compile(r"(?:" + _TYPE + r")*+\[([\w.]+)\]::\w+\(\)")
_PS_MEMBER_SET = re.compile(r"\$[\w:]+(?:\.\w+|\[[^\]]*\]|::\w+)+(?:[-+*/%]|\?\?)?=(?!=)")
_PS_TARGET = re.compile(r"(?:" + _TYPE + r")?\$((?:[A-Za-z_]\w*:)?\w+)")
# a number at a word's start (5, 1.5, 500MB, 0x1F, then perhaps `,` or `..`): PowerShell reads `7z` as a command
_NUMBER = re.compile(r"(?:\d+(?:\.\d+)?(?:[kmgtp]b)?|0x[0-9a-f]+)(?![\w.])|\d+\.\.", _I)
_SENTENCE = re.compile(r"[\s:;,=()\[\]{}<>|&*?!'\"]")
_PLAIN_NAME = re.compile(r"[A-Za-z_]\w*")
_ASSIGN_OPS = {"=", "+=", "-=", "*=", "/=", "%=", "??="}
_TYPE_LED = re.compile(r"(?:" + _TYPE + r")++(?:::[A-Za-z_]|[$(@'\"]|$)")
_PS_OPS = {p + op for op in ("eq", "ne", "gt", "ge", "lt", "le", "like", "notlike", "match", "notmatch", "contains", "notcontains", "in", "notin",
                             "replace", "split") for p in ("-", "-c", "-i")} | {"-and", "-or", "-xor", "-not", "-band", "-bor", "-bxor", "-shl", "-shr",
                                                                                 "-is", "-isnot", "-as", "-join", "-f", "+", "-", "*", "/", "%", "..", ","}
_KEYWORDS = {"for", "foreach", "while", "until", "if", "elif", "elseif", "else", "then", "do", "done", "fi", "try", "catch", "finally", "break",
             "continue", "case", "esac", "function", "switch", "return", "exit", "param", "trap"}
_STD_DIR = re.compile(r"(?:/usr(?:/local)?)?/s?bin/(?=[^/]+$)|(?:[A-Za-z]:\\Windows|%SystemRoot%|%windir%)\\(?:System32|Sysnative|SysWOW64)\\"
                      r"(?:wbem\\|WindowsPowerShell\\v1\.0\\|OpenSSH\\)?(?=[^\\/]+$)", _I)
_CMDLET = re.compile(r"[A-Za-z]+-[A-Za-z][A-Za-z0-9]*")
# cmd.exe doesn't know single quotes: `echo 'a & del /q x'` deletes there. A quoted text is given up
# on when what follows an & or a | in it is, read as a command with arguments, one the deny-list rates.
_PROGRAM_PATH = re.compile(r"[\\/%]|\.(?:exe|bat|cmd|com|ps1|vbs|msi)$", _I)
_CMD_SPLIT = re.compile(r"[&|]\s*(?=[A-Za-z\\.%\"][^\s&|]*\s+\S)")


class _Check:
    """Goes through a parsed command and raises _No at the first thing that is not known to read.
    Keeps what it learns on the way about which shell the line is written for: a line that needs
    both a POSIX shell's and PowerShell's reading, or a device's and a shell's, is given up on."""

    def __init__(self, lexer: _Lexer, powershell: bool = False) -> None:
        self.lexer = lexer
        # the line is for a session that is PowerShell's and nothing else's (WinRM): see expression
        self.powershell = powershell
        self.ps = self.posix = self.device = False
        self.safe = set(_AMBIENT)                # variables known to hold one word that is no option
        self.oneword: set[str] = set()           # a for loop's: one word each time round, though it may start with a dash
        self.pings: set[str] = set()             # PowerShell variables this command set to a new Ping object
        self.joined = False
        self.depth = 0

    # ---- scripts, statements

    def script(self, script: list, inblock: bool = False, lenient: bool = False) -> None:
        self.depth += 1
        if self.depth > 40:
            raise _No
        for idx, pipe in enumerate(script):
            before = ""
            for k, (words, side) in enumerate(pipe):
                for w in side:
                    self.inert(w)
                self.joined = any(w.lead == "joined" for w in side)
                if words and any(w.lead == "called" for w in side) and not (
                        (words[0].lead == "lit" and words[0].plain) or (words[0].lead == "brace" and len(words) == 1)):
                    raise _No                    # & (...) or & $x or & "path": PowerShell runs whatever that comes to
                # A script block given to a command is so many words to a POSIX shell, but only up to the first
                # `;`, `|` or line break in it: what follows is a command of its own there, and
                # `... | ForEach-Object { $a; "reboot" }` reboots. So only a block's first statement is read as
                # PowerShell's alone; the later ones are read as strictly as a line of their own
                later = (inblock or lenient) and (idx > 0 or k > 0)
                before = self.stage(words, before, inblock and not later, lenient and not later, later) or before
                self.joined = False
        self.depth -= 1

    def text(self, text: str) -> None:
        """Text that a shell will read again (the argument of `bash -c`, what ssh sends)."""
        lx = _Lexer(text, self.lexer.bs, self.lexer)
        script, _ = lx.script(0, "")
        self.lexer.quoted += lx.quoted
        self.lexer.ambiguous = self.lexer.ambiguous or lx.ambiguous
        inner = _Check(lx)                       # another shell reads it: what kind of line it is is its own matter
        inner.depth = self.depth + 1
        inner.script(script)
        inner.consistent()

    def consistent(self) -> None:
        """A line is written for one kind of shell: not PowerShell's statements beside a POSIX shell's, nor
        a shell's beside a device's."""
        if (self.ps and self.posix) or (self.device and (self.ps or self.posix)):
            raise _No

    def inert(self, w: _W, inblock: bool = True, assigned: bool = False) -> None:
        """A word that is data to its command: what it nests must only read. `assigned`: the word is `name={ ... }`
        where a POSIX shell would take `name={` for a variable set and the block's text for the command."""
        static = _STATIC_CALL.match(w.raw)       # [type]::Method(...), the word's first call
        for g in w.groups:
            kind = g[0]
            if kind == "arith":
                if not all(name in self.safe for name in g[1]):
                    raise _No
            elif kind == "call" and static:
                kind_of, method, static = static.group(1).lower().removeprefix("system."), g[1].lower(), None
                if not ((kind_of in _PS_STATIC and (method in _PURE_METHODS or method in _PS_STATIC_ALSO))
                        or (kind_of in ("io.file", "io.directory") and method in _PS_FILE_READS) or (method == "new" and _ps_type(kind_of))):
                    raise _No
                self.ps = True
                for pipe in g[2]:
                    for words, side in pipe:
                        for x in words + side:
                            self.inert(x)
            elif kind == "sub":
                self.script(g[1])
            elif kind == "paren":
                self.script(g[1], inblock, lenient=True)
            elif kind == "brace":                # a script block given to a command: to a POSIX shell, words
                if assigned and g[2]:
                    self.script(g[1], False, False)
                else:
                    self.script(g[1], True, lenient=True)
            elif kind == "hash":
                self.hash(g[1])
            else:                                # a method called on a value: only the ones that change nothing
                if g[1].lower() not in _PURE_METHODS and not (g[1].lower() == "send" and self.ping(w)):
                    raise _No
                self.ps = True
                for pipe in g[2]:
                    for words, side in pipe:
                        for x in words + side:
                            self.inert(x)

    def hash(self, script: list) -> None:
        """PowerShell's @{ key = value; ... }. A value may be a command, which then runs. And each entry after
        the first starts a command of its own for a POSIX shell: `key = value` runs `key`, `key= value` runs
        `value` with a variable set for it, and `key={ value }` likewise."""
        self.ps = True
        for idx, pipe in enumerate(script):
            before = ""
            for k, (words, side) in enumerate(pipe):
                for w in side:
                    self.inert(w)
                if k or not words:
                    before = self.stage(words, before, False, False, True) or before
                    continue
                first, more = words[0], words[1:]
                if idx and _deny(" ".join(w.raw for w in words))[0] != "read_only":
                    raise _No                    # a key that is a command's name: `reboot = 1`
                if more and more[0].plain and more[0].s == "=" and first.lead in ("lit", "str") and not first.groups and not first.exps:
                    self.value(more[1:], True)
                    continue
                key, eq, rest = first.raw.partition("=")
                if not eq or first.lead != "lit" or not _PLAIN_NAME.fullmatch(key):
                    raise _No
                if not rest:                     # key= value
                    if idx:
                        self.stage(more, "", False, False)
                    else:
                        self.value(more, True)
                    continue
                if idx and more and not (more[0].plain and more[0].s.lower() in _PS_OPS and more[0].s != "*"):
                    raise _No                    # key=1 word: the word is a command to a POSIX shell
                if first.plain:
                    self.value([_W(rest)] + more, True)
                else:
                    self.inert(first, True, assigned=bool(idx))
                    for x in more:
                        self.inert(x, True)

    def ping(self, w: _W) -> bool:
        """Whether .Send( is called on a Ping: `(New-Object Net.NetworkInformation.Ping).Send(...)`, or a variable
        this command set to one. Send is no method to allow on whatever it is called on (a mail client has one)."""
        held = re.match(r"\$(\w+)\.Send\(\)", w.raw, _I)
        if held:
            return held.group(1).lower() in self.pings
        first = w.groups[0]
        return (w.raw.startswith("().Send()") and first[0] == "paren" and len(first[1]) == 1 and len(first[1][0]) == 1
                and _new_ping(first[1][0][0][0]))

    def value(self, rhs: list, inblock: bool, name: str = "") -> None:
        """What stands right of an assignment's `=`: a command (which runs) or an expression."""
        if name and _new_ping(rhs):
            self.pings.add(name.lower())
        else:
            self.pings.discard(name.lower())
        if rhs:                                  # a statement of its own: `$a = $b = Stop-Computer`, `$x = C:\tools\x.exe`
            self.stage(rhs, "", True, lenient=True)

    def stage(self, words: list, before: str = "", inblock: bool = False, lenient: bool = False, later: bool = False) -> str:
        """One command of a pipeline; `before` is what kind the stages before it were. Returns its kind.
        `inblock` and `lenient` hold where only PowerShell would run the statement (the first one of a script
        block given to a command, a value); `later` for the statements after it (see script)."""
        words = list(words)
        while words and words[0].plain and words[0].s == "!":
            words.pop(0)
        if not words:
            return ""
        w = words[0]
        if w.plain and w.s.lower() in _KEYWORDS:
            return self.keyword(w.s.lower(), words[1:], before, inblock)
        if w.lead in ("brace", "paren") and w.raw in ("{}", "()") and len(words) == 1:
            # ( ... ) or { ...; } as a command: a POSIX shell runs what is inside (PowerShell too, after `&`),
            # so it is read as strictly as the line it stands on
            self.script(w.groups[0][1], inblock, lenient and w.lead == "paren")
            return ""
        first = w.raw[:1]
        if w.lead == "sub":                      # $(...) as the command: a POSIX shell runs what it prints
            raise _No
        if w.lead in ("var", "paren", "hash") or (w.lead == "lit" and (
                (first == "[" and w.s not in ("[", "[[") and _TYPE_LED.match(w.raw)) or (first in "@!" and not w.plain))):
            return self.expression(words, inblock)
        if len(words) == 1 and w.plain and re.fullmatch(r"\d+\.\.\d+", w.s):
            self.ps = True                       # 1..254: a range, the start of a PowerShell pipeline
            return ""
        if w.lead == "str" or ((lenient or later) and w.lead == "lit" and (_NUMBER.match(w.s) or (w.plain and w.s.lower() in ("-not", "-join", "-split")))):
            # a string alone is output to PowerShell and a program's name to a POSIX shell: only where PowerShell
            # alone would run it, or where it is no name a program could have ("Free: $x GB")
            if w.lead == "str" and not lenient and not (later and _SENTENCE.search(w.s)):
                raise _No
            for x in words:
                self.inert(x, inblock)
            return ""
        return self.command(words, before, inblock)

    def expression(self, words: list, inblock: bool) -> str:
        """A PowerShell statement that starts with a value: `$x.Name`, `$x = ...`, `(Get-Date).AddDays(-1)`,
        `[math]::Round(...)`. Nothing in it runs but the methods and commands it nests, checked as such.
        A POSIX shell would run the variable's value as a command, so outside a script block the variable
        must be one PowerShell names and a POSIX shell is unlikely to hold a program's name in."""
        w = words[0]
        self.ps = True
        lead = w.raw.lstrip("!")
        if lead.startswith("$") or w.lead == "var":
            if not inblock and not self.powershell and not _PS_OWN_VAR.match(lead):
                # `$x`, `$x.Name`, `$x = Get-Date`: a value to PowerShell, and to a POSIX shell the
                # command that x holds, with the rest as its arguments. What x holds was set by an
                # earlier line the rules never see together with this one (`x=reboot` in one queue
                # item, `sudo $x` in the next), so the statement is confirmed only where the session
                # is PowerShell's alone, or the variable is one PowerShell defines itself and a
                # POSIX shell is not confirmed setting (assign).
                raise _No
            m = _PS_ASSIGN.match(lead)
            if not m and _PS_MEMBER_SET.match(lead):
                raise _No                        # $x.Prop=..., $x[0]=...: sets something on an object
            if m:                                # $x=..., written without spaces
                self.target(m.group(1))
                rest = lead[m.end():]
                self.inert(w, inblock)
                self.value(([_W(rest)] if rest and re.fullmatch(r"[\w.-]+", rest) else []) + words[1:], inblock, m.group(1))
                return ""
            name = next((e[0] for e in w.exps if e[0]), None)
            if not inblock and (not name or (not re.match(r"\$_[.\[]", lead) if name == "_" else not re.search(r"[a-z]", name))):
                raise _No                        # $SHELL, $0, a bare $_ (the last word of the command before, to bash)
        if len(words) > 1 and words[1].plain and words[1].s in _ASSIGN_OPS:
            m = _PS_TARGET.fullmatch(w.raw)
            if not m:
                raise _No                        # only a variable is assigned to; a property or an element is an object's
            self.target(m.group(1))
            self.value(words[2:], inblock, m.group(1))
            return ""
        if (lead.startswith("$") or w.lead == "var") and len(words) > 1:
            op = words[1]
            if not (op.plain and op.s.lower() in _PS_OPS):
                raise _No                        # `$x reboot`: an error to PowerShell, a command to a POSIX shell
        for x in words:
            self.inert(x, inblock)
        return ""

    def target(self, name: str) -> None:
        self.ps = True
        if _RISKY_VAR.match(name.split(":")[-1]) and name.lower().startswith("env:"):
            raise _No

    def keyword(self, kw: str, rest: list, before: str, inblock: bool) -> str:
        if kw in ("done", "fi", "esac", "break", "continue"):
            if rest:
                raise _No
            self.posix = self.posix or kw in ("done", "fi")
            return ""
        blocks = bool(rest) and any(x.lead in ("brace", "paren") and x.raw in ("{}", "()") for x in rest[:2])
        if kw == "do" and rest and rest[0].plain and rest[0].s.lower() in ("show", "sh", "sho"):
            return self.command(rest, before, inblock)       # a device's `do show ...`, from its configuration mode
        if kw in ("then", "do", "else", "if", "elif", "while", "until") and not blocks:
            self.posix = True
            return self.stage(rest, before, inblock) if rest else ""
        if kw == "for" and len(rest) >= 2 and rest[0].plain and rest[1].plain and rest[1].s == "in":
            self.posix = True                    # for NAME in WORDS: the name is known harmless when every word is
            for x in rest[2:]:
                self.inert(x)
            if all(x.plain and _SAFE_VALUE.fullmatch(x.s) for x in rest[2:]):
                self.safe.add(rest[0].s)
            else:
                self.safe.discard(rest[0].s)
            self.oneword.add(rest[0].s)
            return ""
        if kw in ("if", "elseif", "while", "foreach", "for", "try", "catch", "finally", "else") and blocks:
            self.ps = True                       # PowerShell's: a condition in parentheses, then script blocks
            for x in rest:
                if x.lead == "paren" and x.raw == "()":
                    for pipe in x.groups[0][1]:
                        for words, side in pipe:
                            if kw == "foreach" and len(words) > 2 and words[0].lead == "var" and words[1].plain and words[1].s.lower() == "in":
                                self.value(words[2:], True)      # what it goes through may be a command
                            else:
                                self.stage(words, "", True, lenient=True)
                elif x.lead == "brace" and x.raw == "{}":
                    self.script(x.groups[0][1], True, lenient=True)
                elif not (x.plain and (x.s.lower() in ("else", "elseif", "catch", "finally") or x.s.startswith("["))):
                    raise _No
            return ""
        raise _No

    # ---- commands

    def fixed(self, args: list, ps: bool = False, globs: bool = True) -> None:
        """No argument may turn into something else when the shell expands it: an option, or two words."""
        for w in args:
            if globs and w.plain and w.s[:1] in ("*", "?"):
                raise _No                        # a pattern: the files it matches may be named like options
            for name, quoted, at_start, safe in w.exps:
                if safe or name in self.safe or (name and name.lower() in _AMBIENT_PS):
                    continue
                if ps or (not at_start and (quoted or name in self.oneword)):
                    continue
                raise _No

    def assign(self, w: _W, m: re.Match) -> None:
        """NAME=value before a command, or alone."""
        self.posix = True
        name = m.group(1)
        if _RISKY_VAR.match(name) or name.lower() in _PS_OWN_NAMES:
            raise _No                            # or one a later `$env:X`, `$PSVersionTable` would then run (expression)
        self.inert(w)
        if not w.exps and _SAFE_VALUE.fullmatch(w.s[m.end():]):
            self.safe.add(name)
        else:
            self.safe.discard(name)

    def name(self, w: _W) -> str:
        """The command a word names, without a system directory and `.exe`; _No if it names none plainly."""
        if w.exps or w.groups or w.lead != "lit":
            raise _No
        raw = w.raw
        if not w.plain:
            if raw.startswith("\\") and raw[1:].replace("-", "").replace("_", "").isalnum():
                raw = raw[1:]                    # \ls: the command itself, not an alias
            elif not _STD_DIR.match(raw):
                raise _No
        m = _STD_DIR.match(raw)
        if m:
            raw = raw[m.end():]
        if raw.lower().endswith(".exe"):
            raw = raw[:-4]
        return raw

    def command(self, words: list, before: str = "", inblock: bool = False) -> str:
        for _ in range(12):                      # a prefix may run another: sudo env nice ...
            while words and words[0].lead == "lit" and not words[0].raw.startswith("-"):
                m = _ASSIGN.match(words[0].raw)
                if not m:
                    break
                self.assign(words[0], m)
                words = words[1:]
            if not words:
                return ""
            w, args = words[0], words[1:]
            if w.lead == "var":
                raise _No                        # `sudo $x`, `X=1 $x`: after a prefix a variable is the command to run, in any shell
            if w.lead != "lit":                  # `time (dig ...)`: what a prefix runs may be a group
                return self.stage(words, before, inblock)
            if w.lead == "lit" and w.raw.startswith("/") and not _STD_DIR.match(w.raw):
                return self.routeros(words)
            name = self.name(w)
            low = name.lower()
            a = [x.s for x in args]
            if (name in _VERSIONED and a in _VERSION_ARGS) or (len(a) == 1 and name in _VERSION_SHORT.get(a[0], ())):
                return ""
            wrapper = _WRAPPERS.get(name) or _WRAPPERS.get(low if low in _WRAPPERS_NOCASE else "")
            if wrapper:
                words = wrapper(self, args)
                if words is None:
                    return ""
                if words is not _PASS:
                    continue
                words = [w] + args
            # a name in other letters than the table's (`Sort`, `PING`) is the same command to Windows and
            # no command at all to a POSIX shell
            # no command at all to a POSIX shell; and a version in the name is the same program (php-fpm8.1)
            rule = _READERS.get(name) or _READERS.get(low) or _READERS.get(re.sub(r"[\d.]+$", "", name))
            windows = rule is None and low in _WINDOWS
            if rule is not None or windows:
                rule = _WINDOWS[low] if windows else rule
                for x in args:
                    self.inert(x, inblock)
                if rule is not ANY:
                    if self.joined:
                        raise _No
                    if not getattr(rule, "free", False):
                        self.fixed(args, globs=not windows)
                    if not rule([x.lower() for x in a] if windows else a, _Ctx(self, args, inblock)):
                        if low in _ROUTEROS_MENUS and args:
                            return self.routeros(words)      # `ip address print` is RouterOS's, not iproute2's
                        raise _No
                return ""
            # a cmdlet is named with capitals (Get-Date); a program of a POSIX system that has a dash is not (get-oui)
            if low in _PS_ALIASES or (_CMDLET.fullmatch(name) and name != low):
                if not _cmdlet(self, _PS_ALIASES.get(low, low), args, inblock):
                    raise _No
                self.ps = True
                return ""
            if low in _DEVICE:
                if not _device(low, [x.lower() for x in a], args):
                    raise _No
                self.device = True
                return "device"
            if before == "device" and all(x.plain for x in words) and (
                    (low in _DEVICE_FILTERS and (low != "compare" or re.fullmatch(r"|rollback \d+", " ".join(a))))
                    or (not args and _deny(name)[0] == "read_only" and (low in _DEVICE_WORDS or _DEVICE_NAME.fullmatch(name)))):
                # `| include up`; or one more alternative of the pattern before it (`| include up|down|Gi1/0/2`), which a
                # POSIX shell would run as a command: only a word a device prints, or one shaped like a port or an address
                return "device"
            if low in _ROUTEROS_MENUS and args:
                return self.routeros(words)
            raise _No
        raise _No

    def routeros(self, words: list) -> str:
        """RouterOS: `/ip address print`, `/ip/route/print detail`, `/export`. A menu's path, then print
        or export, with nothing that sets, adds, removes or writes a file."""
        tokens: list[str] = []
        for w in words:
            if w.exps or w.groups or "[" in w.raw or w.raw.startswith(":"):
                raise _No                        # [...] runs a command in place; :put, :execute are a script's
            tokens += [p for p in w.s.lower().split("/") if p]
        verb = next((t for t in tokens if t in _ROUTEROS_READS or t in _ROUTEROS_CHANGES), "")
        if verb not in _ROUTEROS_READS or any(t.startswith("file=") for t in tokens):
            raise _No                            # the first verb decides; after `print`, words are its filter
        if tokens[0] not in _ROUTEROS_MENUS and tokens[0] not in _ROUTEROS_READS:
            raise _No
        self.device = True
        return "device"


def _new_ping(words: list) -> bool:
    return (len(words) == 2 and all(w.plain for w in words) and words[0].s.lower() == "new-object"
            and words[1].s.lower().removeprefix("system.") == "net.networkinformation.ping")


class _Ctx:
    """What a rule may need beyond its arguments' text: the words themselves and the checker."""
    __slots__ = ("chk", "words", "inblock")

    def __init__(self, chk: _Check, words: list, inblock: bool) -> None:
        self.chk, self.words, self.inblock = chk, words, inblock


def _read_as(text: str, bs: bool, powershell: bool = False) -> tuple[bool | None, bool]:
    """(whether `text` only reads, with double quotes read one way: None if a quote stays open; whether the
    other reading could differ)."""
    lx = _Lexer(text, bs)
    try:
        if text.lstrip().startswith("^") or "\n^" in text:
            raise _No                            # ^old^new: bash runs the line before again, changed
        script, _ = lx.script(0, "")
        chk = _Check(lx, powershell)
        chk.script(script)
        chk.consistent()
        pieces = 0
        for q in lx.quoted:
            for m in _CMD_SPLIT.finditer(q):     # up to the next & or |; a `;` separates nothing there
                pieces += 1
                if pieces > 20:
                    raise _No                    # too many to rate each: not confirmed
                piece = re.split(r"[&|]", q[m.end():], maxsplit=1)[0].replace(";", " ")
                if _deny(piece)[0] != "read_only" or _PROGRAM_PATH.search(piece.split()[0]):
                    raise _No                    # rated by the deny-list, or a program named by its path or its extension
        return True, lx.ambiguous
    except _Open:
        return None, lx.ambiguous
    except (_No, RecursionError):
        return False, lx.ambiguous


@functools.lru_cache(maxsize=256)
def _reads(text: str, powershell: bool = False) -> bool:
    posix, ambiguous = _read_as(text, True, powershell)
    if not ambiguous:
        return posix is True
    # a \" inside double quotes: an escaped quote to a POSIX shell, the string's end to PowerShell and
    # cmd.exe. Read both ways; the command must pass each way it can be read at all.
    windows = _read_as(text, False, powershell)[0]
    return (posix is True and windows is not False) or (windows is True and posix is None)


def reads_only(command: str, shell: str = "") -> bool:
    """Whether the local rules can confirm that this command changes nothing: every command in it
    is a known reader in a form that reads, nothing is written to a file, and nothing in it is
    handed to a shell or an interpreter that the rules can't read as well.

    `shell`: "powershell" where the session the command is for can be nothing else (a WinRM
    console); anywhere else the line is read as every shell it could reach would read it, and a
    statement that begins with a variable is not confirmed (_Check.expression)."""
    text, cut = bounded(command)
    return not cut and bool(text.strip()) and _reads(text, shell == "powershell")


# ---------------------------------------------------------------------------------------
# The readers: commands known only to read, and the forms in which they do.
#
# What admits a command to these tables: in the form given, nothing on its command line can
# make it write or delete a file, change a setting, send a signal, or run another program;
# and the same holds for whatever else answers to that name in another shell (`sort` is GNU's
# and cmd.exe's, `curl` is curl and Windows PowerShell's alias). A command that reads in some
# forms and changes things in others is admitted in the reading forms only, each spelled out;
# when in doubt it is left out, which costs the technician one confirmation. To add one, pick
# the narrowest rule that fits:
#   ANY                          any arguments at all (`ls`, `cat`, `ps`)
#   _unless("-o --output")       any arguments but these options
#   _only("-l -u=", need="-l")   only these options (`x=` takes a value), one of `need` among them
#   _forms(r"status( \S+)*")     its words, options aside, must match (`vals`: options whose
#                                value is a word of its own; `deny`/`allow`: options refused or
#                                the only ones accepted)
#   _each(r"/all|/displaydns")   every argument must match
#   a function (args, ctx)       for a grammar of its own (sed, find, curl, git)

ANY = object()


def _denied(word: str, deny: list[str], letters: str | None = None) -> bool:
    """Whether `word` is one of the options in `deny`: a long one written out or cut short (GNU
    tools accept `--out` for `--output`), a short one alone or among others behind one dash.
    With `letters` (a tool's own short options), a word of other letters is no bundle of them:
    `sort -Property Name` is PowerShell's, not `-o`."""
    if len(word) < 2 or word[0] != "-":
        return False
    key = word.split("=", 1)[0]
    if word.startswith("--"):
        return any(d.startswith("--") and (key == d or (len(key) > 3 and d.startswith(key))) for d in deny)
    if any(len(d) > 2 and not d.startswith("--") and key == d for d in deny):
        return True
    if letters is not None and not all(ch in letters or ch.isdigit() for ch in word[1:]):
        return False
    return any(len(d) == 2 and d[1] in word[1:] for d in deny)


def _unless(spec: str, letters: str | None = None, operands: int | None = None):
    deny = spec.split()

    def rule(a, c=None):
        n = 0
        for i, x in enumerate(a):
            if x == "--":
                n += len(a) - i - 1
                break
            if _denied(x, deny, letters):
                return False
            n += not x.startswith("-") or x == "-"
        return operands is None or n <= operands
    return rule


def _only(spec: str, operands: bool | int = True, need: str = ""):
    flags = {o for o in spec.split() if not o.endswith("=")}
    vals = {o[:-1] for o in spec.split() if o.endswith("=")}
    needed = set(need.split())

    def rule(a, c=None):
        seen, n, i = set(), 0, 0
        while i < len(a):
            x = a[i]
            i += 1
            if len(x) > 1 and x[0] == "-":
                key = x.split("=", 1)[0]
                if key in vals:
                    i += "=" not in x
                elif x not in flags:
                    return False
                seen.add(key)
            else:
                n += 1
        return (not needed or bool(seen & needed)) and (operands is True or n <= int(operands))
    return rule


def _forms(pattern: str, vals: str = "", deny: str = "", allow: str | None = None, nocase: bool = False):
    rx = re.compile(pattern, _I if nocase else 0)
    takes, refused = set(vals.split()), deny.split()
    allowed = None if allow is None else set(allow.split()) | takes

    def rule(a, c=None):
        ops, i = [], 0
        while i < len(a):
            x = a[i]
            i += 1
            if x == "--":
                ops += a[i:]
                break
            if len(x) > 1 and x[0] == "-":
                key = x.split("=", 1)[0]
                if _denied(x, refused) or (allowed is not None and key not in allowed):
                    return False
                i += key in takes and "=" not in x
            else:
                ops.append(x)
        return rx.fullmatch(" ".join(re.sub(r"\s", "\1", o) for o in ops)) is not None
    return rule


def _each(allowed: str, need: str = "", max_args: int | None = None):
    ok, must = re.compile(allowed), re.compile(need) if need else None

    def rule(a, c=None):
        return (all(ok.fullmatch(x) for x in a) and (must is None or any(must.fullmatch(x) for x in a))
                and (max_args is None or len(a) <= max_args))
    return rule


def _rx(pattern: str):
    """The arguments, joined by single spaces, must match."""
    rx = re.compile(pattern)
    return lambda a, c=None: rx.fullmatch(" ".join(re.sub(r"\s", "\1", x) for x in a)) is not None


def _or(*rules):
    return lambda a, c=None: any(r(a, c) for r in rules)


# ---- grammars of their own

def _sed(a, c=None):
    """sed that prints: no -i, no script file, and no `w`, `W` or `e` in a script (as a command or as a
    flag of s///), which write a file or run a command."""
    scripts, i, files = [], 0, 0
    while i < len(a):
        x = a[i]
        i += 1
        if x in ("-e", "--expression"):
            scripts.append(a[i] if i < len(a) else "")
            i += 1
        elif x.startswith("--expression="):
            scripts.append(x.split("=", 1)[1])
        elif x in ("-n", "-E", "-r", "-s", "-u", "-z", "--quiet", "--silent", "--regexp-extended", "--null-data", "--separate", "--unbuffered",
                   "--posix", "--debug", "--sandbox") or re.fullmatch(r"-[nErsuz]+", x):
            continue
        elif re.fullmatch(r"-[nErsuz]*e", x):
            scripts.append(a[i] if i < len(a) else "")
            i += 1
        elif x in ("-l", "--line-length"):
            i += 1
        elif x.startswith("-") and len(x) > 1:
            return False
        elif not scripts and not files:
            scripts.append(x)
            files = 1                            # what follows the script are files
        else:
            files += 1
    return bool(scripts) and all("\0" not in s and _sed_script(s) for s in scripts)       # a script holding an expansion isn't known


def _sed_script(s: str) -> bool:
    i, n = 0, len(s)

    def address(i):
        if i < n and s[i] in "/\\":
            d = s[i] if s[i] == "/" else s[i + 1:i + 2]
            i += 1 if s[i] == "/" else 2
            while i < n and s[i] != d:
                i += 2 if s[i] == "\\" else 1
            return i + 1 if i < n else -1
        j = i
        while j < n and (s[j].isdigit() or s[j] in "$~+"):
            j += 1
        return j
    while i < n:
        if s[i] in " \t\n;{}":
            i += 1
            continue
        i = address(i)
        if i < 0:
            return False
        if i < n and s[i] == ",":
            i = address(i + 1)
            if i < 0:
                return False
        while i < n and s[i] in " \t!":
            i += 1
        if i >= n:
            return False
        cmd = s[i]
        i += 1
        if cmd in "{}":
            continue
        if cmd in "pdqQDGgHhxnNPlFz=":
            while i < n and s[i].isdigit():
                i += 1
        elif cmd in "sy":
            if i >= n:
                return False
            d = s[i]
            i += 1
            for _ in range(2):
                while i < n and s[i] != d:
                    i += 2 if s[i] == "\\" else 1
                if i >= n:
                    return False
                i += 1
            j = i
            while j < n and s[j] not in ";}\n \t":
                j += 1
            if cmd == "s" and not re.fullmatch(r"[gpiImM0-9]*", s[i:j]):
                return False
            i = j
        elif cmd in "aicrR:btT#":
            while i < n and s[i] != "\n" and (cmd in "aicrR#" or s[i] != ";"):
                i += 1
        else:
            return False                         # w, W, e and anything unknown
    return True


_AWK_WRITES = re.compile(r"\bprintf?\b(?:(?!\bprintf?\b)[^;}])*?(>|\|)|\bsystem\s*\(|\bgetline\b|\bfflush\s*\(|\bclose\s*\(|@load|@include")


def _awk(a, c=None):
    """awk that prints: a program on the command line that neither redirects its output, pipes, nor
    calls system()."""
    i, program = 0, None
    while i < len(a):
        x = a[i]
        i += 1
        if x in ("-F", "-v", "--field-separator", "--assign"):
            i += 1
        elif x.startswith(("-F", "-v")) or x.startswith(("--field-separator=", "--assign=")) or x in ("--posix", "--traditional", "-P", "-c", "--re-interval", "-r"):
            continue
        elif x.startswith("-") and len(x) > 1:
            return False                         # -f file, -i inplace, -e, -l: a program or a library the rules can't read
        elif program is None:
            program = x
    return program is not None and "\0" not in program and not _AWK_WRITES.search(program)


def _find(a, c=None):
    """find that prints: no -delete, no -fprint/-fls, no -ok, and what -exec runs is a reader itself."""
    i = 0
    while i < len(a):
        x = a[i]
        i += 1
        if x in ("-delete", "-ok", "-okdir", "-fprint", "-fprint0", "-fprintf", "-fls"):
            return False
        if x in ("-exec", "-execdir"):
            j = i
            while j < len(a) and a[j] not in (";", "+"):
                j += 1
            if j >= len(a) or j == i or c is None:
                return False
            c.chk.command(c.words[i:j])          # raises if it is not a reader
            i = j + 1
    return True


_CURL_FLAGS = set("fsSLkIiv46gNGnqZ#0123")
_CURL_VALS = set("HmAebxuUrEYyzCtP")
_CURL_LONG = set("""--silent --show-error --fail --fail-with-body --location --location-trusted --insecure --head --include --verbose --compressed
    --ipv4 --ipv6 --http1.0 --http1.1 --http2 --http2-prior-knowledge --http3 --tlsv1 --tlsv1.2 --tlsv1.3 --no-buffer --globoff --get
    --no-progress-meter --path-as-is --ssl --ssl-reqd --ssl-no-revoke --no-keepalive --tcp-nodelay --disable --raw --tr-encoding --no-alpn
    --negotiate --ntlm --digest --basic --anyauth --proxy-insecure --progress-bar --styled-output --no-styled-output --suppress-connect-headers
    --version --help""".split())
_CURL_LONG_VALS = set("""--header --max-time --connect-timeout --user-agent --referer --cookie --proxy --user --proxy-user --range --cert --key
    --cacert --capath --resolve --connect-to --interface --retry --retry-delay --retry-max-time --max-redirs --url --ciphers --tls-max
    --dns-servers --noproxy --limit-rate --speed-time --speed-limit --oauth2-bearer --unix-socket --proxy-header --pinnedpubkey --cert-type
    --key-type --pass --local-port --keepalive-time --max-filesize --proto --proto-default --proto-redir --request --output --write-out""".split())
_NULL_FILES = ("/dev/null", "nul", "-", "/dev/stdout", "$null")


def _curl(a, c=None):
    """curl that fetches to the terminal: GET or HEAD, nothing sent, nothing saved but to /dev/null."""
    i = 0

    def value(opt, rest=""):
        nonlocal i
        v = rest
        if not v:
            if i >= len(a):
                return False
            v = a[i]
            i += 1
        if opt in ("o", "--output"):
            return v.lower() in _NULL_FILES
        if opt in ("X", "--request"):
            return v.upper() in ("GET", "HEAD", "OPTIONS")
        return opt not in ("w", "--write-out") or ("%output" not in v and not v.startswith("@"))
    while i < len(a):
        x = a[i]
        i += 1
        if x.startswith("--"):
            if x in _CURL_LONG:
                continue
            if x not in _CURL_LONG_VALS or not value(x):
                return False
        elif x.startswith("-") and len(x) > 1:
            for k, ch in enumerate(x[1:], 2):
                if ch in _CURL_FLAGS:
                    continue
                if ch in _CURL_VALS or ch in "oXw":
                    if not value(ch, x[k:]):
                        return False
                    break
                return False                     # -d, -F, -T, -O, -c, -D, -K... send, save or read a config
    return True


_WGET_FLAGS = set("""-q -S -nv -v -d -4 -6 --quiet --server-response --spider --no-check-certificate --no-verbose --verbose --debug --inet4-only
    --inet6-only --no-cache --no-cookies --no-hsts --content-on-error --no-proxy --version -V""".split())
_WGET_VALS = set("""-T -t -U --timeout --tries --header --user-agent --max-redirect --connect-timeout --read-timeout --dns-timeout --user
    --password --http-user --http-password --referer --ca-certificate --bind-address""".split())


def _wget(a, c=None):
    """wget that prints what it fetches (-O -) or only checks the address (--spider): by default it saves a file."""
    i, out = 0, False
    while i < len(a):
        x = a[i]
        i += 1
        key = x.split("=", 1)[0]
        m = re.fullmatch(r"-[qSv]*O(.*)", x)
        if m or key == "--output-document":
            target = (m.group(1) if m else x.partition("=")[2]) or (a[i] if i < len(a) else "")
            i += not (m.group(1) if m else "=" in x)
            if target not in ("-", "/dev/null"):
                return False
            out = True
        elif x in _WGET_FLAGS:
            out = out or x in ("--spider", "--version", "-V")
        elif key in _WGET_VALS:
            i += "=" not in x
        elif x.startswith("-") and len(x) > 1:
            return False
    return out


_OPENSSL_SUBS = {"s_client", "x509", "verify", "version", "ciphers", "crl", "req", "asn1parse", "dgst", "pkcs7", "s_time", "sess_id", "errstr",
                 "list", "storeutl", "help"}
_OPENSSL_WRITES = ("-out", "-sess_out", "-keylogfile", "-msgfile", "-engine", "-provider", "-signkey", "-cacreateserial", "-caserial", "-cakey",
                   "-new", "-x509toreq", "-writerand", "-keyout", "-sign", "-req", "-days", "-set_serial", "-ca")


def _openssl(a, c=None):
    return bool(a) and a[0] in _OPENSSL_SUBS and not any(x.lower().startswith(_OPENSSL_WRITES) and x.lower() != "-cafile" and x.lower() != "-capath"
                                                         for x in a[1:]) and (a[0] != "req" or "-noout" in a)


def _date(a, c=None):
    """date that prints: no -s, and no bare operand (which would set the clock) but a +FORMAT."""
    i = 0
    while i < len(a):
        x = a[i]
        i += 1
        if x in ("-d", "--date", "-r", "--reference", "-f", "--file"):
            i += 1
        elif x.startswith("+") or x.lower() == "/t" or x.startswith(("--date=", "--reference=", "--iso-8601", "--rfc-3339=", "-I")) or x in (
                "-u", "--utc", "--universal", "-R", "--rfc-email", "--debug"):
            continue
        else:
            return False
    return True


def _batch(a, c=None):
    """top and iotop print once and leave only in batch mode (-b); otherwise they wait for keys."""
    return any(len(x) > 1 and x[0] == "-" and x[1] != "-" and "b" in x for x in a) or "--batch" in a


def _nc(a, c=None):
    flags = [x for x in a if x.startswith("-")]
    return any("z" in x for x in flags) and all(re.fullmatch(r"-[zvnuw46tU]+", x) for x in flags)


def _nmap(a, c=None):
    return not any(x.startswith(("-o", "--script", "--data", "--resume", "--stylesheet", "--append-output", "--spoof-mac", "--proxies", "--datadir",
                                 "--servicedb", "--versiondb", "--badsum", "--send-", "--interactive")) or x in ("-A", "-b", "-S", "-D", "-iR")
                   or (x.startswith("-s") and "C" in x) for x in a)


_IP_FLAGS = set("""-4 -6 -0 -s -stats -statistics -d -details -j -json -p -pretty -o -oneline -c -color -br -brief -h -human -human-readable
    -r -resolve -a -all -t -timestamp -ts -tshort -iec -N -Numeric""".split())
_IP_VALS = {"-n", "-netns", "-f", "-family", "-rc", "-rcvbuf", "-l", "-loops"}
# iproute2 takes the first of its objects that the word given starts
_IP_OBJECTS = ("address", "addrlabel", "maddress", "route", "rule", "neighbor", "neighbour", "ntable", "ntbl", "link", "l2tp", "fou", "ila", "macsec",
               "tunnel", "tunl", "tuntap", "tap", "token", "tcpmetrics", "tcp_metrics", "monitor", "xfrm", "mroute", "mrule", "netns", "netconf",
               "vrf", "sr", "nexthop", "mptcp", "ioam", "help", "stats")
_IP_SHOWN = {"address", "addrlabel", "maddress", "route", "rule", "neighbor", "neighbour", "ntable", "ntbl", "link", "tunnel", "tunl", "tuntap", "tap",
             "token", "tcpmetrics", "tcp_metrics", "mroute", "mrule", "netconf", "vrf", "nexthop"}


def _ip(a, c=None):
    """ip that shows: an object with no verb, or with show, list or get as iproute2 would read the
    word (any start of it: `ip a s`, `ip r g`; but link's `s` is set)."""
    i = 0
    while i < len(a) and a[i].startswith("-"):
        if a[i] in _IP_VALS:
            i += 1
        elif a[i] in ("-V", "-Version") and len(a) == 1:
            return True
        elif a[i] not in _IP_FLAGS and not a[i].startswith("-color="):
            return False                         # -batch file, -force
        i += 1
    if i >= len(a):
        return False
    obj = next((o for o in _IP_OBJECTS if o.startswith(a[i])), None)
    verb = a[i + 1] if i + 1 < len(a) else ""
    if obj in ("monitor", "help"):
        return True
    if obj == "netns":
        return not verb or any(v.startswith(verb) for v in ("list", "identify", "pids")) and not "set".startswith(verb)
    if obj not in _IP_SHOWN:
        return False
    if not verb:
        return True
    if len(verb) == 1 and obj not in ("address", "route", "neighbor", "neighbour", "rule"):
        return False                             # link's `s` is set, token's too
    return any(v.startswith(verb) for v in ("show", "list", "lst", "get"))


_NMCLI = re.compile(r"|(?:g|general)(?: (?:status|hostname|permissions|logging))?|(?:n|networking)(?: connectivity(?: check)?)?|(?:r|radio)(?: (?:all|wifi|wwan))?"
                    r"|(?:c|con|connection)(?: (?:show|sh)(?: \S+)*)?|(?:d|dev|device)(?: (?:status|st|show|sh|lldp|wifi)(?: \S+)*)?|(?:m|monitor)")


def _nmcli(a, c=None):
    ops, i = [], 0
    while i < len(a):
        x = a[i]
        i += 1
        if x in ("-t", "--terse", "-p", "--pretty", "-s", "--show-secrets", "-v", "--version", "-o", "--overview", "-e", "--escape"):
            continue
        if x in ("-f", "--fields", "-g", "--get-values", "-c", "--colors", "-m", "--mode", "-w", "--wait"):
            i += 1
        elif x.startswith("-"):
            return False
        else:
            ops.append(x)
    joined = " ".join(ops)
    return _NMCLI.fullmatch(joined) is not None and not re.search(r"\bwifi (?:connect|hotspot|rescan|show-password)\b|\blldp (?!list)", joined + " ")


def _pfctl(a, c=None):
    """pf's control, where it shows: -s rules (or -sr, -vvsr), -t table -T show. Its other options load a rule set,
    flush, enable, disable or kill states."""
    i, shows = 0, False
    while i < len(a):
        x = a[i]
        i += 1
        if x == "-s" or x in ("-a", "-t", "-p", "-i"):
            shows = shows or x == "-s"
            i += 1
        elif re.fullmatch(r"-[vqr]*s[A-Za-z]+", x):
            shows = True
        elif x == "-T":
            if i >= len(a) or a[i] not in ("show", "test"):
                return False
            shows = True
            i += 1
        elif x.startswith("-") and not re.fullmatch(r"-[vqrh]+", x):
            return False
    return shows


def _iptables(a, c=None):
    """iptables that lists (-L, -S): its other capital letters are all commands that change the rules."""
    listing, i = False, 0
    while i < len(a):
        x = a[i]
        i += 1
        if x.startswith("--"):
            key = x.split("=", 1)[0]
            if key in ("--list", "--list-rules", "--version"):
                listing = True
            elif key == "--table":
                i += "=" not in x
            elif key not in ("--line-numbers", "--numeric", "--verbose", "--exact", "--ipv4", "--ipv6", "--wait"):
                return False
        elif x.startswith("-") and len(x) > 1:
            if not all(ch in "nvxLSVtw46" for ch in x[1:]):
                return False
            listing = listing or bool(set(x) & set("LSV"))
            if x.endswith("t") or (x.endswith("w") and i < len(a) and a[i].isdigit()):
                i += 1
        elif not re.fullmatch(r"[\w-]+", x):
            return False
    return listing


def _nft(a, c=None):
    ops = [x for x in a if not x.startswith("-")]
    opts = [x for x in a if x.startswith("-")]
    if not all(re.fullmatch(r"-[anstyjpNSTu]+|--(?:handle|numeric|stateless|json|terse|numeric-priority|numeric-protocol|reversedns|service|numeric-time)", x)
               for x in opts):
        return opts in (["-v"], ["--version"], ["-V"]) and not ops
    text = " ".join(ops)                         # nft reads its arguments as one script: `;` starts another command
    return bool(ops) and text.split()[0] in ("list", "describe") and not re.search(r"[;\n{]", text)


_GIT_READS = set("""status log diff show rev-parse rev-list describe ls-files ls-tree ls-remote cat-file blame annotate shortlog grep whatchanged
    name-rev merge-base for-each-ref show-ref check-ignore check-attr var version help count-objects show-branch cherry diff-tree diff-index
    diff-files verify-commit verify-tag""".split())
_GIT_CHANGING = {"-d", "-D", "-m", "-M", "-c", "-C", "-f", "-u", "-a", "-s", "-e", "--delete", "--move", "--copy", "--force", "--edit", "--edit-description",
                 "--unset-upstream", "--track", "--no-track", "--annotate", "--sign", "--add", "--unset", "--unset-all", "--replace-all",
                 "--rename-section", "--remove-section", "--global", "--system", "--local", "--file", "--create-reflog"}


def _git(a, c=None):
    """git that looks: a reading verb, or the listing form of a verb that also creates and deletes."""
    i = 0
    while i < len(a) and a[i].startswith("-"):   # git's own options come before the verb
        x = a[i]
        if x in ("--version", "--help", "-v", "-h") and len(a) == i + 1:
            return True
        if x in ("-C", "--git-dir", "--work-tree"):
            i += 1
        elif x not in ("--no-pager", "-p", "--paginate", "--no-optional-locks", "--bare", "--literal-pathspecs") and not x.startswith(
                ("--git-dir=", "--work-tree=", "--namespace=")):
            return False                         # -c name=value can name a pager, an editor or an alias: a command
        i += 1
    if i >= len(a):
        return False
    verb, rest = a[i], a[i + 1:]
    if any(x.startswith(("--output", "-O", "--open-files-in-pager", "--ext-diff", "--upload-pack", "--exec")) for x in rest):
        return False
    if verb in _GIT_READS:
        return True
    ops = [x for x in rest if not x.startswith("-")]
    if verb == "clean":                          # -n: "don't actually remove anything, just show what would be done"
        return any(x == "--dry-run" or (re.fullmatch(r"-[a-zA-Z]+", x) and "n" in x) for x in rest) and not any(
            x in ("--interactive",) or (re.fullmatch(r"-[a-zA-Z]+", x) and "i" in x) for x in rest)
    if verb == "branch":
        listing = bool({"-l", "--list", "--contains", "--no-contains", "--merged", "--no-merged", "--points-at", "--show-current"} & set(rest))
        return not (_GIT_CHANGING - {"-a"}) & set(rest) and not any(x.startswith("--set-upstream") for x in rest) and (listing or not ops)
    if verb == "tag":
        return not (_GIT_CHANGING & set(rest)) and (not ops or bool({"-l", "--list", "--contains", "--points-at", "--merged"} & set(rest)))
    if verb == "remote":
        return not rest or rest == ["-v"] or rest[0] in ("show", "get-url")
    if verb == "stash":
        return rest[:1] in (["list"], ["show"])
    if verb == "reflog":
        return not ops or ops[0] == "show" or ops[0] not in ("expire", "delete", "exists")
    if verb == "config":
        gets = bool({"--get", "--get-all", "--get-regexp", "--get-urlmatch", "--list", "-l"} & set(rest))
        sets = bool(({"--add", "--unset", "--unset-all", "--replace-all", "--edit", "-e", "--rename-section", "--remove-section"}) & set(rest))
        return not sets and (gets or len(ops) == 1)
    if verb in ("worktree", "submodule", "notes", "lfs"):
        return rest[:1] in (["list"], ["status"], ["summary"], ["show"], ["ls-files"], ["env"], ["version"]) or (verb in ("submodule", "notes") and not rest)
    return False


_APT_SIMULATED = {"install", "remove", "purge", "upgrade", "dist-upgrade", "full-upgrade", "autoremove", "autopurge", "reinstall"}


def _apt(a, c=None, own=("list", "show", "policy", "search", "depends", "rdepends", "showsrc", "changelog")):
    """apt that lists, or that simulates (-s): "no action, a simulation of events that would occur"."""
    if any(x.startswith(("-o", "-c", "--option", "--config-file")) for x in a):
        return False                             # a setting given on the line can undo -s or name a command
    ops = [x for x in a if not x.startswith("-")]
    if not ops:
        return a in (["--version"], ["-v"])
    if ops[0] in own:
        return True
    simulated = any(x in ("-s", "--simulate", "--just-print", "--dry-run", "--recon", "--no-act") or (re.fullmatch(r"-[a-zA-Z]+", x) and "s" in x) for x in a)
    return ops[0] in _APT_SIMULATED and simulated


def _pacman(a, c=None):
    return bool(a) and re.fullmatch(r"-Q\w*|-S[silgpq]+|-F[lxoq]*|-T\w*|-V|-h|--query|--version|--help", a[0]) is not None and not any(
        x.startswith(("--overwrite", "--root", "--dbpath", "--config", "--hookdir")) for x in a)


def _rpm(a, c=None):
    return bool(a) and (a[0].startswith(("-q", "-V")) or a[0] in ("--query", "--verify", "--version")) and not any(
        x.startswith(("--re", "--import", "--set", "--init", "--erase", "--install", "--upgrade", "--freshen", "--delsign", "--addsign", "--resign", "--root",
                      "--dbpath", "--eval", "--define", "--pipe", "--macros", "--load", "-D", "-E")) for x in a)


def _rsync(a, c=None):
    """rsync told to change nothing (-n): it compares the two sides and says what it would do. Not with
    an option that names a program to run or a file to write."""
    dry = False
    for x in a:
        if x == "--":
            break
        bundle = re.fullmatch(r"-[a-zA-Z]+", x) is not None
        if x.startswith(("--rsh", "--rsync-path", "--write-batch", "--only-write-batch", "--log-file", "-e")) or (bundle and "e" in x):
            return False
        dry = dry or x in ("--dry-run", "--list-only") or (bundle and "n" in x)
    return dry or a in (["--version"], ["-V"])


def _tar(a, c=None):
    """tar that lists an archive (t), with nothing that names a program."""
    if not a:
        return False
    listing = "--list" in a or (re.fullmatch(r"-?[a-zA-Z]+", a[0]) is not None and "t" in a[0] and not set(a[0]) & set("xcruA"))
    longs = {"--list", "--verbose", "--gzip", "--bzip2", "--xz", "--zstd", "--lzma", "--wildcards", "--numeric-owner", "--no-anchored", "--ignore-case",
             "--full-time", "--utc"}
    return listing and all((x in longs or x.startswith("--file=")) if x.startswith("--") else re.fullmatch(r"-[tvfzjJa]+", x) is not None
                           for x in a[1:] if x.startswith("-"))


def _unpacker(a, c=None):
    """gzip and its like, writing to the terminal (-c), listing (-l) or testing (-t): otherwise they replace the file."""
    return any((x[1] != "-" and set(x) & set("clt")) or x in ("--stdout", "--to-stdout", "--list", "--test") for x in a if len(x) > 1 and x[0] == "-")


def _python(a, c=None):
    return a in (["-V"], ["--version"], ["-VV"]) or (a[:2] == ["-m", "json.tool"] and sum(not x.startswith("-") for x in a[2:]) <= 1
                                                      and not any(x.startswith("--outfile") for x in a))


_PARTED_WORDS = {"print", "p", "free", "all", "list", "devices", "unit", "s", "b", "kb", "mb", "gb", "tb", "kib", "mib", "gib", "tib", "%", "cyl", "chs", "compact"}


def _parted(a, c=None):
    opts = [x for x in a if x.startswith("-")]
    ops = [x for x in a if not x.startswith("-")]
    if not all(x in ("-l", "--list", "-s", "--script", "-m", "--machine", "-j", "--json") for x in opts):
        return False
    if "-l" in opts or "--list" in opts:
        return all(x.startswith("/") for x in ops)
    return len(ops) > 1 and bool({"print", "p"} & set(ops[1:])) and all(x.lower() in _PARTED_WORDS or x.isdigit() for x in ops[1:])


def _fsck(a, c=None):
    opts = [x for x in a if x.startswith("-")]
    return any("n" in x.lower() for x in opts) and not any(x.startswith("--") or set(x[1:]) & set("ypar") for x in opts)


_AWS_VALS = {"--profile", "--region", "--output", "--endpoint-url", "--query", "--color", "--cli-read-timeout", "--cli-connect-timeout", "--ca-bundle"}
_AWS_READS = re.compile(r"(?:describe|list|get|head|lookup|search|scan|query|batch-get|filter|check|estimate|validate|wait|tail|show|view|preview)(?:-[\w-]+)?")
_AWS_SAVES = {"get-object", "get-object-torrent", "get-job-output", "get-export", "get-sdk", "get-thing-shadow", "get-media"}


def _aws(a, c=None):
    """aws that describes, lists or gets: the operation's first word says which it is."""
    ops, i = [], 0
    while i < len(a) and len(ops) < 2:
        if a[i] in _AWS_VALS:
            i += 1
        elif not a[i].startswith("-"):
            ops.append(a[i])
        i += 1
    if len(ops) < 2:
        return a in (["--version"], ["help"]) or ops == ["help"]
    service, op = ops
    if service == "configure":
        return op in ("list", "get", "list-profiles")
    if service == "s3":
        return op in ("ls", "presign")
    return _AWS_READS.fullmatch(op) is not None and op not in _AWS_SAVES


_CLOUD_READS = re.compile(r"(?:list|show|get|check|exists|version|describe|info|read|tail|lookup|query|search|print-access-token|print-identity-token|wait)(?:-[\w-]+)?")
_CLOUD_CHANGES = re.compile(r"(?:create|delete|update|set|add|remove|start|stop|restart|reset|deploy|apply|import|export|enable|disable|attach|detach|resize"
                            r"|move|patch|replace|rollback|run|exec|ssh|scp|login|logout|activate|revoke|submit|cancel|purge|restore|invoke|publish|send|put"
                            r"|upload|download|copy|cp|mv|rm|sync|rsync|init|install|uninstall|upgrade|migrate|failover|promote|drain|call|execute|trigger"
                            r"|approve|reject|accept|sign|encrypt|decrypt|deallocate|generalize|redeploy|reimage|assign|unassign|grant|rotate|regenerate"
                            r"|renew|capture|convert|swap|scale|configure|connect|browse|open|edit|clone|merge|push|pull|tag|untag|lock|unlock|kill"
                            r"|terminate|simulate|rest|get-credentials)(?:-[\w-]+)?")


def _cloud(a, c=None):
    """az and gcloud: groups, then a verb, then perhaps what it names. The verb must be a reading one,
    and no word before the options may be one that changes things."""
    ops = []
    for x in a:
        if x.startswith("-"):
            break
        ops.append(x)
    if not ops:
        return a in (["--version"], ["-v"])
    if ops == ["version"] or any(_CLOUD_CHANGES.fullmatch(x) for x in ops):
        return ops == ["version"]
    return any(_CLOUD_READS.fullmatch(x) for x in ops[-2:])


def _ansible(a, c=None):
    if "--version" in a or "--list-hosts" in a:
        return True
    module = next((a[i + 1] for i, x in enumerate(a[:-1]) if x in ("-m", "--module-name")), "")
    return module in ("ping", "setup", "ansible.builtin.ping", "ansible.builtin.setup") and not {"-a", "--args"} & set(a)


_IPMI = re.compile(r"sdr(?: (?:list|elist|info|type \S+|get \S+))?(?: \S+)?|sel(?: (?:list|elist|info))?(?: \S+)?|sensor(?: (?:list|get(?: \S+)+|reading(?: \S+)+))?"
                   r"|fru(?: (?:print|list)(?: \d+)?)?|lan print(?: \d+)?|chassis (?:status|power status|restart_cause|poh|selftest)|power status"
                   r"|(?:mc|bmc) (?:info|getenables|guid|selftest)|user list(?: \d+)?|sol info(?: \d+)?|dcmi power reading|channel info(?: \d+)?")


def _ipmi(a, c=None):
    ops, i = [], 0
    while i < len(a):
        if a[i] in ("-I", "-H", "-U", "-P", "-f", "-L", "-p", "-C", "-N", "-R", "-t", "-b", "-m"):
            i += 1
        elif not a[i].startswith("-"):
            ops.append(a[i])
        elif a[i] not in ("-E", "-v", "-c", "-vv"):
            return False
        i += 1
    return _IPMI.fullmatch(" ".join(ops)) is not None


def _esxcli(a, c=None):
    ops = [x for x in a if not x.startswith("-")]
    return bool(ops) and ops[-1] in ("list", "get") and all(re.fullmatch(r"[a-z0-9]+", x) for x in ops) and not {
        "set", "add", "remove", "delete", "kill", "reset", "start", "stop", "restart", "install", "update", "apply", "enter", "exit", "load", "unload"} & set(ops)


# SQL that only reads, for the clients below.
_SQL_STRING = re.compile(r"'(?:[^']|'')*'|\"[^\"]*\"|`[^`]*`")
_SQL_CHANGES = re.compile(r"\b(?:insert|update|delete|drop|truncate|alter|create|grant|revoke|merge|replace|call|do|copy|load|import|lock|vacuum|analy[sz]e"
                          r"|reindex|cluster|refresh|comment|execute|exec|prepare|handler|kill|shutdown|reset|purge|flush|install|uninstall|rename|backup"
                          r"|restore|attach|detach|begin|commit|rollback|savepoint|set|declare|open|fetch|notify|listen|unlisten|checkpoint|discard|reassign"
                          r"|into|outfile|dumpfile|start|stop|change|optimize|repair|for\s+(?:update|share))\b", _I)
_SQL_CALLS = re.compile(r"(?<![\w.])([A-Za-z_][\w.]*+)\s*+\(")
_SQL_PURE = set("""count sum avg min max now version current_database current_user coalesce nullif length char_length lower upper trim substring
    substr concat round floor ceil ceiling abs cast convert extract date_trunc date_part age to_char date datetime strftime date_format datediff
    timestampdiff unix_timestamp from_unixtime format string_agg array_agg group_concat db_name object_name schema_name getdate sysdatetime
    datepart dateadd isnull len serverproperty databasepropertyex host_name suser_sname user_name current_setting to_timestamp to_date greatest
    least row_number rank dense_rank lag lead first_value last_value ntile bool_or bool_and every stddev variance sqlite_version typeof ifnull
    iif instr printf hex julianday time unixepoch in values over as from exists any all on and or not where using join by distinct interval
    limit when then else case having union select""".split())
_SQL_PURE_LIKE = re.compile(r"pg_stat_\w+|has_\w+_privilege|pg_\w*size\w*|pg_is_in_recovery|pg_postmaster_start_time|pg_(?:current|last)_\w+|pg_wal_lsn_diff|pg_blocking_pids")
_SQL_META = re.compile(r"\\(?:d[a-zA-Z]*\+?|l\+?|conninfo|x|timing|z|dp|encoding)(?:\s+[\w.*\"-]+)*")
_SQL_PROCS = {"sp_who", "sp_who2", "sp_helpdb", "sp_help", "sp_helptext", "sp_helpindex", "sp_spaceused", "sp_lock", "sp_databases", "sp_tables",
              "sp_columns", "xp_fixeddrives", "sp_readerrorlog", "xp_readerrorlog", "sp_helpfile", "sp_helplogins"}


def _sql_reads(sql: str) -> bool:
    """Whether every statement only reads: SELECT and its like with no function but known pure ones,
    SHOW, DESCRIBE, a listing meta-command of psql. Whatever it can't place, it refuses."""
    if "/*" in sql or "\0" in sql or len(sql) > 4000:
        return False
    stripped = _SQL_STRING.sub("''", re.sub(r"\\[Gg]\s*$", "", sql.strip()))
    statements = [s.strip() for s in stripped.split(";") if s.strip()]
    for s in statements:
        head = s.split(None, 1)[0].lower()
        if head.startswith("\\"):
            if s.count("\\") != 1 or not _SQL_META.fullmatch(s):
                return False
        elif head in ("show", "describe", "desc"):
            if "\\" in s or re.search(r"\binto\b", s, _I):
                return False
        elif head in ("exec", "execute"):
            if not re.fullmatch(r"exec(?:ute)?\s+(?:master\.)?(?:dbo\.|sys\.)?(\w+)(?:\s+[\w'@=, ]*)?", s, _I) or s.split()[1].split(".")[-1].lower() not in _SQL_PROCS:
                return False
        elif head in ("select", "explain", "table", "values", "with", "pragma"):
            if "\\" in s or _SQL_CHANGES.search(s) or (head == "pragma" and ("=" in s or "(" in s)):
                return False
            for m in _SQL_CALLS.finditer(s):
                name = m.group(1).lower().split(".")[-1]
                if name not in _SQL_PURE and not _SQL_PURE_LIKE.fullmatch(name):
                    return False
        else:
            return False
    return bool(statements)


def _sql_client(flags: str, vals: str, sql: str, bundle: str = "", lists: str = "", operands: int = 2):
    """A database's command-line client run with the statement on the line, which must only read."""
    flag_set, val_set, sql_set, list_set = set(flags.split()), set(vals.split()), set(sql.split()), set(lists.split())

    def rule(a, c=None):
        texts, i, n, listing = [], 0, 0, False
        while i < len(a):
            x = a[i]
            i += 1
            key = x.split("=", 1)[0]
            if x in list_set:
                listing = True
            elif x in flag_set or (bundle and re.fullmatch("-[" + bundle + "]+", x)):
                continue
            elif key in sql_set or (bundle and re.fullmatch("-[" + bundle + "]*" + "[" + "".join(s[1] for s in sql_set if len(s) == 2) + "]", x)):
                if "=" in x and x.startswith("--"):
                    texts.append(x.split("=", 1)[1])
                elif i < len(a):
                    texts.append(a[i])
                    i += 1
                else:
                    return False
            elif key in val_set:
                i += not ("=" in x and x.startswith("--"))
            elif len(x) > 2 and x[:2] in val_set and not x.startswith("--"):
                continue
            elif x.startswith("-") and len(x) > 1 and not (x.startswith("-p") and "-p" in flag_set):
                return False
            else:
                n += not x.startswith("-")
        return n <= operands and (listing or (bool(texts) and all(_sql_reads(t) for t in texts)))
    return rule


def _sqlite(a, c=None):
    ops = [x for x in a if not x.startswith("-")]
    if any(x not in ("-readonly", "-header", "-noheader", "-column", "-csv", "-line", "-json", "-list", "-html", "-table", "-box", "-markdown", "-batch",
                     "-quote", "-tabs", "-ascii", "-safe") for x in a if x.startswith("-")):
        return False
    return len(ops) >= 2 and all(re.fullmatch(r"\.(?:tables|schema|databases|indexes|dbinfo|show|dump|fullschema|stats|version|help)(?: [\w.%*-]+)*", s)
                                 if s.startswith(".") else _sql_reads(s) for s in ops[1:])


_REDIS_READS = set("""PING INFO DBSIZE GET MGET EXISTS TTL PTTL TYPE STRLEN LLEN LRANGE LINDEX SCARD SMEMBERS SISMEMBER HGET HGETALL HKEYS HVALS HLEN
    HMGET HEXISTS ZCARD ZRANGE ZSCORE ZCOUNT ZRANK KEYS SCAN SSCAN HSCAN ZSCAN TIME LASTSAVE ROLE XLEN XINFO XRANGE OBJECT ECHO RANDOMKEY GETRANGE
    BITCOUNT""".split())
_REDIS_SUBS = {"MEMORY": {"USAGE", "STATS", "DOCTOR"}, "CLIENT": {"LIST", "INFO", "GETNAME", "ID"}, "CONFIG": {"GET"}, "SLOWLOG": {"GET", "LEN"},
               "CLUSTER": {"INFO", "NODES", "SLOTS", "SHARDS"}, "LATENCY": {"LATEST", "HISTORY", "DOCTOR"}, "COMMAND": {"COUNT", "INFO", "DOCS"},
               "PUBSUB": {"CHANNELS", "NUMSUB", "NUMPAT"}, "MODULE": {"LIST"}, "ACL": {"LIST", "WHOAMI", "USERS", "CAT"},
               "SENTINEL": {"MASTERS", "MASTER", "SLAVES", "REPLICAS", "SENTINELS", "GET-MASTER-ADDR-BY-NAME", "CKQUORUM"}}


def _redis(a, c=None):
    i = 0
    while i < len(a) and a[i].startswith("-"):
        if a[i] in ("-h", "-p", "-a", "-n", "-u", "--user", "--pass", "-s", "--cacert", "--cert", "--key", "--pattern", "-i", "-r", "--sni"):
            i += 1
        elif a[i] in ("--scan", "--bigkeys", "--memkeys", "--hotkeys", "--stat", "--latency", "--latency-history", "--version", "-v"):
            return all(x.startswith("-") or a[k - 1] in ("--pattern", "-h", "-p", "-a", "-n", "-i") for k, x in enumerate(a))
        elif a[i] not in ("--no-auth-warning", "--tls", "--raw", "--no-raw", "--insecure", "-c", "-3", "-2", "--csv", "--json"):
            return False
        i += 1
    if i >= len(a):
        return False
    cmd = a[i].upper()
    if cmd in _REDIS_SUBS:
        return i + 1 < len(a) and a[i + 1].upper() in _REDIS_SUBS[cmd]
    return cmd in _REDIS_READS


def _net(a, c=None):
    """Windows' net (and Samba's `net ads`): what lists. A second name, a password, `/add`, `/delete`
    or a share=path changes things."""
    if not a:
        return True
    sub, rest = a[0].lower(), [x.lower() for x in a[1:]]
    switches = [x for x in rest if x.startswith("/")]
    ops = [x for x in rest if not x.startswith("/")]
    listing = all(re.fullmatch(r"/domain(?::\S+)?|/all|/cache|/rtsdomain(?::\S+)?|/help|/\?", x) for x in switches)
    if sub in ("help", "helpmsg"):
        return True
    if sub == "use":
        return not rest
    if sub in ("accounts", "start", "file", "print"):
        return listing and not ops
    if sub == "view":
        return listing
    if sub in ("user", "localgroup", "group", "share", "session", "statistics", "config", "time"):
        return listing and len(ops) <= 1 and not any("=" in x or "*" in x for x in ops) and not (sub == "config" and switches)
    if sub == "ads":
        return ops[:1] in (["info"], ["status"], ["testjoin"], ["lookup"], ["workgroup"])
    return False


def _wmic(a, c=None):
    """wmic that gets or lists; not `call`, `set`, `create` or `delete`, nor output to a file or through a
    style sheet (which may hold script)."""
    words = [w for x in a for w in x.lower().split()]
    if {"call", "set", "create", "delete", "terminate", "uninstall", "product"} & set(words) or not {"get", "list"} & set(words):
        return False                             # `product`: listing it makes Windows Installer check, and repair, every package
    return all(re.fullmatch(r"/(?:node|user|password|namespace|role|locale|authority|implevel|authlevel|failfast|privileges):\S*"
                            r"|/format:(?:list|csv|table|value|htable|hform|mof|rawxml|xml|textvaluelist)|/value|/all|/every:\d+|/repeat:\d+|/translate:\S+|/\?", x)
               for x in words if x.startswith("/"))


def _netsh(a, c=None):
    words = [w for x in a for w in x.lower().split()]
    return ("show" in words or words == ["dump"]) and not {"set", "add", "delete", "del", "reset", "import", "export", "install", "uninstall", "exec",
                                                             "start", "stop", "connect", "disconnect", "renew", "release", "flush", "trace", "-f"} & set(words)


def _dism(a, c=None):
    a = [x.lower() for x in a]
    changes = re.compile(r"/(?:restorehealth|startcomponentcleanup|enable-feature|disable-feature|(?:add|remove|apply|capture|set|mount|unmount|commit|export|import)-\S+"
                         r"|cleanup-wim|spsuperseded|resetbase)")
    return (all(x.startswith("/") for x in a) and not any(changes.match(x) for x in a)
            and (any(x.startswith("/get-") for x in a) or ("/cleanup-image" in a and bool({"/checkhealth", "/scanhealth"} & set(a)))))


def _test(a, c=None, arithmetic=False):
    """test, [ and [[: what they compare is data, but -v and -R take a variable's name, and [[ evaluates
    both sides of -eq and its like as arithmetic, variables in them included."""
    for i, x in enumerate(a):
        if x in ("-v", "-R") and not (i + 1 < len(a) and _PLAIN_NAME.fullmatch(a[i + 1])):
            return False
        if arithmetic and x in ("-eq", "-ne", "-lt", "-le", "-gt", "-ge") and c is not None:
            c.chk.fixed([w for w in c.words[max(i - 1, 0):i + 2] if w.exps], globs=False)
            if any(not re.fullmatch(r"-?\d+|\0", y) for y in (a[i - 1] if i else "", a[i + 1] if i + 1 < len(a) else "")):
                return False                     # a bare word there is a variable's name to [[
    return True


def _test2(a, c=None):
    return _test(a, c, arithmetic=True)


_test.free = _test2.free = True


def _read(a, c=None):
    i = 0
    while i < len(a):
        x = a[i]
        i += 1
        if x in ("-d", "-n", "-N", "-p", "-t", "-u", "-i"):
            i += 1
        elif not re.fullmatch(r"-[ers]+|[A-Za-z_]\w*|-a", x):
            return False
    return True


_read.free = True


def _printf(a, c=None):
    return not (a and a[0].startswith("-v"))     # -v NAME assigns, and NAME may hold a subscript


_printf.free = True
_READERS: dict[str, object] = {}


def _add(names: str, rule) -> None:
    for name in names.split():
        _READERS[name] = rule


# -- files, text, the system at a glance
_add("""ls ll la l dir vdir cat tac nl head tail more grep egrep fgrep zgrep zegrep zfgrep bzgrep xzgrep zcat bzcat xzcat zstdcat lz4cat wc cut tr
    comm paste join column fold fmt rev od hexdump strings base64 base32 md5sum sha1sum sha224sum sha256sum sha384sum sha512sum
    b2sum cksum sum stat df du free uptime ps pgrep pidof pstree vmstat iostat mpstat nproc lscpu lsmem lspci lsusb lshw lsblk lsmod
    lsns lslogins lsipc lslocks lsattr lsscsi lsof lsinitramfs findmnt mountpoint id whoami groups users who w last lastb uname
    arch hostid tty logname getent getfacl getfattr namei realpath readlink basename dirname pwd echo true false : sleep seq expr
    bc cal locale diff cmp jq zipinfo which whereis type lsb_release modinfo numfmt locate mlocate plocate printenv cd pushd popd chdir help
    apropos whatis getconf zdump numastat avahi-browse vainfo sockstat swapinfo kldstat opnsense-version freebsd-version clog""", ANY)
_add("pkg", _forms(r"(?:info|query|rquery|version|which|search|stats)(?: \S+)*"))
_add("gpart", _forms(r"(?:show|list|status)(?: \S+)*"))
_add("camcontrol", _forms(r"(?:devlist|identify|inquiry)(?: \S+)*"))
# bash's own that take a variable's name: a name with a subscript, a[...], has the subscript evaluated as
# arithmetic, which can run a command, so the name must be a plain one
_add("test [", _test)
_add("[[", _test2)
_add("read", _read)
_add("printf", _printf)
_add("wait", _each(r"-[nf]+|%?\d+"))
# (not `expand`: Windows' unpacks a cabinet into a file; not `fc`: bash's runs the last command again)
_add("file", _unless("-C --compile"))
_add("pidstat", _unless("-e"))
_add("lastlog", _unless("-C --clear -S --set"))
_add("lsinitrd", _unless("--unpack --unpackearly"))
_add("inxi", _unless("-U --update --output-file"))
# dd that only reads: to the terminal or to /dev/null (a read test), with nothing but sizes and counts
_add("dd", _each(r"(?:if|bs|ibs|obs|count|skip|iflag|status)=.+|of=/dev/null"))
_add("ffprobe", _each(r"(?!-o$).*"))
_add("rg", _unless("--pre --pre-glob --hostname-bin"))
_add("ag", _unless("--pager"))
_add("less", lambda a, c=None: not any(x.startswith("+") for x in a) and _unless("-o -O -k --log-file --LOG-FILE --lesskey-file")(a))
_add("man", _unless("-P --pager -H --html --preprocessor"))
_add("sort", lambda a, c=None: "/o" not in [x.lower() for x in a] and _unless("-o --output --compress-program", letters="bdfgiMhnRrVckmostuzSTC")(a))
_add("uniq", _unless("", operands=1))
_add("xxd", _unless("-r --revert", operands=1))
_add("tree", _unless("-o --output"))
_add("sed", _sed)
_add("awk gawk mawk nawk", _awk)
_add("find", _find)
_add("date", _date)
_add("history", _each(r"\d+"))
_add("alias", _each(r"-p"))
_add("set", _each(r"[-+][A-Za-z]+|[A-Za-z_]\w*"))
_add("ulimit", _each(r"-[a-zA-Z]+"))
_add("umask", _each(r"-[Sp]+"))
_add("clear", _each(r"", max_args=0))
_add("hostname", _each(r"-[fsidIAy]+|--(?:fqdn|short|ip-address|all-ip-addresses|domain|all-fqdns|long|version|help)"))
_add("gzip gunzip xz unxz bzip2 bunzip2", _unpacker)
_add("zstd unzstd lz4", lambda a, c=None: _unpacker(a) and _unless("-o --output", operands=1)(a))
_add("tar bsdtar", _tar)
_add("unzip", _each(r"-[lZtvqp1]+|[^-].*", need=r"-[lZtvqp1]*[lZtp][lZtvqp1]*"))
_add("7z 7za 7zr", _forms(r"[lt](?: \S+)*", deny="-o"))
_add("python python3", _python)
_add("php", _only("-v -m -i --ini --version --modules --info --ri= --rf=", operands=False, need="-v -m -i --ini --version --modules --info --ri --rf"))
_add("php-fpm", _only("-t -tt -v -i -m --test --version --info --modules -y= --fpm-config= -c= --php-ini=", operands=False,
                      need="-t -tt -v -i -m --test --version --info --modules"))
_add("top iotop", _batch)
_add("sar", _unless("-o"))
_add("fuser", _unless("-k --kill"))
_add("dmidecode", _unless("--dump-bin"))
_add("sensors", _unless("-s --set"))
_add("passwd", _only("-S --status -a --all", need="-S --status"))
_add("chage", _only("-l --list", need="-l --list"))
_add("faillock", _unless("--reset"))
_add("visudo", _only("-c --check -f= --file= -q -s", operands=False, need="-c --check"))
_add("crontab", _only("-l -u=", operands=False, need="-l"))
_add("atq", ANY)
_add("at", _only("-l -q=", operands=False, need="-l"))
_add("screen", _each(r"-ls|-list"))
_add("tmux", _forms(r"ls|list-(?:sessions|windows|panes|clients)(?: \S+)*", allow="-t -a -F -V"))
_add("klist", lambda a, c=None: not {"purge", "add_bind", "purge_bind"} & {x.lower() for x in a})
# -- services, logs, time
_add("journalctl", _unless("--vacuum-size --vacuum-time --vacuum-files --rotate --flush --sync --relinquish-var --smart-relinquish-var --setup-keys "
                           "--update-catalog --cursor-file"))
_add("dmesg", _unless("-C -c -D -E -n --clear --read-clear --console-off --console-on --console-level", letters="CcDdEeFfHhkLlnPprSsTtuVwWxJ"))
_add("systemctl", _forms(r"|(?:status|show|cat|help|list-\S+|is-\S+|get-default|show-environment)(?: \S+)*",
                         vals="-t --type --state -p --property -P -n --lines -o --output -H --host -M --machine -s --signal"))
_add("service", _forms(r"--status-all|\S+ status", allow=""))
_add("rc-status", ANY)
_add("rc-service", _forms(r"\S+ status"))
_add("sv", _forms(r"status(?: \S+)+"))
_add("initctl", _forms(r"list|status \S+|version"))
_add("chkconfig", _rx(r"--list(?: \S+)?"))
_add("supervisorctl", _forms(r"(?:status|avail|pid|version)(?: \S+)*"))
_add("pm2", _forms(r"(?:list|ls|l|status|show|describe|info|jlist|prettylist|logs)(?: \S+)*"))
_add("timedatectl", _forms(r"|status|show(?: \S+)*|list-timezones|timesync-status|show-timesync(?: \S+)*", vals="-p --property -H --host -M --machine"))
_add("hostnamectl", _forms(r"|status|hostname|chassis|icon-name|deployment|location", vals="-H --host -M --machine"))
_add("localectl", _forms(r"|status|list-\S+"))
_add("loginctl", _forms(r"|list-\S+|(?:show|session-status|user-status|seat-status|show-session|show-user|show-seat)(?: \S+)*",
                        vals="-p --property -n --lines -o --output"))
_add("systemd-analyze", _forms(r"|(?:time|blame|critical-chain|dump|verify|security|cat-config|unit-paths|calendar|timespan|timestamp|condition|unit-files"
                               r"|capability|syscall-filter|filesystems|exit-status|architectures|plot|dot)(?: \S+)*"))
_add("systemd-cgls systemd-detect-virt systemd-path", ANY)
_add("resolvectl systemd-resolve", _or(_forms(r"|(?:status|query|statistics|show-cache|show-server-state)(?: \S+)*|(?:dns|domain|llmnr|mdns|dnssec|dnsovertls|nta|default-route)(?: \S+)?"),
                                       _each(r"--status|--statistics")))
_add("networkctl", _forms(r"|(?:status|list|lldp)(?: \S+)*"))
_add("busctl", _forms(r"|(?:list|status|tree|introspect|get-property|monitor)(?: \S+)*", vals="-H --host -M --machine --address --match"))
_add("coredumpctl", _forms(r"|(?:list|info)(?: \S+)*", deny="-o --output"))
_add("bootctl", _forms(r"|status|list|is-installed"))
_add("efibootmgr", _only("-v -u --verbose --unicode", operands=False))
_add("ntpstat mailq pg_lsclusters pg_isready pg_controldata mongostat mongotop doveconf named-checkconf", ANY)
_add("ntpq", _each(r"-[pn46]+|-c|[lao]?peers|rv(?:\s.*)?|as|associations|sysinfo|sysstats|kerninfo|iostats|version|readvar(?:\s.*)?|pstats(?:\s.*)?|(?!-)[\w.:-]+"))
_add("chronyc", _forms(r"(?:tracking|sources|sourcestats|activity|ntpdata|serverstats|clients|rtcdata|smoothing|selectdata|authdata|manual list|waitsync)(?: \S+)*",
                       vals="-h -p", allow="-n -a -m -N -c -d -v -4 -6"))
_add("hwclock", _only("-r --show --verbose -v --utc -u --localtime -l --get --test", operands=False))
_add("ntpdate", _only("-q -u -d -p= -t= -4 -6 -qu -uq", need="-q -qu -uq -d"))
# -- disks and file systems
_add("mount", _forms(r"", vals="-t --types", allow="-l -v --show-labels"))
_add("swapon", _each(r"-s|--show(?:=.*)?|--summary|--noheadings|--raw|--bytes|-v", need=r"-s|--show(?:=.*)?|--summary"))
_add("blkid", _unless("-g --garbage-collect"))
_add("fdisk", _only("-l -lu -ul --list -x --list-details -o= --output= -u --units -b= --bytes -L --color", need="-l -lu -ul --list -x --list-details"))
_add("sfdisk", _only("-l --list -d --dump -s --show-size -g --show-geometry -J --json -F --list-free -V --verify -T --list-types -q --quiet -u= -o= --output=",
                     need="-l --list -d --dump -s --show-size -g --show-geometry -J --json -F --list-free -V --verify -T --list-types"))
_add("sgdisk", _only("-p --print -i= --info= -v --verify -L --list-types -O --print-mbr -E --end-of-largest -F --first-aligned-in-largest -D --display-alignment",
                     need="-p --print -i --info -v --verify -L --list-types -O --print-mbr -E --end-of-largest -F --first-aligned-in-largest -D --display-alignment"))
_add("gdisk", _only("-l", need="-l"))
_add("parted", _parted)
_add("smartctl", _only("-a --all -x --xall -i --info -H --health -c --capabilities -A --attributes -l= --log= -n= --nocheck= -d= --device= -j --json "
                       "-q= --quietmode= -T= --tolerance= -b= --badsum= -P= --presets= -g= --get= --scan --scan-open -h --help -V --version -r= -f= --format= "
                       "-v= --vendorattribute= -F= -B="))
_add("hdparm", _only("-I -i -C -g -t -T -tT -Tt -V"))
_add("nvme", _forms(r"(?:list|list-subsys|list-ns|list-ctrl|smart-log|smart-log-add|id-ctrl|id-ns|error-log|fw-log|get-feature|get-log|show-regs|version|help"
                    r"|effects-log)(?: \S+)*", deny="--output-file"))
_add("mdadm", _only("--detail -D --examine -E --query -Q --detail-platform --scan -s --verbose -v --brief -b --export -Y --test -t --version -V --help -h "
                    "--examine-bitmap -X -Ds -Es -Dsv -Esv",
                    need="--detail -D --examine -E --query -Q --detail-platform --version -V --help -h --examine-bitmap -X -Ds -Es -Dsv -Esv"))
_add("cryptsetup", _forms(r"(?:status|luksDump|isLuks|luksUUID|benchmark)(?: \S+)*|", allow="--version -V -v --verbose --debug"))
_add("zpool", _forms(r"(?:status|list|iostat|history|get|version)(?: \S+)*"))
_add("zfs", _forms(r"(?:list|get|version|holds|userspace|groupspace)(?: \S+)*"))
_add("btrfs", _forms(r"(?:filesystem|fi) (?:show|df|usage|du)(?: \S+)*|(?:subvolume|sub) (?:list|show|get-default)(?: \S+)*|(?:device|dev) (?:usage|stats)(?: \S+)*"
                     r"|(?:scrub|balance) status(?: \S+)*|qgroup show(?: \S+)*|property (?:get|list)(?: \S+)*|version", deny="-z --reset"))
_add("lvs vgs pvs lvdisplay vgdisplay pvdisplay lvscan xfs_info dumpe2fs lsscsi showmount", ANY)
_add("xfs_repair", _only("-n -v -f", need="-n"))
_add("fsck e2fsck fsck.ext2 fsck.ext3 fsck.ext4 fsck.xfs fsck.vfat fsck.fat", _fsck)
_add("tune2fs", _only("-l", need="-l"))
_add("blockdev", _each(r"--(?:get\w+|report)|-[vq]|/\S+", need=r"--(?:get\w+|report)"))
_add("e2label", _each(r"\S+", max_args=1))
_add("multipath", _only("-l -ll -v= -v2 -v3 -d", need="-l -ll"))
_add("exportfs", _each(r"-[vs]+"))
_add("rpcinfo", _unless("-d"))
_add("nfsstat", _unless("-z --zero"))
_add("dmsetup", _forms(r"(?:ls|info|status|table|deps|targets|version)(?: \S+)*"))
_add("dkms", _forms(r"status(?: \S+)*"))
_add("ipmitool", _ipmi)
# -- the network
_add("netstat ping ping6 traceroute traceroute6 tracepath tracepath6 mtr dig nslookup host whois fping ssh-keyscan iwlist nmblookup ldapwhoami "
     "smbstatus testparm getenforce sestatus aa-status apparmor_status aureport getsebool", ANY)
_add("ss", _unless("-K --kill -D --diag"))
_add("ldapsearch", _unless("-t -T"))
_add("ausearch", _unless("--checkpoint"))
_add("ip", _ip)
_add("ifconfig", lambda a, c=None: sum(not x.startswith("-") for x in a) <= 1 and all(re.fullmatch(r"-[asvlud]+|(?!-)[\w.:-]+", x) for x in a))
_add("route", _each(r"-[neCFv46]+|print|PRINT"))
_add("arp", _each(r"-[anveH]+|/[ag]|-i|--device|--numeric|--verbose|(?!-)[\w.:-]+"))
_add("arping", _unless("-U -A"))
_add("nbtstat", _each(r"-[aAcnrsS]|(?!-)[\w.:-]+"))
_add("nc ncat netcat", _nc)
_add("nmap", _nmap)
_add("tcpdump", _unless("-w -z -G -C -W"))
_add("iperf3 iperf", _unless("--logfile --pidfile -D --daemon -I"))
_add("curl", _curl)
_add("wget", _wget)
_add("openssl", _openssl)
_add("nmcli", _nmcli)
_add("iw", _rx(r"dev|list|reg get|features|commands|phy|dev \S+ (?:link|info|scan(?: dump)?|station dump|survey dump|get power_save|mpath dump)|phy \S+ info|\S+ (?:link|info)"))
_add("iwconfig", _each(r"(?!-)[\w.-]+", max_args=1))
_add("rfkill", _forms(r"|list(?: \S+)?"))
_add("ethtool", _only("""-a -c -g -i -k -l -m -n -u -S -T -P -x -e -d -I --show-pause --show-coalesce --show-ring --driver --show-features --show-offload
    --show-channels --module-info --dump-module-eeprom --show-nfc --show-ntuple --statistics --show-time-stamping --show-permaddr --show-rxfh
    --show-rxfh-indir --show-eee --show-fec --show-priv-flags --json --phy-statistics --include-statistics --version -h --help"""))
_add("mii-tool", _only("-v -vv -V"))
_add("bridge", _forms(r"(?:link|fdb|vlan|mdb|monitor)(?: show(?: \S+)*)?", allow="-s -d -j -p -c -br -brief -json -details -statistics -color -oneline -o -4 -6 -t"))
_add("brctl", _forms(r"show(?: \S+)?|showmacs \S+|showstp \S+"))
_add("tc", _forms(r"(?:qdisc|class|filter|action|monitor)(?: (?:show|ls|list)(?: \S+)*)?", allow="-s -d -p -j -r -g -statistics -details -pretty -json -raw -graph -iec -br -color -c"))
_add("conntrack", _only("-L --dump -S --stats -C --count -E --event -p= --proto= -s= -d= --src= --dst= -o= --output= -f= --family= -n", need="-L --dump -S --stats -C --count -E --event"))
_add("ipset", _forms(r"(?:list|save|version|help)(?: \S+)*|", deny="-f --file", allow="-L -S -V --version -n -name -t -terse -o= -output= -s -sorted -r -resolve"))
_add("iptables ip6tables iptables-legacy ip6tables-legacy iptables-nft ip6tables-nft", _iptables)
_add("iptables-save ip6tables-save", _only("-c --counters -t= --table= -V --version", operands=False))
_add("nft", _nft)
_add("pfctl", _pfctl)
_add("wg", _forms(r"|show(?: \S+){0,2}|showconf \S+"))
_add("ufw", _forms(r"status(?: verbose| numbered)?|show \S+|app (?:list|info \S+)|version", allow="--version"))
_add("firewall-cmd", _each(r"--(?:state|version|check-config|permanent|direct|zone=\S+|(?:list|get|query|info)-[\w-]+(?:=\S*)?)",
                           need=r"--(?:state|version|check-config|(?:list|get|query|info)-[\w-]+(?:=\S*)?)"))
_add("fail2ban-client", _forms(r"status(?: \S+)?|ping|version|get \S+(?: \S+)*|banned", allow="-V --version -v"))
_add("auditctl", _only("-l -s -v", operands=False, need="-l -s -v"))
_add("semodule", _each(r"-l\w*|--list-modules(?:=\w+)?|-v", need=r"-l\w*|--list-modules(?:=\w+)?"))
_add("semanage", _each(r"(?!-[admDEio]$)(?!--(?:add|delete|modify|deleteall|extract|import|output)$)\S+", need=r"-l|--list"))
_add("sysctl", _each(r"-[aAenNqXbr]+|--(?:all|values|names|ignore|binary|pattern=.*|deprecated)|(?!-)[\w./*-]+"))
_add("smbclient", _only("-L= -U= -N -k -I= -p= -m= --no-pass", need="-L"))
_add("net net1", _net)
# -- services' own tools
_add("nginx", _only("-t -T -v -V -q -c= -p= -tq", operands=False, need="-t -T -v -V -tq"))
_add("apachectl apache2ctl httpd apache2", _each(r"-[tSMVvlL]|-D|DUMP_\w+|configtest|status|fullstatus", need=r"-[tSMVvlL]|configtest|status|fullstatus"))
_add("sshd", _only("-t -T -f= -C= -4 -6", operands=False, need="-t -T"))
_add("ssh-keygen", _only("-l -lf -lv -lvf -f= -E= -F= -v -y -B -e -m=", need="-l -lf -lv -lvf -F -y -B -e"))
_add("ssh-add", _only("-l -L", operands=False, need="-l -L"))
_add("gpg gpg2", _only("--list-keys -k --list-secret-keys -K --fingerprint --list-sigs --list-public-keys --version --verify --keyid-format= --with-colons "
                       "--with-fingerprint --batch --no-tty --with-keygrip",
                       need="--list-keys -k --list-secret-keys -K --fingerprint --list-sigs --list-public-keys --version --verify"))
_add("certbot", _forms(r"certificates", allow="--version"))
_add("keytool", _only("-list -v -rfc -keystore= -storepass= -alias= -storetype= -cacerts", need="-list"))
_add("named-checkzone", _unless("-o"))
_add("postconf", _each(r"-[ndhfmlaACMFPtTxpo]+|[\w.]+"))
_add("postqueue", _only("-p -j", operands=False, need="-p -j"))
_add("exim exim4", _each(r"-bpc?|-bV|-bP|-bt|(?!-)[\w.@-]+", need=r"-bpc?|-bV|-bP|-bt"))
_add("rabbitmqctl", _forms(r"(?:status|cluster_status|environment|report|list_\w+|version|ping)(?: \S+)*", vals="-n --node -t --timeout -p --vhost"))
_add("mysqladmin", _forms(r"(?:status|extended-status|processlist|ping|version|variables)(?: (?:status|extended-status|processlist|ping|version|variables))*",
                          vals="-u --user -h --host -P --port -S --socket -i --sleep -c --count", allow="-p --password --silent -s -v --verbose -r --relative"))
_add("haproxy", _only("-c -f= -v -vv -V -q", operands=False, need="-c -v -vv"))
_add("psql", _sql_client("-X -w -W --csv --no-psqlrc --tuples-only --no-align --expanded --quiet --no-password -V --version",
                         "-h -p -U -d -F -R --host --port --username --dbname --field-separator --record-separator", "-c --command",
                         bundle="XAtqxwW", lists="-l --list -V --version"))
_add("mysql mariadb", _sql_client("-p --password --batch --skip-column-names --silent --table --vertical --verbose --raw --ssl --skip-ssl --compress",
                                  "-h -P -u -D -S --host --port --user --database --socket --protocol --default-character-set --ssl-mode --ssl-ca --connect-timeout",
                                  "-e --execute", bundle="NBstEvr", lists="-V --version", operands=1))
_add("sqlcmd", _sql_client("-E -N -C -W -b -I", "-S -d -U -P -l -t -s -h -y -Y -w -H", "-Q", operands=0))
_add("sqlite3", _sqlite)
_add("redis-cli", _redis)
# -- packages
_add("dpkg", _each(r"-[lsLSpcICV]|--(?:list|status|listfiles|search|print-avail|get-selections|print-architecture|print-foreign-architectures|audit|verify"
                   r"|compare-versions|contents|info|version|no-pager)|[^-].*",
                   need=r"-[lsLSpcICV]|--(?:list|status|listfiles|search|print-avail|get-selections|print-architecture|print-foreign-architectures|audit|verify"
                        r"|compare-versions|contents|info|version)"))
_add("dpkg-query", ANY)
_add("rpm", _rpm)
_add("apt", _apt)
_add("apt-get", lambda a, c=None: _apt(a, c, own=()))
_add("apt-cache", _forms(r"(?!gencaches)\S+(?: \S+)*", deny="-o -c --option --config-file"))
_add("apt-mark", _forms(r"show\w+(?: \S+)*"))
_add("apt-config", _forms(r"dump(?: \S+)*"))
_add("dnf yum", _forms(r"(?:list|info|search|provides|whatprovides|repolist|repoinfo|check-update|repoquery|deplist|updateinfo|grouplist)(?: \S+)*"
                       r"|history(?: (?:list|info)(?: \S+)*)?|(?:group|module) (?:list|info|summary)(?: \S+)*|"))
_add("zypper", _forms(r"(?:se|search|if|info|lr|repos|lu|list-updates|lp|list-patches|pa|packages|patches|ps|ls|services|pt|patterns|pd|products|what-provides|wp"
                      r"|lifecycle|licenses)(?: \S+)*"))
_add("pacman", _pacman)
_add("snap", _forms(r"(?:list|info|find|search|version|changes|services|connections|interfaces|get|logs|tasks|model|warnings|known|aliases)(?: \S+)*"))
_add("flatpak", _forms(r"(?:list|info|search|remotes|history|ps|remote-ls|remote-info|documents|permissions)(?: \S+)*|"))
_add("pip pip3", _forms(r"(?:list|show|freeze|check|config (?:list|get|debug)|index versions|debug|inspect)(?: \S+)*|", allow=None))
_add("npm", _forms(r"(?:ls|list|ll|la|view|info|show|outdated|config (?:get|list|ls)|root|prefix|bin|ping|explain|why|fund)(?: \S+)*|version|audit(?! fix)(?: \S+)*|"))
_add("gem", _forms(r"(?:list|info|search|env|environment|outdated|contents|dependency|specification|which)(?: \S+)*"))
# -- containers, clusters, clouds, code
_DOCKER = (r"(?:ps|logs|inspect|images|stats|top|port|version|info|diff|history|events|search)(?: \S+)*|(?:image|images) (?:ls|list|inspect|history)(?: \S+)*"
           r"|container (?:ls|list|ps|inspect|logs|top|port|stats|diff)(?: \S+)*|(?:volume|network) (?:ls|list|inspect)(?: \S+)*|system (?:df|info|events)(?: \S+)*"
           r"|compose (?:ps|logs|config|top|images|ls|version)(?: \S+)*|context (?:ls|list|show|inspect)(?: \S+)*|node (?:ls|inspect)(?: \S+)*"
           r"|service (?:ls|ps|logs|inspect)(?: \S+)*|stack (?:ls|ps|services)(?: \S+)*|pod (?:ps|ls|list|inspect|logs|top|stats)(?: \S+)*|")
_add("docker podman nerdctl", _forms(_DOCKER, vals="-H --host --context -c --config -l --log-level --file -p --project-name --project-directory --env-file --profile",
                                     deny="-o --output"))
_add("docker-compose", _forms(r"(?:ps|logs|config|top|images|ls|version)(?: \S+)*|",
                              vals="--file -p --project-name --project-directory --env-file --profile", deny="-o --output"))
_add("crictl", _forms(r"(?:ps|pods|images|img|inspect|inspecti|inspectp|logs|stats|statsp|info|version)(?: \S+)*"))
_add("lxc", _forms(r"(?:list|ls|info|config show|profile (?:list|show)|network (?:list|show|info)|storage (?:list|show|info)|image list|version)(?: \S+)*"))
_add("kubectl oc k", _forms(r"(?:get|describe|logs|top|version|cluster-info|api-resources|api-versions|explain|events)(?: \S+)*|auth can-i(?: \S+)*"
                            r"|config (?:view|get-contexts|current-context|get-clusters|get-users)(?: \S+)*|rollout (?:status|history)(?: \S+)*",
                            vals="-n --namespace --context --kubeconfig --cluster --user -s --server --as --token --request-timeout -l --selector -o --output "
                                 "-c --container --since --tail --field-selector --sort-by --filename", deny="--output-directory"))
_add("helm", _forms(r"(?:list|ls|status|history|get (?:values|manifest|notes|hooks|all|metadata)|show \S+|search \S+|version|env|repo list|template|lint"
                    r"|dependency list)(?: \S+)*", vals="-n --namespace --kube-context --kubeconfig -o --output", deny="--output-dir --post-renderer"))
_add("virsh", _forms(r"(?:list|dominfo|domstate|domblklist|domiflist|domifaddr|dumpxml|net-list|net-info|net-dumpxml|net-dhcp-leases|pool-list|pool-info|vol-list"
                     r"|vol-info|nodeinfo|version|snapshot-list|snapshot-info|snapshot-current|domstats|domblkinfo|domblkstat|domifstat|capabilities|sysinfo"
                     r"|hostname|uri|nodememstats|nodecpustats|vcpuinfo|vcpucount|dommemstat|iface-list|domuuid|domid|domname|domdisplay|domjobinfo"
                     r"|nodedev-list)(?: \S+)*", vals="-c --connect", deny="--set --config"))
_add("qm", _forms(r"list|(?:status|config|pending|showcmd|listsnapshot) \S+(?: \S+)*"))
_add("pct", _forms(r"list|(?:status|config|pending|listsnapshot|df) \S+(?: \S+)*"))
_add("pvesh", _forms(r"(?:get|ls) \S+(?: \S+)*"))
_add("pvecm", _forms(r"status|nodes"))
_add("pvesm", _forms(r"status|list \S+(?: \S+)*"))
_add("pveversion", ANY)
_add("ceph", _or(_each(r"-s|--status"), _forms(r"status|health(?: detail)?|df(?: detail)?|versions?|osd (?:tree|df|stat|ls|dump|perf|pool ls(?: detail)?|pool stats"
                                               r"|utilization)(?: \S+)*|mon (?:stat|dump)|pg (?:stat|dump(?: \S+)*)|fs (?:ls|status)(?: \S+)*|mgr stat|quorum_status",
                                               allow="-f --format")))
_add("xl", _forms(r"(?:list|info|uptime|vcpu-list|dmesg)(?: \S+)*"))
_add("vboxmanage VBoxManage", _forms(r"(?:list|showvminfo|showhdinfo)(?: \S+)*|", allow="--version -v --machinereadable --details -l --long -s --sorted"))
_add("vagrant", _forms(r"status(?: \S+)?|global-status|version|port(?: \S+)?|ssh-config(?: \S+)?|", allow="--version -v --prune --machine-readable"))
_add("esxcli", _esxcli)
_add("vim-cmd", _rx(r"vmsvc/(?:getallvms|get\.\w+ \d+|power\.getstate \d+)|hostsvc/(?:hostsummary|hosthardware)"))
_add("git", _git)
_add("rsync", _rsync)
_add("terraform tofu", _forms(r"version|show(?: \S+)?|output(?: \S+)*|state (?:list|show|pull)(?: \S+)*|providers(?: schema)?|validate|graph|workspace (?:list|show)|plan|",
                              deny="-out -generate-config-out"))
_add("ansible", _ansible)
_add("ansible-playbook", lambda a, c=None: bool({"--list-hosts", "--list-tasks", "--list-tags", "--syntax-check", "--version"} & set(a)))
_add("ansible-inventory", _only("--list --graph --host= -i= --inventory= -y --yaml --vars --toml", need="--list --graph --host"))
_add("ansible-config", _forms(r"(?:dump|list|view)(?: \S+)*"))
_add("ansible-galaxy", _forms(r"(?:collection |role )?list(?: \S+)*"))
_add("aws", _aws)
_add("az gcloud", _cloud)

# Programs that say what version they are and do nothing else when asked only that.
_VERSIONED = set("""python2 node nodejs java javac ruby perl go rustc cargo gcc g++ cc clang make cmake docker podman kubectl helm ansible nginx apache2 httpd
    mysql mariadb psql sqlite3 redis-cli redis-server openssl ssh git npm npx pip pip3 pipx uv yarn pnpm dotnet az aws
    gcloud curl wget nmap rsync tar gzip systemd systemctl mongod mongosh mongo postgres mysqld dockerd containerd runc k3s kubeadm kubelet etcd consul
    vault nomad packer vagrant vim nvim nano tmux screen lsof strace gdb php terraform tofu ffmpeg ffprobe iperf3""".split())
_VERSION_ARGS = (["--version"], ["-version"], ["version"], ["--help"])
# -v and -V say the version to some and mean "verbose" (and then a prompt, or an editor) to others
_VERSION_SHORT = {"-v": set("node nodejs perl ruby gcc g++ cc clang make git docker podman nginx npm npx yarn pnpm redis-cli redis-server terraform tofu lsof gdb screen php".split()),
                  "-V": set("python2 pip pip3 curl wget nmap rsync ssh mysql mariadb psql nginx httpd apache2 strace tmux nano".split())}

# Windows' own tools, by lower-case name; their arguments are compared in lower case too.
_WINDOWS: dict[str, object] = {name: ANY for name in """tasklist systeminfo whoami ver vol findstr comp getmac quser qwinsta qprocess driverquery
    dsquery dsget pathping tracert where""".split()}
_WINDOWS.update({
    "ipconfig": _each(r"/(?:all|displaydns|allcompartments)"),
    "sc": _rx(r"(?:\\{1,2}\S+ )?(?:query|queryex|qc|qdescription|qfailure|qfailureflag|qtriggerinfo|qsidtype|qprivs|enumdepend|sdshow|getdisplayname|getkeyname)(?: \S+)*"),
    "wmic": _wmic,
    "reg": _rx(r"(?:query|compare)(?: \S+)*"),
    "netsh": _netsh,
    "schtasks": _rx(r"|/query(?: \S+)*"),
    "nltest": _each(r"/(?:dsgetdc|dclist|domain_trusts|dsgetsite|sc_query|sc_verify|whowill|finduser|dnsgetdc|dsgetfti|user|server|query|trusted_domains|parentdomain"
                    r"|dcname|dsaddresstosite|dsgetsitecov|all_trusts|primary|forest|v|force|pdc|ds|gc|kdc|timeserv|writable|ip|netbios|dns|site|account|ret_dns"
                    r"|ret_netbios)(?::\S*)?"),
    "dcdiag": _each(r"/(?:s|u|p|test|skip|c|e|a|q|v|i|n|dnsall|dnsbasic|dnsforwarders|dnsdelegation|dnsdynamicupdate|dnsrecordregistration|dnsresolveextname"
                    r"|dnsinternettld|d)(?::\S*)?|(?![-/])[\w.*-]+"),
    "repadmin": _each(r"/(?:show\w+|replsum\w*|queue|viewlist|istg|bridgeheads|latency|failcache|csv|errorsonly|verbose|all|bysrc|bydest|sort:\S+|repsto|conn"
                      r"|intersite|nocache|u:\S+|pw:\S+|homeserver:\S+)|(?![-/])[\w.*,=:-]+", need=r"/(?:show\w+|replsum\w*|queue|viewlist|istg|bridgeheads|latency|failcache)"),
    "gpresult": _each(r"/(?:r|v|z|scope|user|s|u|p)|(?![-/])[\w.\\@-]+", need=r"/[rvz]"),
    "w32tm": _rx(r"/(?:query|monitor|stripchart|tz|dumpreg|ntte|ntpte)(?: \S+)*"),
    "bcdedit": _rx(r"|/enum(?: \S+)*|/v"),
    "manage-bde": _rx(r"-status(?: \S+)*|-protectors -get(?: \S+)*|-protectors \S+ -get"),
    "vssadmin": _rx(r"list (?:shadows|shadowstorage|writers|providers|volumes)(?: \S+)*"),
    "wbadmin": _rx(r"get (?:versions|items|disks|status|virtualmachines)(?: \S+)*"),
    "wevtutil": _rx(r"(?:el|enum-logs|gl|get-log|qe|query-events|gli|get-log-info|ep|enum-publishers|gp|get-publisher)(?: \S+)*"),
    "fsutil": _rx(r"fsinfo(?: \S+)*|volume (?:diskfree|list|query\w*)(?: \S+)*|(?:dirty|behavior|quota|repair|resource|usn|8dot3name|sparse|reparsepoint|objectid) quer\w+(?: \S+)*"),
    "powercfg": _rx(r"[/-](?:a|availablesleepstates|list|l|query|q|getactivescheme|devicequery|lastwake|waketimers|requests|aliases)(?: \S+)*"),
    "chkdsk": _each(r"[a-z]:"),
    "sfc": _rx(r"/verifyonly|/verifyfile=\S+"),
    "dism": _dism,
    "certutil": _each(r"-(?:store|verifystore|dump|verify|ping|cainfo|hashfile|getreg|user|enterprise|v|gmt|seconds|view|restrict|out|config|urlfetch|tcainfo|dcinfo"
                      r"|template|templates|catemplates)|[^-/].*", need=r"-(?:store|verifystore|dump|verify|ping|cainfo|hashfile|getreg|view|tcainfo|dcinfo|template"
                                                                          r"|templates|catemplates)"),
    "auditpol": _rx(r"/(?:get|list)(?: \S+)*"),
    "openfiles": _rx(r"|/query(?: \S+)*"),
    "logman": _rx(r"|query(?: \S+)*"),
    "typeperf": _each(r"(?!-(?:o|f|config|cf|y)$).*"),
    "pnputil": _rx(r"/(?:enum-devices|enum-drivers|enum-interfaces|enum-classes|e|\?)(?: \S+)*"),
    "mountvol": _rx(r""),
    "fltmc": _rx(r"|filters|instances(?: \S+)*|volumes"),
    "path": _rx(r""),
    "chcp": _rx(r""),
    "cls": _rx(r""),
    "subst": _rx(r""),
    "doskey": _rx(r"/history"),
    "assoc": _each(r"[^=]+", max_args=1),
    "ftype": _each(r"[^=]+", max_args=1),
    "query": _rx(r"(?:user|session|process|termserver)(?: \S+)*"),
    "cmdkey": _rx(r"/list(?::\S+)?"),
    "winrm": _rx(r"(?:get|enumerate|e|g|id|identify)(?: \S+)*"),
    "tzutil": _rx(r"/[gl]"),
    "netdom": _rx(r"query(?: \S+)*"),
    "slmgr": _rx(r"/(?:dli|dlv|xpr)"),
    "dsregcmd": _rx(r"/status"),
    "icacls": _each(r"/(?:t|c|l|q|verify)|/findsid|[^/].*"),
    "attrib": _each(r"(?![+-][rashoixvpu]$).+"),
    "cacls": _each(r"[^/].*", max_args=1),
    "mode": _rx(r"|con|com\d+"),
})

# PowerShell. A cmdlet reads when its verb does, for the nouns given (None: any noun).
_PS_VERBS: dict[str, set | None] = {
    "get": None, "test": None, "resolve": None, "convertto": None, "convertfrom": None, "find": None,
    "search": {"adaccount", "unifiedauditlog", "adminauditlog", "mailboxauditlog"},      # (Search-Mailbox can delete what it finds)
    "select": {"object", "string", "xml"}, "where": {"object"}, "sort": {"object"}, "group": {"object"}, "measure": {"object", "command"},
    "format": {"table", "list", "wide", "custom", "hex"}, "out": {"null", "string", "host", "default"}, "compare": {"object"},
    "write": {"output", "host", "verbose", "warning", "error", "debug", "information", "progress"}, "join": {"path", "string"}, "split": {"path"},
    # these change only something of the console they run in: where it stands, a variable, a remote session it opened
    "start": {"sleep"}, "clear": {"host"}, "set": {"location", "strictmode", "variable"}, "push": {"location"}, "pop": {"location"},
    "new": {"timespan", "guid", "pssessionoption", "cimsessionoption", "variable"}, "remove": {"variable", "pssession", "cimsession"}, "add": {"member"},
}
_PS_NOT = {"get-wuinstall", "get-wuuninstall", "test-cluster", "test-mailflow"}
# parameters that make a Get- or a Test- do something: checked as the start of a name, as PowerShell accepts them
_PS_DENY = ("install", "acceptall", "autoreboot", "download", "repair", "fix", "outfile", "append", "remove", "delete", "reset", "restart", "clear", "kill")
_PS_ALIASES = {"gci": "get-childitem", "gc": "get-content", "gps": "get-process", "gsv": "get-service", "gwmi": "get-wmiobject", "gcim": "get-ciminstance",
               "select": "select-object", "?": "where-object", "ft": "format-table", "fl": "format-list", "fw": "format-wide",
               "measure": "measure-object", "group": "group-object", "%": "foreach-object", "gi": "get-item", "gl": "get-location", "gcm": "get-command", "gal": "get-alias", "gv": "get-variable",
               "gdr": "get-psdrive", "ghy": "get-history", "h": "get-history", "gjb": "get-job", "gmo": "get-module", "gu": "get-unique", "sl": "set-location",
               "oh": "out-host", "iwr": "invoke-webrequest", "irm": "invoke-restmethod", "icm": "invoke-command",
               "rvpa": "resolve-path", "tnc": "test-netconnection", "ipmo": "import-module", "gsn": "get-pssession", "gin": "get-computerinfo",
               "gtz": "get-timezone"}
_PS_TYPES = set("""net.networkinformation.ping net.sockets.tcpclient diagnostics.stopwatch psobject pscustomobject object collections.arraylist
    collections.hashtable hashtable text.stringbuilder version uri datetime timespan security.principal.windowsprincipal
    directoryservices.directorysearcher directoryservices.directoryentry management.managementobjectsearcher""".split())
_PS_TYPE_GENERIC = re.compile(r"collections\.generic\.\w+\[[\w.,]+\]")
# Methods that compute, format, look up or probe, on whatever they are called: nothing here changes what it is called on.
_PURE_METHODS = set("""tostring toupper tolower toupperinvariant tolowerinvariant trim trimstart trimend split substring contains startswith
    endswith indexof lastindexof padleft padright equals compareto gettype round floor ceiling abs max min pow sqrt truncate parse tryparse parseexact
    join isnullorempty isnullorwhitespace adddays addhours addminutes addseconds addmonths addyears addmilliseconds addticks subtract
    tolocaltime touniversaltime tofiletime tofiletimeutc fromfiletime fromfiletimeutc fromseconds fromminutes fromhours fromdays frommilliseconds
    gethostentry gethostaddresses gethostname gethostbyname gethostbyaddress resolve getstring getbytes tobase64string frombase64string toint32
    toint64 todouble todatetime toboolean tochar tobyte combine getfilename getfilenamewithoutextension getextension getdirectoryname getfullpath
    gettemppath exists readalltext readalllines readlines readallbytes getfiles getdirectories getlastwritetime getcreationtime
    getenvironmentvariable getenvironmentvariables getfolderpath getcurrent getcurrentdomain getcurrentforest getcomputerdomain isinrole match
    matches ismatch escape newguid startnew where getenumerator getvalue getvaluenames getsubkeynames opensubkey getowner converttodatetime
    getrelated getaccesscontrol connect connectasync beginconnect wait waitone endconnect close dispose findall findone getipproperties
    getallnetworkinterfaces getipglobalproperties getactivetcplisteners getactivetcpconnections tochararray gethashcode totitlecase normalize
    getdomain getforest finddomaincontroller count first last any all sum average skip take reverse distinct toarray tolist containskey
    getnewclosure getdrives""".split())
# Called on a type itself, [type]::Method(...): only on the types that compute, convert or look up; and of a file or
# a folder only what reads it.
_PS_STATIC = set("""math string datetime timespan convert int int32 int64 long double decimal bool char byte guid regex version ipaddress uri net.dns
    net.ipaddress text.encoding io.path environment diagnostics.stopwatch security.principal.windowsidentity timezoneinfo globalization.cultureinfo
    directoryservices.activedirectory.domain directoryservices.activedirectory.forest net.networkinformation.networkinterface
    net.networkinformation.ipglobalproperties io.driveinfo""".split())
_PS_STATIC_ALSO = {"replace", "format"}          # [regex]::Replace, [string]::Format: pure on these types
_PS_FILE_READS = set("""exists readalltext readalllines readlines readallbytes getfiles getdirectories getlastwritetime getcreationtime
    getlastaccesstime getattributes enumeratefiles enumeratedirectories getfilesystementries getlogicaldrives getcurrentdirectory""".split())
_ICM_PARAMS = {"computername", "cn", "session", "credential", "scriptblock", "erroraction", "ea", "authentication", "usessl", "port", "hidecomputername",
               "throttlelimit", "argumentlist", "sessionoption", "configurationname", "vmname", "vmid", "containerid", "hostname", "username"}
_WEB_PARAMS = {"uri", "usebasicparsing", "method", "headers", "timeoutsec", "maximumredirection", "useragent", "skipcertificatecheck", "usedefaultcredentials",
               "credential", "erroraction", "ea", "disablekeepalive", "contenttype", "proxy", "proxyusedefaultcredentials", "sslprotocol", "nocache",
               "skiphttperrorcheck", "authentication", "token", "websession", "sessionvariable", "resume", "maximumretrycount", "retryintervalsec",
               "verbose", "certificatethumbprint", "certificate"}


def _ps_type(name: str) -> bool:
    name = name.lower().strip("[]")
    name = name[7:] if name.startswith("system.") else name
    return name in _PS_TYPES or _PS_TYPE_GENERIC.fullmatch(name) is not None


def _cmdlet(chk: "_Check", name: str, args: list, inblock: bool) -> bool:
    """Whether this cmdlet, with these arguments, only reads. A script block given to it is code that
    it may run, so it must only read as well (but for the filter of an AD cmdlet, which is a query)."""
    verb, _, noun = name.partition("-")
    params = [x.s[1:].split(":", 1)[0].lower() for x in args if x.lead == "lit" and len(x.s) > 1 and x.s[0] == "-" and x.s[1].isalpha()]
    typed = None                                 # New-Object's type, written as Type(arguments): no method call
    if name == "new-object":
        typed = next((x for k, x in enumerate(args) if not x.s.startswith("-") and (k == 0 or args[k - 1].s.lower() not in ("-argumentlist", "-property"))), None)
    after = ""
    for x in args:
        if x.lead == "brace" and x.raw == "{}" and after == "-filter" and name.startswith(("get-ad", "search-ad")):
            for pipe in x.groups[0][1]:          # {Name -like "x*" -and Enabled -eq $true}
                for words, side in pipe:
                    for y in words + side:
                        chk.inert(y, True)
        elif x is typed and x.groups:
            for g in x.groups:
                if g[0] != "call":
                    return False
                for pipe in g[2]:
                    for words, side in pipe:
                        for y in words + side:
                            chk.inert(y, True)
        else:
            chk.inert(x, inblock)
        after = x.s.lower() if x.plain else ""
    if any("win32_product" in x.s.lower() for x in args):
        return False                             # listing it makes Windows Installer check, and repair, every package
    if name == "foreach-object":
        # blocks only: `% Name` reads a property of that name, or calls a method of that name
        return all((x.lead == "brace" and x.raw == "{}") or (x.plain and (x.s.lower() in ("-begin", "-process", "-end", "-parallel", "-throttlelimit") or x.s.isdigit()))
                   for x in args)
    if name == "new-object":
        if typed is None or "comobject" in params or "com" in params:
            return False
        raw = typed.raw.split("()")[0] if typed.groups else typed.s
        return _ps_type(raw)
    if name == "import-module":
        return all(x.plain and (re.fullmatch(r"[\w.]+", x.s) and not x.s.lower().endswith((".ps1", ".psm1", ".psd1", ".dll"))
                                or x.s.lower() in ("-name", "-erroraction", "-force", "-verbose", "-disablenamechecking", "-skipeditioncheck", "-global",
                                                   "-passthru")) for x in args)
    if name == "add-type":
        return len(args) == 2 and args[0].s.lower() == "-assemblyname" and args[1].plain and re.fullmatch(r"[\w.]+", args[1].s) is not None
    if name == "invoke-command":
        return all(p in _ICM_PARAMS for p in params) and any(x.lead == "brace" for x in args)
    if name in ("invoke-webrequest", "invoke-restmethod"):
        for k, x in enumerate(args):
            if x.plain and x.s.lower() in ("-method", "-me") and (k + 1 >= len(args) or args[k + 1].s.lower() not in ("get", "head", "options")):
                return False
        return all(p in _WEB_PARAMS for p in params)
    nouns = _PS_VERBS.get(verb, ())
    if nouns is not None and noun not in nouns:
        return False
    if name in _PS_NOT:
        return False
    return not any(d.startswith(p) or p.startswith(d) for p in params if len(p) >= 3 for d in _PS_DENY)


# Network devices: commands that display. `sh` is also a shell, so its first word must be one a
# switch or a router completes to a `show` command.
_DEVICE = {"show", "sh", "sho", "display", "dis", "get", "diagnose", "diag", "execute", "terminal", "term"}
_DEVICE_FILTERS = {"include", "exclude", "begin", "section", "count", "match", "except", "no-more", "nomore", "trim", "json", "i", "incl", "e", "exc",
                   "b", "beg", "s", "sec", "sect", "compare"}
# words a device prints, which stand as alternatives in a filter's pattern (`| include up|down`), and the shape of a
# port's or a VLAN's name or an address there (Gi1/0/2, Vlan10, 10.0.0.1): none is a program a POSIX shell would find
_DEVICE_WORDS = set("""up down connected notconnect notconnected disabled err-disabled errdisabled administratively trunk access active inactive full
    half auto error errors drops crc input output protocol vlan interface description hostname version uptime permit deny established idle
    static native suspended routed unassigned assigned manual dhcp fail failed failure warning critical collisions runts giants duplex speed
    flap flapping blocked forwarding listening learning designated alternate""".split())
_DEVICE_NAME = re.compile(r"(?=[^/]*[A-Z0-9])[A-Za-z0-9][\w.:-]*(?:/[\w.:-]+)*")
_SH_WORDS = set("""run running-config start startup-config ver version ip ipv6 int interface interfaces vlan vlans mac arp cdp lldp log logging clock inv
    inventory env environment proc processes mem memory flash boot users line spanning-tree span etherchannel port-channel access-lists access-list
    route bgp ospf eigrp crypto standby vrrp hsrp ntp snmp tech tech-support controllers power module switch stack license platform policy-map
    class-map nat dhcp history sessions ssh aaa vtp trunk config configuration system hardware redundancy failover conn xlate nameif cpu file
    archive debug debugging privilege terminal diag errdisable storm-control monitor track udld vpc fex feature bfd mpls vrf isis rip pim igmp qos
    queue queueing port-security authentication dot1x radius tacacs wireless ap wlan client""".split())
_FORTI_ROOTS = {"system", "router", "hardware", "vpn", "firewall", "log", "user", "wireless-controller", "switch-controller", "webfilter", "antivirus",
                "ips", "application", "endpoint-control", "report", "test", "extender", "ipsec"}
_ROUTEROS_MENUS = {"ip", "ipv6", "interface", "system", "routing", "log", "tool", "user", "queue", "ppp", "certificate", "snmp", "radius", "port", "file",
                   "disk", "caps-man", "mpls", "container", "export"}
_ROUTEROS_READS = {"print", "export", "ping"}
_ROUTEROS_CHANGES = {"set", "add", "remove", "enable", "disable", "edit", "unset", "move", "reset", "reset-configuration", "reboot", "shutdown", "import",
                     "run", "upgrade", "install", "uninstall", "save", "load", "restore", "flush", "release", "renew", "fetch", "comment", "make-static"}


def _device(name: str, a: list[str], words: list) -> bool:
    if any(w.exps or w.groups for w in words):
        return False
    if name == "show":
        return True
    if name in ("display", "dis"):               # (elsewhere `display` shows a picture, and can be told to write one)
        return bool(a) and not any(x.startswith("-") for x in a)
    if name in ("sh", "sho"):
        return bool(a) and a[0] in _SH_WORDS
    if name == "get":
        return bool(a) and a[0] in _FORTI_ROOTS
    if name in ("diagnose", "diag"):
        return bool(set(a) & {"list", "status", "show", "info", "stats", "summary", "top"} or a[:1] in (["hardware"], ["sniffer"])) and not set(a) & {
            "kill", "clear", "reset", "restart", "enable", "disable", "set", "delete", "flush", "purge", "shutdown", "reboot", "execute", "start", "stop",
            "test"}
    if name == "execute":                        # FortiOS: its probes, and the log viewer with the filter it keeps for this console
        return re.fullmatch(r"log display|log filter(?: \S+)+|ping6? \S+|traceroute \S+|tracert6 \S+|ping6?-options(?: \S+)+", " ".join(a)) is not None
    return re.fullmatch(r"(?:length|len|width|pager) \d+|(?:no )?monitor", " ".join(a)) is not None


# ---- commands that run another command: the rest of the line (or the text given) is checked in its place

_PASS = object()                                 # not the form that runs another command: look the name up as a reader


def _w_sudo(chk, args):
    i = 0
    while i < len(args):
        x = args[i]
        if x.exps or x.groups or not x.s.startswith("-"):
            break
        i += 1
        if x.s == "--":
            break
        if x.s in ("-l", "-ll", "-v", "-V", "--list", "--validate", "--version"):
            return None                          # what may be run, or the timestamp renewed: nothing is run
        if x.s in ("-u", "-g", "--user", "--group"):
            i += 1
        elif x.s not in ("-n", "-E", "-H", "-nE", "-En", "--non-interactive", "--preserve-env") and not x.s.startswith(("--user=", "--group=")):
            raise _No                            # -i, -s: a shell; -e: an editor
    if i >= len(args):
        raise _No
    return args[i:]


def _w_env(chk, args):
    i = 0
    while i < len(args) and args[i].plain and args[i].s.startswith("-"):
        s = args[i].s
        i += 1
        if s in ("-u", "--unset"):
            i += 1
        elif s == "--":
            break
        elif s not in ("-i", "--ignore-environment", "-0", "--null", "-") and not s.startswith("--unset="):
            raise _No                            # -S splits a string into a command
    return args[i:] or None                      # alone it prints the environment


def _skipping(flags: str = "", vals: str = "", operand: bool = False, alone=None):
    """A prefix with options of its own (`x=` takes a value), perhaps one operand (timeout's duration), then the command."""
    flag_set, val_set = set(flags.split()), set(vals.split())

    def wrapper(chk, args):
        if alone is not None and alone([x.s.lower() for x in args]):
            return None
        i = 0
        while i < len(args) and args[i].plain and args[i].s.startswith("-") and len(args[i].s) > 1:
            s = args[i].s
            i += 1
            if s in val_set:
                i += 1
            elif s not in flag_set and s.split("=", 1)[0] not in val_set and not re.fullmatch(r"-\d+", s):
                raise _No
        i += operand
        if i >= len(args):
            raise _No
        return args[i:]
    return wrapper


def _w_command(chk, args):
    if args and args[0].plain and args[0].s in ("-v", "-V"):
        return None                              # says what a name would run
    return _skipping("-p")(chk, args)


def _w_xargs(chk, args):
    """xargs gives its command arguments the rules can't see, so only a reader that reads whatever its arguments."""
    i = 0
    while i < len(args) and args[i].plain and args[i].s.startswith("-"):
        s = args[i].s
        i += 1
        if s in ("-n", "-L", "-P", "-I", "-d", "-a", "-s", "-E"):
            i += 1
        elif not re.fullmatch(r"-[0rtx]+|--(?:null|no-run-if-empty|verbose|exit|max-args=\d+|max-procs=\d+|max-lines=\d+|delimiter=.+|arg-file=.+|replace(?:=.+)?)|-[nLPIs]\S+", s):
            raise _No
    rest = args[i:]
    if rest and _READERS.get(chk.name(rest[0])) is not ANY:
        raise _No
    for x in rest:
        chk.inert(x)
    return None


def _w_shell(chk, args):
    i = 0
    while i < len(args):
        x = args[i]
        if not x.plain or not x.s.startswith("-"):
            break
        i += 1
        if re.fullmatch(r"-[lexu]*c", x.s):      # -c, -lc, -ec: the next word is the text to run; what follows it is $0, $1...
            if i >= len(args) or args[i].exps or args[i].groups:
                raise _No
            chk.text(args[i].s)
            return None
        if x.s in ("--version", "--help"):
            return None
        if not re.fullmatch(r"-[lexu]+|--login|--norc|--noprofile|--posix", x.s):
            raise _No
    return _PASS                                 # a script to run, which is no reader; or a switch's `sh ip int br`


_SSH_FLAGS = re.compile(r"-[46AaCkqTtvxXYy]+")
_SSH_OPTIONS = re.compile(r"(?:StrictHostKeyChecking|ConnectTimeout|BatchMode|UserKnownHostsFile|LogLevel|PreferredAuthentications|PubkeyAuthentication"
                          r"|PasswordAuthentication|ServerAliveInterval|ServerAliveCountMax|IdentitiesOnly|Port|User|ConnectionAttempts|AddressFamily"
                          r"|NumberOfPasswordPrompts|KbdInteractiveAuthentication|HostKeyAlgorithms|KexAlgorithms|Ciphers|MACs|PubkeyAcceptedAlgorithms"
                          r"|PubkeyAcceptedKeyTypes)[= ]\S*", _I)


def _w_ssh(chk, args):
    """ssh host command: the remote shell reads the command's words again, joined by spaces."""
    i = 0
    while i < len(args) and args[i].s.startswith("-"):
        x = args[i]
        i += 1
        if x.exps or x.groups:
            raise _No
        if x.s in ("-p", "-i", "-l", "-J", "-b", "-c", "-m"):
            i += 1
        elif x.s == "-o":
            if i >= len(args) or not _SSH_OPTIONS.fullmatch(args[i].s):
                raise _No                        # ProxyCommand, LocalCommand...: a command run here
            i += 1
        elif x.s == "-V" and len(args) == 1:
            return None
        elif not _SSH_FLAGS.fullmatch(x.s) and not (x.s.startswith("-o") and _SSH_OPTIONS.fullmatch(x.s[2:])) and not re.fullmatch(r"-p\d+", x.s):
            raise _No
    rest = args[i + 1:]
    if i >= len(args) or not rest or any(x.exps or x.groups for x in args[i:]):
        raise _No                                # no command: a login, where anything may be typed
    chk.text(" ".join(x.s for x in rest))
    return None


def _w_container(chk, args):
    """docker exec NAME command, podman's and nerdctl's: the command is run as given, with no shell between."""
    plain = [x.s for x in args]
    i = 1 if plain[:1] == ["compose"] else 0
    if plain[i:i + 1] != ["exec"]:
        return _PASS
    i += 1
    while i < len(args) and args[i].s.startswith("-"):
        s = args[i].s
        i += 1
        if s in ("-u", "--user", "-w", "--workdir", "--index"):
            i += 1
        elif not re.fullmatch(r"-[itT]+|--interactive|--tty|--privileged|--no-TTY|--(?:user|workdir|index)=\S+", s):
            raise _No                            # -e NAME=value, -d
    if i + 1 >= len(args) or args[i].exps or args[i].groups:
        raise _No
    return args[i + 1:]


def _w_kubectl(chk, args):
    plain = [x.s for x in args]
    if "exec" not in plain[:7]:
        return _PASS
    if "--" not in plain or any(x.exps or x.groups for x in args[:plain.index("--")]):
        raise _No
    k = plain.index("--")
    before = plain[:k]
    j = 0
    while j < len(before):
        s = before[j]
        j += 1
        if s in ("-n", "--namespace", "-c", "--container", "--context", "--kubeconfig"):
            j += 1
        elif s.startswith("-") and not re.fullmatch(r"-[it]+|--stdin|--tty|--(?:namespace|container|context|kubeconfig)=\S+", s):
            raise _No
    if k + 1 >= len(args):
        raise _No
    return args[k + 1:]


def _w_wsl(chk, args):
    i = 0
    while i < len(args) and args[i].plain and args[i].s.startswith("-"):
        s = args[i].s.lower()
        i += 1
        if s in ("-l", "--list", "--status", "--version", "-v", "--verbose", "--running", "--all", "--quiet", "-q", "--online", "-o"):
            if not all(x.plain and x.s.startswith("-") for x in args):
                raise _No
            return None
        if s in ("-d", "--distribution", "-u", "--user"):
            i += 1
        elif s in ("-e", "--exec", "--"):
            break
        else:
            raise _No
    if i >= len(args) or any(x.exps or x.groups for x in args[i:]):
        raise _No
    chk.text(" ".join(x.s for x in args[i:]))    # the distribution's shell reads the words again
    return None


def _w_powershell(chk, args):
    """powershell -Command "text" (or pwsh): the text is a script. -File and -EncodedCommand can't be read."""
    i = 0
    while i < len(args):
        x = args[i]
        s = "-" + x.s[1:].lower()
        if not x.plain or x.s[:1] not in "-/":
            break
        i += 1
        if s in ("-executionpolicy", "-ep", "-exec", "-ex", "-windowstyle", "-w", "-outputformat", "-of", "-inputformat", "-if"):
            i += 1
        elif s in ("-command", "-c"):
            rest = args[i:]
            if len(rest) == 1 and rest[0].lead == "brace" and rest[0].raw == "{}":
                chk.script(rest[0].groups[0][1], True)
            elif not rest or any(y.exps or y.groups for y in rest):
                raise _No
            else:
                chk.text(rest[0].s if len(rest) == 1 else " ".join(y.raw for y in rest))
            return None
        elif s in ("-version", "-v", "-help", "-h", "-?") and len(args) == 1:
            return None
        elif s not in ("-noprofile", "-nop", "-noninteractive", "-noni", "-nologo", "-nol", "-mta", "-sta"):
            raise _No
    raise _No


def _w_cmd(chk, args):
    """cmd /c text: cmd.exe reads the rest of the line again."""
    i = 0
    while i < len(args) and args[i].plain and args[i].s.lower() in ("/d", "/q", "/s", "/u", "/a"):
        i += 1
    if i >= len(args) or args[i].s.lower() != "/c" or i + 1 >= len(args) or any(x.exps or x.groups for x in args[i + 1:]):
        raise _No                                # /k leaves a shell open; alone it is one
    rest = args[i + 1:]
    chk.text(rest[0].s if len(rest) == 1 else " ".join(x.raw for x in rest))
    return None


_WRAPPERS = {
    "sudo": _w_sudo, "doas": _w_sudo, "env": _w_env, "command": _w_command, "xargs": _w_xargs, "ssh": _w_ssh, "kubectl": _w_kubectl, "oc": _w_kubectl,
    "k": _w_kubectl, "docker": _w_container, "podman": _w_container, "nerdctl": _w_container, "wsl": _w_wsl, "powershell": _w_powershell,
    "pwsh": _w_powershell, "cmd": _w_cmd,
    "time": _skipping("-p -v", alone=lambda a: a == ["/t"]), "nice": _skipping("", "-n --adjustment"), "ionice": _skipping("-t", "-c -n --class --classdata"),
    "timeout": _skipping("--foreground --preserve-status -v --verbose", "-s --signal -k --kill-after", operand=True),
    "stdbuf": _skipping("-oL -eL -iL -o0 -e0 -i0", "-o -e -i --output --error --input"), "builtin": _skipping(), "busybox": _skipping(), "toybox": _skipping(),
}
_WRAPPERS.update({name: _w_shell for name in ("sh", "bash", "zsh", "dash", "ksh", "ash")})
_WRAPPERS_NOCASE = {"powershell", "pwsh", "cmd", "wsl"}


# ---------------------------------------------------------------------------------------
# What the deny-list reads, and the verdicts.

# Rules about shell syntax (redirects, where a command starts). Inside quotes these characters
# are data, e.g. `awk 'NR>1{...}'`, so they are matched against the command with quoted text blanked.
_SHELL_SYNTAX = {r[0] for r in DISRUPTIVE + MODIFYING if r[0].pattern.startswith(CMD)} | {
    r[0] for r in MODIFYING if r[1] in ("output redirect to file", "package change")}

# Finding where a command starts is the costly part of those rules, and most commands hold none of the
# words a rule is about: each such rule is first asked for by its words alone, wherever they stand.
_WORDS_OF = {r[0]: re.compile(r"(?<!\w)(?:" + r[0].pattern[len(CMD):] + r")", r[0].flags & (re.I | re.M))
             for r in DISRUPTIVE + MODIFYING if r[0].pattern.startswith(CMD)}

# Commands that hand quoted text to a shell again, or to an interpreter as code: their quotes hide nothing.
_REPARSES = re.compile(
    r"\b((ba|z|k|da|a|fi|)sh|su|runuser|script|env)\s+(\S+\s+){0,8}?-[a-zA-Z]*c\b|\b(ssh|eval|xargs|parallel|watch|nohup|timeout|chroot|wsl|psexec|schtasks|at)\b"
    r"|\s-exec(dir)?\b|\b(powershell|pwsh)\b|\bcmd\s+/[ck]\b|\b(python[23]?|perl|ruby|node|php)\s+(\S+\s+){0,4}?-[cer]\b|\|\s*(sudo\s+)?(ba|z|k|da|)sh\b"
    r"|\bbinpath=", _I)

# awk can write files and run commands from inside its program text.
_AWK = re.compile(r"\b[gmn]?awk\b")


def _quoted(command: str) -> tuple[str, list[str]] | None:
    """(command with the contents of '...' and "..." blanked, the quoted texts), or None when
    the quoting can't be read with confidence (unterminated, `$'...'` with escapes of its own, or
    $(...)/backticks inside "...", which the shell does run)."""
    out, texts, i, n = [], [], 0, len(command)
    while i < n:
        c = command[i]
        if c == "\\" and i + 1 < n:
            out.append(command[i:i + 2])
            i += 2
        elif c in "'\"":
            if c == "'" and i and command[i - 1] == "$":
                return None
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


# A command written to slip past a rule's wording runs all the same: `r\m`, `'rm' -rf`, `r''m`,
# `rm${IFS}-rf`, `Rem`ove-Item`, `shutdown.exe`, `C:\Windows\System32\shutdown /r`. The rules also
# read the command with such marks taken out. A backslash is an escape to a POSIX shell and a
# path's separator to Windows, where `\"` ends a string too, so there are two such copies.
_IFS = re.compile(r"\$\{IFS\}|\$IFS\b")
_EMPTY_QUOTES = re.compile(r"(?<=[\w-])(?:''|\"\")(?=[\w-])")
_QUOTED_WORD = re.compile(r"(['\"])([\w./:\\+=@%,~^-]+)\1")
_ESCAPE = re.compile(r"\\(?=[\w-])")
_CARET = re.compile(r"\^(?=[^\n])|`(?=[A-Za-z-])")
_EXE = re.compile(r"(?<=[\w)])\.exe\b", _I)


@functools.lru_cache(maxsize=8)
def _views(text: str) -> tuple[tuple[str, str], ...]:
    """The readings of a command that the rules are matched against: each is (the text, the text
    with quoted contents blanked for the rules about shell syntax)."""
    plain = _QUOTED_WORD.sub(r"\2", _EMPTY_QUOTES.sub("", _IFS.sub(" ", text)))
    seen, out = set(), []
    for view in (text, _EXE.sub("", _ESCAPE.sub("", plain)), _EXE.sub("", _CARET.sub("", plain.replace("\\", "/")))):
        if view not in seen:
            seen.add(view)
            q = None if _REPARSES.search(view) else _quoted(view)
            out.append((view, q[0] if q else view))
    return tuple(out)


def _deny(command: str) -> tuple[str, list[str]]:
    """What the deny-list says of a command, whether or not it is a known reader."""
    text, cut = bounded(command)
    views = _views(text)

    def hits(rules):
        out = []
        for pat, why in rules:
            words = _WORDS_OF.get(pat)
            if why in out or (words is not None and not any(words.search(shell) for _, shell in views)):
                continue
            if any(pat.search(shell if pat in _SHELL_SYNTAX else plain) for plain, shell in views):
                out.append(why)
        return out

    reasons = hits(DISRUPTIVE)
    if any(_SQL_CLIENT.search(plain) for plain, _ in views):
        reasons += [why for why in hits(_SQL) if why not in reasons]
    if reasons:
        return "disruptive", reasons + [TOO_LONG] * cut
    reasons = hits(MODIFYING)
    if _AWK.search(text):
        q = None if _REPARSES.search(text) else _quoted(text)
        if any(_AWK_WRITES.search(t) for t in (q[1] if q else [text])):
            reasons.append("awk writes a file or runs a command")
    if cut:
        reasons.append(TOO_LONG)
    if reasons:
        return "modifying", reasons
    return "read_only", []


def classify(command: str) -> tuple[str, list[str]]:
    """Return (level, reasons) for the command according to the deny-list. A command the allow-list
    confirms as a reader is read-only whatever words it holds: `grep -i restart`, `Get-Help
    Stop-Service` and `fdisk -l` name what they look for or list, and do none of it. `read_only`
    here means only that no rule spoke; whether it may stand is `effective`'s to say."""
    if reads_only(command):
        return "read_only", []
    return _deny(command)


def effective(model_level: str, command: str, shell: str = "") -> tuple[str, list[str]]:
    """Combine the model's label with local rules; the higher level wins. `read_only` stands only
    for a command the allow-list confirms: one the rules don't know is rated modifying. `shell`:
    "powershell" for a session that is PowerShell's alone (reads_only)."""
    local, reasons = classify(command)
    model_level = model_level if model_level in LEVELS else "modifying"
    level = max(model_level, local, key=LEVELS.index)
    if level == "read_only" and not reads_only(command, shell):
        return "modifying", [UNKNOWN]
    return level, reasons


def session_impact(command: str, session_kind: str) -> str | None:
    """Reason this command would cut the session it is run in, or None.

    session_kind is "local", "ssh", "winrm", "rdp" (typed into a window on the remote desktop),
    "window" (pasted into a remote-support tool's window). SSH sessions may reach a network
    device rather than a Linux host, so device rules are checked too. A command known only to
    read cuts nothing, whatever it names (`Get-Help Restart-Computer`)."""
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
    if reads_only(command, "powershell" if session_kind == "winrm" else ""):
        return None
    views = [plain for plain, _ in _views(bounded(command)[0])]
    for pat, why in rules:
        if any(pat.search(view) for view in views):
            return why
    return None
