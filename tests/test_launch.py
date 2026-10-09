"""A terminal program (its menu entry says Terminal=true) is started in a terminal window, the
desktop's own, with the command given the way that terminal takes it."""

from pathlib import Path

from davibemanager import launch


def which_of(*names):
    return lambda n: f"/usr/bin/{n}" if n in names else None


def test_the_desktops_own_terminal_comes_first_then_the_known_ones():
    cmd = ["/home/u/Applications/htop-dvm.AppImage"]
    # xdg-terminal-exec: the desktop's choice, as GLib (the menu) uses it
    assert launch.terminal_argv(cmd, {}, which_of("xdg-terminal-exec", "alacritty", "konsole")) == ["xdg-terminal-exec", *cmd]
    # Omarchy's session names it, and has alacritty and foot
    assert launch.terminal_argv(cmd, {"TERMINAL": "xdg-terminal-exec"}, which_of("alacritty", "foot")) == ["alacritty", "-e", *cmd]
    assert launch.terminal_argv(cmd, {"TERMINAL": "foot"}, which_of("alacritty", "foot")) == ["foot", *cmd]
    # the desktop in use, before another desktop's terminal that happens to be installed
    assert launch.terminal_argv(cmd, {"XDG_CURRENT_DESKTOP": "KDE"}, which_of("gnome-terminal", "konsole")) == ["konsole", "-e", *cmd]
    assert launch.terminal_argv(cmd, {"XDG_CURRENT_DESKTOP": "GNOME"}, which_of("gnome-terminal", "konsole")) == ["gnome-terminal", "--", *cmd]
    assert launch.terminal_argv(cmd, {"XDG_CURRENT_DESKTOP": "X-Cinnamon:GNOME"}, which_of("gnome-terminal")) == ["gnome-terminal", "--", *cmd]
    # one that takes the command as a string
    assert launch.terminal_argv(["/a b/x", "-q"], {}, which_of("tilix")) == ["tilix", "-e", "'/a b/x' -q"]
    # an unknown terminal named by the user: -e, the common way
    assert launch.terminal_argv(cmd, {"TERMINAL": "myterm"}, which_of("myterm")) == ["myterm", "-e", *cmd]
    # nothing to open it in
    assert launch.terminal_argv(cmd, {"TERMINAL": "/usr/bin/../evil"}, which_of()) is None


def test_whether_an_app_is_a_terminal_program_is_read_from_its_own_menu_entry(tmp_path):
    assert not launch.is_terminal_app(None) and not launch.is_terminal_app(tmp_path)
    (tmp_path / "app.desktop").write_text("[Desktop Entry]\nType=Application\nName=htop (DVM)\nExec=htop\nTerminal=true\n")
    assert launch.is_terminal_app(tmp_path)
    (tmp_path / "app.desktop").write_text("[Desktop Entry]\nType=Application\nName=gThumb (DVM)\nExec=gthumb\nTerminal=false\n")
    assert not launch.is_terminal_app(tmp_path)
