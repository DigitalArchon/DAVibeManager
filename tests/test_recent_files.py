"""The window's file choosers leave GTK's recent files list as it was (recentguard.py): GTK's chooser
adds every file chosen to $XDG_DATA_HOME/recently-used.xbel, writes the whole list from its model a
quarter of a second later (an entry older than 30 days dropped) and again as the main loop ends, and
the guard puts back what those writes changed. The window's choosers are WebKit's, for the page's
<input type="file">: attaching files, importing a .vibe, restoring a backup.

The logic is held here with a stand-in for GTK's manager and a list in a folder of the test's own;
then real choosers, under Xvfb in a process of their own (HOME and the XDG folders fresh temporary
ones, no session bus of the user's), a list seeded with an entry older than 30 days and the chosen
file's own earlier entry, which must be byte for byte as seeded after GTK's write and after the loop
has ended - and, with the guard off, isn't (GTK's writes are what the guard undoes)."""

import importlib.util
import inspect
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import textwrap
import time
from pathlib import Path
from unittest import mock

import pytest

from davibemanager import recentguard

SRC = Path(__file__).resolve().parents[1] / "src"
CANONICAL = Path(__file__).resolve().parents[2] / "DAAssistant" / "assistant" / "recentguard.py"
NOW = 1_800_000_000
APP = "davibemanager"


def entry(href, stamp="2026-09-01T10:00:00.000000Z", app="org.gnome.TextEditor"):
    return (f'  <bookmark href="{href}" added="{stamp}" modified="{stamp}" visited="{stamp}">\n'
            f'    <info>\n'
            f'      <metadata owner="http://freedesktop.org">\n'
            f'        <mime:mime-type type="text/plain"/>\n'
            f'        <bookmark:applications>\n'
            f'          <bookmark:application name="{app}" exec="&apos;{app} %u&apos;" modified="{stamp}" count="1"/>\n'
            f'        </bookmark:applications>\n'
            f'      </metadata>\n'
            f'    </info>\n'
            f'  </bookmark>\n').encode()


def xbel(*entries):
    return (b'<?xml version="1.0" encoding="UTF-8"?>\n<xbel version="1.0"\n'
            b'      xmlns:bookmark="http://www.freedesktop.org/standards/desktop-bookmarks"\n'
            b'      xmlns:mime="http://www.freedesktop.org/standards/shared-mime-info"\n'
            b'>\n' + b"".join(entries) + b'</xbel>')


class Info:
    def __init__(self, stamp):
        self.stamp = stamp

    def has_application(self, name):
        return name == APP

    def get_application_info(self, name):
        return (f"'{name} %u'", 1, self.stamp)


class Manager:
    """GTK's recent manager as the guard sees it: "changed" handlers run after its own write, and
    its model (lookup_item)."""

    def __init__(self):
        self.handlers, self.model = [], {}

    def connect_after(self, name, handler):
        assert name == "changed"
        self.handlers.append(handler)

    def changed(self):
        for handler in self.handlers:
            handler(self)

    def lookup_item(self, uri):
        if uri not in self.model:
            raise LookupError(f"Unable to find an item with URI '{uri}'")
        return Info(self.model[uri])


def gtk_writes(path, data):
    """As GLib's g_file_set_contents writes the list: a file of its own renamed over it (a link in
    its place replaced, not followed), then 0600."""
    temp = f"{path}.XXXXXX"
    Path(temp).write_bytes(data)
    os.replace(temp, path)
    os.chmod(path, 0o600)


class Timers:
    def __init__(self):
        self.waiting = []

    def later(self, seconds, call):
        item = [seconds, call]
        self.waiting.append(item)
        return lambda: self.waiting.remove(item)

    def run(self):
        for item in list(self.waiting):
            self.waiting.remove(item)
            item[1]()


class Folder:
    def __init__(self, root: Path):
        self.root = root
        self.data = root / "data"
        self.data.mkdir(mode=0o700)
        self.recent = str(self.data / "recently-used.xbel")
        self.manager, self.timers = Manager(), Timers()
        self.seed = xbel(entry("file:///srv/notes.txt"), entry("file:///srv/old.txt", "2026-01-02T03:04:05.000000Z"))

    def keeper(self):
        return recentguard.Keeper(self.manager, self.recent, APP, clock=lambda: NOW, later=self.timers.later)

    def write(self, data, mode=0o600, path=None):
        path = path or self.recent
        Path(path).write_bytes(data)
        os.chmod(path, mode)

    def read(self, path=None):
        return Path(path or self.recent).read_bytes()

    def choose(self, keeper, *uris):
        """A chooser ends with `uris` chosen, and GTK takes them in and writes the list."""
        keeper.chose(list(uris))
        for uri in uris:
            self.manager.model[uri] = NOW
        gtk_writes(self.recent, xbel(entry("file:///srv/notes.txt"), *(entry(uri, app=APP) for uri in uris)))
        self.manager.changed()


@pytest.fixture
def folder(tmp_path):
    return Folder(tmp_path)


def test_the_list_gtk_writes_after_a_choice_is_put_back_byte_for_byte_with_its_mode(folder):
    folder.write(folder.seed, 0o640)
    keeper = folder.keeper()
    folder.choose(keeper, "file:///home/u/report.pdf")
    assert folder.read() == folder.seed
    assert stat.S_IMODE(os.lstat(folder.recent).st_mode) == 0o640
    assert not keeper.pending and folder.timers.waiting == []


def test_another_programs_change_is_kept_and_is_what_a_later_choice_puts_back(folder):
    folder.write(folder.seed)
    keeper = folder.keeper()
    theirs = folder.seed.replace(b"</xbel>", entry("file:///srv/theirs.odt") + b"</xbel>")
    gtk_writes(folder.recent, theirs)           # another program's write, GTK re-reads it
    folder.manager.changed()
    assert folder.read() == theirs
    folder.choose(keeper, "file:///home/u/report.pdf")
    assert folder.read() == theirs


def test_a_list_that_was_not_there_is_taken_away_again(folder):
    folder.choose(folder.keeper(), "file:///home/u/report.pdf")
    assert not os.path.lexists(folder.recent)


def test_the_write_stays_pending_until_gtk_holds_every_file_chosen(folder):
    """GTK adds the files one by one, as each one's details come: a write with some of them is
    followed by another."""
    folder.write(folder.seed)
    keeper = folder.keeper()
    keeper.chose(["file:///a.txt", "file:///b.txt"])
    folder.manager.model["file:///a.txt"] = NOW
    folder.manager.model["file:///b.txt"] = NOW - 86400 * 9         # its earlier entry, not ours
    gtk_writes(folder.recent, b"with a")
    folder.manager.changed()
    assert folder.read() == folder.seed and keeper.pending
    folder.manager.model["file:///b.txt"] = NOW
    gtk_writes(folder.recent, b"with a and b")
    folder.manager.changed()
    assert folder.read() == folder.seed and not keeper.pending


def test_where_gtk_never_takes_the_files_in_the_wait_ends_and_others_changes_count_again(folder):
    """Recent files switched off by the user: GTK writes an empty list over theirs, and adds nothing."""
    folder.write(folder.seed)
    keeper = folder.keeper()
    keeper.chose(["file:///a.txt"])
    gtk_writes(folder.recent, xbel())
    folder.manager.changed()
    assert folder.read() == folder.seed and keeper.pending
    assert [seconds for seconds, _ in folder.timers.waiting] == [recentguard.HOLD_SECONDS]
    folder.timers.run()
    assert not keeper.pending
    gtk_writes(folder.recent, b"theirs")
    folder.manager.changed()
    assert folder.read() == b"theirs"


def test_the_list_gtk_writes_as_the_loop_ends_is_put_back(folder):
    folder.write(folder.seed)
    keeper = folder.keeper()
    folder.choose(keeper, "file:///home/u/report.pdf")
    gtk_writes(folder.recent, b"the model, as the loop ended")      # no signal: put_back
    keeper.put_back()
    assert folder.read() == folder.seed


def test_a_chooser_left_with_nothing_chosen_pends_nothing(folder):
    folder.write(folder.seed)
    keeper = folder.keeper()
    keeper.chose([])
    assert not keeper.pending


def test_a_link_to_a_regular_file_is_made_again_and_written_through(folder):
    target = folder.data / "kept" / "recent.xbel"
    target.parent.mkdir()
    folder.write(folder.seed, 0o644, target)
    os.symlink("kept/recent.xbel", folder.recent)
    keeper = folder.keeper()
    folder.choose(keeper, "file:///home/u/report.pdf")             # the link replaced by a file
    assert os.readlink(folder.recent) == "kept/recent.xbel" and folder.read(target) == folder.seed
    keeper.chose(["file:///home/u/two.pdf"])
    folder.write(b"written through the link", 0o600, target)
    folder.manager.model["file:///home/u/two.pdf"] = NOW
    folder.manager.changed()
    assert os.readlink(folder.recent) == "kept/recent.xbel" and folder.read(target) == folder.seed
    assert stat.S_IMODE(os.stat(target).st_mode) == 0o644


def test_a_link_to_what_is_no_file_is_made_again_and_what_it_names_is_never_written(folder):
    os.symlink(os.devnull, folder.recent)
    keeper = folder.keeper()
    with mock.patch.object(recentguard, "_write_whole", wraps=recentguard._write_whole) as written:
        folder.choose(keeper, "file:///home/u/report.pdf")
        keeper.put_back()
    assert os.readlink(folder.recent) == os.devnull
    written.assert_not_called()


def test_a_link_naming_a_file_outside_the_data_folder_is_never_written_through(folder):
    outside = folder.root / "elsewhere.xbel"
    folder.write(folder.seed, path=outside)
    os.symlink(outside, folder.recent)
    keeper = folder.keeper()
    keeper.chose(["file:///home/u/report.pdf"])
    folder.write(b"changed through the link", path=outside)
    folder.manager.model["file:///home/u/report.pdf"] = NOW
    with mock.patch.object(recentguard, "_say") as said:
        folder.manager.changed()
    assert folder.read(outside) == b"changed through the link" and os.readlink(folder.recent) == str(outside)
    said.assert_called_once()


def test_a_folder_in_the_lists_place_is_left_alone(folder):
    os.mkdir(folder.recent)
    keeper = folder.keeper()
    keeper.chose(["file:///a.txt"])
    folder.manager.model["file:///a.txt"] = NOW
    folder.manager.changed()
    keeper.put_back()
    assert os.path.isdir(folder.recent)


def test_a_failure_is_said_on_stderr_and_never_raised(folder):
    folder.write(folder.seed)
    keeper = folder.keeper()
    with mock.patch.object(recentguard, "_write_whole", side_effect=OSError("disk full")), \
            mock.patch.object(recentguard, "_say") as said:
        folder.choose(keeper, "file:///home/u/report.pdf")
        keeper.put_back()
    assert said.call_count == 2 and "disk full" in said.call_args[0][0]


def test_a_write_leaves_no_temp_file(folder):
    folder.write(folder.seed)
    folder.choose(folder.keeper(), "file:///home/u/report.pdf")
    assert os.listdir(folder.data) == ["recently-used.xbel"]


@pytest.fixture
def fresh_keeper(monkeypatch):
    monkeypatch.setattr(recentguard, "_keeper", None)


def fake_gtk(data_dir, filename):
    manager = Manager()
    manager.props = type("Props", (), {"filename": filename})()
    glib = type("GLib", (), {"get_user_data_dir": staticmethod(lambda: data_dir),
                             "get_application_name": staticmethod(lambda: APP)})
    gtk = type("Gtk", (), {"RecentManager": type("RM", (), {"get_default": staticmethod(lambda: manager)})})
    return mock.patch.object(recentguard, "_gtk", return_value=(glib, gtk))


def test_the_list_is_kept_only_where_gtk_keeps_it_in_the_data_folder(tmp_path, monkeypatch, fresh_keeper):
    data = str(tmp_path / "data")
    monkeypatch.setenv("XDG_DATA_HOME", data)
    with fake_gtk(data, os.path.join(data, "recently-used.xbel")):
        assert recentguard.keeper().path == os.path.join(data, "recently-used.xbel")


@pytest.mark.parametrize("elsewhere", ["the list", "GLib's data folder"])
def test_a_list_elsewhere_or_another_data_folder_is_never_kept(tmp_path, monkeypatch, fresh_keeper, elsewhere):
    data = str(tmp_path / "data")
    monkeypatch.setenv("XDG_DATA_HOME", data)
    glib_dir, filename = ((data, str(tmp_path / "recently-used.xbel")) if elsewhere == "the list"
                          else (str(tmp_path / "other"), os.path.join(data, "recently-used.xbel")))
    with fake_gtk(glib_dir, filename), mock.patch.object(recentguard, "_say") as said:
        assert recentguard.keeper() is None and recentguard.keeper() is None
    said.assert_called_once()


def test_the_data_folder_is_xdg_data_home_where_absolute_else_under_home():
    assert recentguard.data_home({"XDG_DATA_HOME": "/x/data", "HOME": "/h"}) == "/x/data"
    assert recentguard.data_home({"XDG_DATA_HOME": "rel", "HOME": "/h"}) == "/h/.local/share"
    assert recentguard.data_home({"HOME": "/h"}) == "/h/.local/share"


class Chooser:
    """A file chooser as run() sees one: run() emits "response" to what is connected, as GTK's do,
    then returns it - noting how often the keeper had been told by then."""

    def __init__(self, response, keeper):
        self.response, self.keeper, self.handlers, self.told_by_then = response, keeper, [], None

    def connect(self, name, handler):
        assert name == "response"
        self.handlers.append(handler)

    def run(self):
        for handler in self.handlers:
            handler(self, self.response)
        self.told_by_then = self.keeper.chose.call_count
        return self.response

    def get_uris(self):
        return ["file:///a.txt"]


@pytest.mark.parametrize(("response", "chose"), [(-3, True), (-5, True), (-6, False), (-4, False)])
def test_run_tells_the_keeper_what_an_accepted_chooser_chose_as_it_answers(response, chose):
    """Before run() comes back: GTK can write the list before then (a Save dialog's, measured)."""
    keeper = mock.Mock()
    chooser = Chooser(response, keeper)
    with mock.patch.object(recentguard, "keeper", return_value=keeper):
        assert recentguard.run(chooser) == response
    assert chooser.told_by_then == (1 if chose else 0)
    assert keeper.chose.call_args_list == ([mock.call(["file:///a.txt"])] if chose else [])


def test_a_stand_in_chooser_with_no_signals_is_told_once_it_has_answered():
    chooser = mock.Mock(spec=["run", "get_uris"])
    chooser.run.return_value = -3
    chooser.get_uris.return_value = ["file:///a.txt"]
    with mock.patch.object(recentguard, "keeper", return_value=mock.Mock()) as kept:
        assert recentguard.run(chooser) == -3
    kept.return_value.chose.assert_called_once_with(["file:///a.txt"])


def test_pywebviews_dialog_is_wrapped_once_and_tells_the_keeper_as_its_dialog_answers(monkeypatch):
    """guard_pywebview wraps pywebview's own dialog (its GTK backend's BrowserView.create_file_dialog,
    which window.create_file_dialog and a download's Save dialog run on the GTK thread): what it rests
    on, and a hook on every dialog's answer while it runs, which tells the keeper a file chooser's."""
    pytest.importorskip("gi")
    backend = pytest.importorskip("webview.platforms.gtk")
    view = backend.BrowserView
    original = getattr(view.create_file_dialog, "__wrapped__", view.create_file_dialog)
    assert list(inspect.signature(original).parameters) == \
        ["self", "dialog_type", "directory", "allow_multiple", "save_filename", "file_types"]
    assert "dialog.run()" in inspect.getsource(original) and "gtk.FileChooserDialog(" in inspect.getsource(original)
    assert "i.create_file_dialog(" in inspect.getsource(backend.create_file_dialog)
    assert "self.create_file_dialog(" in inspect.getsource(view.on_download_decide_destination)

    class FileChooser:
        def get_uris(self):
            return ["file:///tmp/a%20b.txt"]

    hooks, unhooked = [], []

    def hook_responses(on_response):
        hooks.append(on_response)
        return lambda: unhooked.append(on_response)

    def dialog(self, *args, **kwargs):
        for on_response in hooks:
            on_response(object(), -5)                      # another dialog of the app's: not a chooser
            on_response(FileChooser(), -6)                 # Cancel
            on_response(FileChooser(), -5)                 # OK
        return ("/tmp/a b.txt",)

    monkeypatch.setattr(view, "create_file_dialog", dialog)
    monkeypatch.setattr(recentguard, "_hook_responses", hook_responses)
    monkeypatch.setattr(recentguard, "_gtk", lambda: (None, type("Gtk", (), {"FileChooser": FileChooser})))
    recentguard._wrap_pywebview_dialogs()
    recentguard._wrap_pywebview_dialogs()
    assert view.create_file_dialog.__wrapped__ is dialog                   # wrapped once
    keeper = mock.Mock()
    with mock.patch.object(recentguard, "keeper", return_value=keeper):
        assert view.create_file_dialog(object(), 10, "/tmp", False, "", ()) == ("/tmp/a b.txt",)
    keeper.chose.assert_called_once_with(["file:///tmp/a%20b.txt"])
    assert len(hooks) == 1 and unhooked == hooks                            # and only while it ran


def test_guard_pywebview_answers_the_windows_file_inputs_before_it_shows(monkeypatch):
    monkeypatch.setattr(recentguard, "_wrap_pywebview_dialogs", lambda: None)
    shown = []

    class Event:
        def __iadd__(self, handler):
            shown.append(handler)
            return self

    window = type("Window", (), {"events": type("Events", (), {"before_show": Event()})(), "native": "the window"})()
    recentguard.guard_pywebview(window)
    with mock.patch.object(recentguard, "answer_file_inputs") as answered:
        for handler in shown:
            assert list(inspect.signature(handler).parameters) == ["window"]   # pywebview passes it so
            handler(window)
    answered.assert_called_once_with("the window")


@pytest.mark.skipif(not CANONICAL.is_file(), reason="DA Assistant's repository isn't beside this one")
def test_the_module_is_da_assistants_copy_but_for_its_docstrings_paths():
    """recentguard.py is DA Assistant's (the DA apps' security standard): line for line after its
    docstring. A change is made there first, then copied here."""
    import ast

    def code(text):
        first = ast.parse(text).body[0]
        assert isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant)
        return text.splitlines()[first.end_lineno:]

    ours = code((SRC / "davibemanager" / "recentguard.py").read_text(encoding="utf-8"))
    theirs = code(CANONICAL.read_text(encoding="utf-8"))
    if ours != theirs:
        first = next((i for i, (a, b) in enumerate(zip(ours, theirs)) if a != b), min(len(ours), len(theirs)))
        pytest.fail(f"recentguard.py differs from DA Assistant's at line {first + 1} after the docstring: "
                    f"{ours[first:first + 1]!r} here, {theirs[first:first + 1]!r} there. Change DA Assistant's "
                    "copy first, then copy it here.")


SCRIPT = textwrap.dedent('''
    import json, os, sys, threading
    sys.path.insert(0, {src!r})
    import gi
    gi.require_version("Gtk", "3.0")
    gi.require_version("WebKit2", "4.1")
    from gi.repository import GLib, Gtk
    from davibemanager import recentguard

    how, chosen, guarded = sys.argv[1], sys.argv[2], sys.argv[3] == "guarded"
    if guarded:
        recentguard._wrap_pywebview_dialogs()       # what guard_pywebview does to pywebview's dialog
    else:
        recentguard._keeper = recentguard._NONE
    recent = os.path.join(os.environ["XDG_DATA_HOME"], "recently-used.xbel")
    seen = {{}}

    def now():
        with open(recent, "rb") as f:
            return f.read().decode()

    pressed = []

    def accept():
        # chooses the file and accepts, and answers GTK's "Replace it?" with Replace
        if "chosen" in seen:
            return False
        for window in Gtk.Window.list_toplevels():
            if not window.get_visible():
                continue
            if isinstance(window, Gtk.MessageDialog):
                window.response(Gtk.ResponseType.ACCEPT)
            elif isinstance(window, Gtk.FileChooserDialog) and window not in pressed:
                action = window.get_action()
                if action in (Gtk.FileChooserAction.OPEN, Gtk.FileChooserAction.SELECT_FOLDER):
                    window.select_filename(chosen)
                if action == Gtk.FileChooserAction.OPEN:
                    ready = window.get_filenames() == [chosen]
                else:
                    ready = window.get_filename() == chosen
                if ready:
                    ids = [int(Gtk.ResponseType.ACCEPT), int(Gtk.ResponseType.OK)]
                    pressed.append(window)
                    window.response(next(i for i in ids if window.get_widget_for_response(i) is not None))
        return True

    def written():
        seen["after_write"] = now()
        Gtk.main_quit()
        return False

    window = Gtk.Window()
    window.show()

    class Request:
        """WebKit's WebKitFileChooserRequest, as answer_file_input reads it."""
        def get_select_multiple(self):
            return True
        def get_mime_types_filter(self):
            return None
        def get_selected_files(self):
            return None
        def select_files(self, paths):
            seen["chosen"] = list(paths)
            GLib.timeout_add(800, written)
        def cancel(self):
            seen["chosen"] = None
            Gtk.main_quit()

    def choose():
        GLib.timeout_add(100, accept)
        if how == "input":
            view = type("View", (), {{"get_toplevel": lambda self: window}})()
            seen["answered"] = recentguard.answer_file_input(view, Request())
            return False
        raise SystemExit("no such chooser")
        return False

    GLib.idle_add(choose)
    Gtk.main()
    recentguard.put_back()
    seen["after_loop"] = now()
    seen["mode"] = os.stat(recent).st_mode & 0o777
    print("RESULT", json.dumps(seen), flush=True)
''')


def real_choice(tmp_path, how, guarded, chosen_name="notes.txt"):
    """`how` chooses `chosen_name` in a process of its own under Xvfb: (the list as seeded, what the
    process saw)."""
    if not shutil.which("xvfb-run") or importlib.util.find_spec("gi") is None:
        pytest.skip("needs Xvfb and PyGObject")
    tmp_path = tmp_path / "chooser"                 # beside what the suite's own fixtures make there
    tmp_path.mkdir()
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C.UTF-8", "GTK_USE_PORTAL": "0",
           "NO_AT_BRIDGE": "1", "GSETTINGS_BACKEND": "memory", "GIO_USE_VFS": "local"}
    for name, sub in (("HOME", "home"), ("XDG_DATA_HOME", "data"), ("XDG_CONFIG_HOME", "config"),
                      ("XDG_CACHE_HOME", "cache"), ("XDG_RUNTIME_DIR", "run"), ("XDG_STATE_HOME", "state")):
        env[name] = str(tmp_path / sub)
        os.mkdir(env[name], 0o700)
    chosen = os.path.join(env["HOME"], chosen_name)
    if chosen_name.endswith("/"):
        chosen = chosen.rstrip("/")
        os.mkdir(chosen)
    else:
        Path(chosen).write_text("notes\n", encoding="utf-8")
    seed = xbel(entry("file:///srv/report-from-august.txt", "2026-08-01T09:00:00.000000Z"),
                entry("file:///srv/agenda.txt", time.strftime("%Y-%m-%dT%H:%M:%S.000000Z", time.gmtime())),
                entry("file://" + chosen, "2026-11-05T12:00:00.000000Z"))
    recent = Path(env["XDG_DATA_HOME"]) / "recently-used.xbel"
    recent.write_bytes(seed)
    os.chmod(recent, 0o644)
    script = tmp_path / "choose.py"
    script.write_text(SCRIPT.format(src=str(SRC)), encoding="utf-8")
    command = ["xvfb-run", "-a"] + (["dbus-run-session", "--"] if shutil.which("dbus-run-session") else [])
    command += [sys.executable, "-I", str(script), how, chosen, "guarded" if guarded else "unguarded"]
    done = subprocess.run(command, env=env, capture_output=True, text=True, timeout=180, check=False)
    assert done.returncode == 0, done.stderr[-3000:]
    results = [line[len("RESULT "):] for line in done.stdout.splitlines() if line.startswith("RESULT ")]
    assert len(results) == 1, done.stdout[-3000:] + done.stderr[-3000:]
    seen = json.loads(results[0])
    assert seen["chosen"] == [chosen], done.stderr[-3000:]
    return seed.decode(), seen


def test_a_pages_file_input_leaves_the_list_byte_for_byte_as_it_was(tmp_path):
    seed, seen = real_choice(tmp_path, "input", guarded=True)
    assert seen["answered"] is True
    assert seen["after_write"] == seed and seen["after_loop"] == seed and seen["mode"] == 0o644


def test_every_file_chooser_of_the_app_goes_through_the_guard():
    """The page's <input type="file"> (attach, import a .vibe, restore a backup) and pywebview's own
    dialogs: guard_pywebview covers them before webview.start, the list is put back once the loop has
    ended (in main's finally), and the app makes no Gtk file chooser of its own."""
    app = (SRC / "davibemanager" / "app.py").read_text(encoding="utf-8")
    assert re.search(r"recentguard\.guard_pywebview\(window\)\n(.*\n){0,3}?\s+webview\.start\(", app)
    assert re.search(r"finally:\n(\s+#.*\n)*\s+recentguard\.put_back\(\)", app)
    for path in (SRC / "davibemanager").rglob("*.py"):
        if path.name != "recentguard.py":
            text = path.read_text(encoding="utf-8")
            assert "FileChooser" not in text and "RecentManager" not in text, path


def test_without_the_guard_gtk_changes_the_list_as_it_writes_and_as_the_loop_ends(tmp_path):
    """What the guard undoes: the old entry dropped, the file's own entry the app's, the list 0600."""
    seed, seen = real_choice(tmp_path, "input", guarded=False)
    for written in (seen["after_write"], seen["after_loop"]):
        assert written != seed and "report-from-august" not in written and "agenda.txt" in written
    assert seen["mode"] == 0o600
