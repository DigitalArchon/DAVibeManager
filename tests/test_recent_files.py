"""The window's file choosers leave GTK's recent files list as it was (recentguard.py): GTK's chooser
adds every file chosen to $XDG_DATA_HOME/recently-used.xbel, writes the whole list from its model a
quarter of a second later (an entry older than 30 days dropped) and again as the main loop ends, and
the guard puts back what those writes changed. The window's choosers are WebKit's, for the page's
<input type="file">: attaching files, importing a .vibe, restoring a backup.

The logic is held here with a stand-in for GTK's manager and a list in a folder of the test's own;
then real choosers, under Xvfb in a process of their own (HOME and the XDG folders fresh temporary
ones, no session bus of the user's), a list seeded with an entry older than 30 days and the chosen
file's own earlier entry, which must be byte for byte as seeded after GTK's write and after the loop
has ended - and, with the guard off, isn't (GTK's writes are what the guard undoes). And a chooser
opened through the guard fits the screen's work area: on a 640x480 screen GTK's own size for one is
1096x822, placed off the screen's top left (on the lab's Omarchy, 1280x800, its header bar with Cancel,
Open and the location bar was off the screen)."""

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


# --- a write of GTK's that lands before the chooser's answer (a name typed into a Save dialog, or a place
# into the location bar, reaches the app 250 ms after GTK took the file in: GtkButton holds the default
# button pressed so long; a write already on its way, its "changed" timer started by another program's
# change or by the list put back after the app's previous choice, lands first, the file in it)

STAMP_NOW = time.strftime("%Y-%m-%dT%H:%M:%S.000000Z", time.gmtime(NOW))


def theirs(folder):
    """Another program's write to the list, which GTK re-reads."""
    data = folder.seed.replace(b"</xbel>", entry("file:///srv/theirs.odt") + b"</xbel>")
    folder.write(data, 0o640)
    folder.manager.changed()
    return data


def gtk_writes_first(folder, *uris):
    for uri in uris:
        folder.manager.model[uri] = NOW
    gtk_writes(folder.recent, xbel(entry("file:///srv/theirs.odt"), *(entry(uri, STAMP_NOW, APP) for uri in uris)))
    folder.manager.changed()


def test_a_write_landing_before_the_answer_is_put_back_byte_for_byte(folder):
    folder.write(folder.seed)
    keeper = folder.keeper()
    keeper.opened()
    before = theirs(folder)
    gtk_writes_first(folder, "file:///home/u/new.pdf")
    keeper.chose(["file:///home/u/new.pdf"])
    keeper.closed()
    assert folder.read() == before and stat.S_IMODE(os.lstat(folder.recent).st_mode) == 0o640
    assert not keeper.pending and folder.timers.waiting == []


def test_the_files_in_the_write_that_came_first_are_taken_in_whatever_the_manager_says(folder):
    """The write held them: nothing more is awaited, even where the manager's model is not yet heard from."""
    folder.write(folder.seed)
    keeper = folder.keeper()
    keeper.opened()
    gtk_writes(folder.recent, xbel(entry("file:///home/u/new.pdf", STAMP_NOW, APP)))
    keeper.chose(["file:///home/u/new.pdf"])
    keeper.closed()
    assert folder.read() == folder.seed
    assert not keeper.pending and folder.timers.waiting == []


def test_without_the_chooser_open_the_write_that_came_first_stays(folder):
    """What opened() is for: told only of the answer, the list holding the file already is taken for the clean
    copy."""
    folder.write(folder.seed)
    keeper = folder.keeper()
    theirs(folder)
    gtk_writes_first(folder, "file:///home/u/new.pdf")
    keeper.chose(["file:///home/u/new.pdf"])
    assert b"new.pdf" in folder.read()


def test_another_programs_write_while_it_is_open_stands_when_gtk_writes_after(folder):
    folder.write(folder.seed)
    keeper = folder.keeper()
    keeper.opened()
    before = theirs(folder)
    folder.choose(keeper, "file:///home/u/report.pdf")
    keeper.closed()
    assert folder.read() == before and not keeper.pending


def test_a_file_the_list_already_held_from_before_counts_only_as_added_since(folder):
    """notes.txt is in the list from September: the list as the answer comes is clean."""
    folder.write(folder.seed)
    keeper = folder.keeper()
    keeper.opened()
    before = theirs(folder)
    keeper.chose(["file:///srv/notes.txt"])
    keeper.closed()
    assert keeper.clean == recentguard.look(folder.recent) and folder.read() == before


def test_a_list_that_was_not_there_before_a_write_that_came_first_is_taken_away_again(folder):
    keeper = folder.keeper()
    keeper.opened()
    gtk_writes_first(folder, "file:///home/u/new.pdf")
    keeper.chose(["file:///home/u/new.pdf"])
    keeper.closed()
    assert not os.path.lexists(folder.recent)


def test_the_list_it_opened_on_and_the_newest_are_kept(folder):
    folder.write(folder.seed)
    keeper = folder.keeper()
    keeper.opened()
    for n in range(recentguard.SEEN * 2):
        folder.write(folder.seed + str(n).encode())
        folder.manager.changed()
    assert len(keeper._seen) == recentguard.SEEN
    assert keeper._seen[0][1] == folder.seed
    assert keeper._seen[-1][1] == folder.seed + str(recentguard.SEEN * 2 - 1).encode()
    keeper.closed()
    assert keeper._seen == [] and not keeper.watching


def test_two_choosers_open_keep_the_lists_until_both_have_answered(folder):
    folder.write(folder.seed)
    keeper = folder.keeper()
    keeper.opened()
    keeper.opened()
    keeper.closed()
    assert keeper.watching
    before = theirs(folder)
    gtk_writes_first(folder, "file:///home/u/new.pdf")
    keeper.chose(["file:///home/u/new.pdf"])
    keeper.closed()
    assert folder.read() == before


def test_what_a_list_holds_is_read_from_gtks_layout():
    data = xbel(entry("file:///srv/a%20b.txt", STAMP_NOW, APP), entry("file:///srv/old.txt"),
                entry("https://example.com/x", STAMP_NOW))
    found = recentguard.added(data)
    assert found["/srv/a b.txt"] == NOW and found["/srv/old.txt"] < NOW and found["https://example.com/x"] == NOW
    listing = (recentguard.FILE, data, 0o600)
    assert recentguard.holds(listing, ["file:///srv/a b.txt"], NOW)
    assert not recentguard.holds(listing, ["file:///srv/old.txt"], NOW)
    assert not recentguard.holds((recentguard.ABSENT,), ["file:///srv/a"], NOW)
    assert recentguard.added(b"not a list") == {}


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



def test_run_tells_the_keeper_the_chooser_opened_before_it_runs_and_closed_after():
    keeper = mock.Mock()
    with mock.patch.object(recentguard, "keeper", return_value=keeper):
        recentguard.run(Chooser(-3, keeper))
    assert [name for name, *_ in keeper.method_calls] == ["opened", "chose", "closed"]


def test_a_chooser_that_fails_is_still_closed():
    keeper = mock.Mock()
    chooser = mock.Mock(spec=["run", "connect"])
    chooser.run.side_effect = RuntimeError("gone")
    with mock.patch.object(recentguard, "keeper", return_value=keeper), pytest.raises(RuntimeError):
        recentguard.run(chooser)
    assert [name for name, *_ in keeper.method_calls] == ["opened", "closed"]


def test_a_pages_file_input_is_open_from_show_until_it_answers():
    """The window's choosers (attaching, importing a .vibe, restoring a backup) are the page's file inputs."""
    keeper, calls, made = mock.Mock(), [], []

    class Native:
        def __init__(self):
            self.handlers = []

        def connect(self, name, handler):
            self.handlers.append(handler)

        def show(self):
            calls.append("show")

        def get_uris(self):
            return ["file:///a.txt"]

        def get_filenames(self):
            return ["/a.txt"]

        def destroy(self):
            calls.append("destroy")

        def __getattr__(self, name):
            return lambda *a: None

    class FileChooserNative:
        @staticmethod
        def new(*_args):
            made.append(Native())
            return made[-1]

    gtk = mock.Mock(FileChooserNative=FileChooserNative)
    gtk.Window, gtk.OffscreenWindow = type("W", (), {}), type("O", (), {})
    gtk.ResponseType.ACCEPT = -3
    keeper.opened.side_effect = lambda: calls.append("opened")
    keeper.closed.side_effect = lambda: calls.append("closed")
    keeper.chose.side_effect = lambda uris: calls.append("chose")
    request = mock.Mock()
    request.get_select_multiple.return_value = False
    request.get_mime_types_filter.return_value = None
    request.get_selected_files.return_value = None
    with mock.patch.object(recentguard, "keeper", return_value=keeper), \
            mock.patch.object(recentguard, "_gtk", return_value=(None, gtk)), \
            mock.patch.object(recentguard, "_fitting", return_value=lambda: None):
        assert recentguard.answer_file_input(mock.Mock(), request)
        assert calls == ["opened", "show"]
        made[0].handlers[0](made[0], -3)
    assert calls == ["opened", "show", "chose", "closed", "destroy"]


def test_pywebviews_own_dialog_is_open_while_it_runs():
    keeper, calls = mock.Mock(), []
    keeper.opened.side_effect = lambda: calls.append("opened")
    keeper.closed.side_effect = lambda: calls.append("closed")

    class BrowserView:
        def create_file_dialog(self, *args, **kwargs):
            calls.append("dialog")
            return ("/a.txt",)

    backend = mock.Mock(BrowserView=BrowserView)
    platforms = mock.Mock(gtk=backend)
    modules = {"webview": mock.Mock(platforms=platforms), "webview.platforms": platforms,
               "webview.platforms.gtk": backend}
    with mock.patch.dict(sys.modules, modules), \
            mock.patch.object(recentguard, "keeper", return_value=keeper), \
            mock.patch.object(recentguard, "_hook_responses", return_value=lambda: None):
        recentguard._wrap_pywebview_dialogs()
        assert BrowserView().create_file_dialog() == ("/a.txt",)
    assert calls == ["opened", "dialog", "closed"]

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


# --- a chooser fits the screen: the monitor's work area, less a margin, and placed on it -----------------------

def test_the_room_is_the_work_area_less_a_margin_on_each_side():
    assert recentguard.fit_room(1280, 800) == (1152, 720)
    assert recentguard.fit_room(640, 480) == (576, 432)
    assert recentguard.fit_room(1920, 1080) == (1728, 972)
    assert recentguard.fit_room(200, 100) == (168, 68)          # 16 px at least
    assert recentguard.fit_room(20, 20) == (1, 1)


def test_a_window_off_the_area_is_moved_in_as_little_as_it_takes():
    area = (0, 26, 1280, 774)                                   # a bar of 26 px at the top
    assert recentguard.placed(100, 100, 600, 400, area) == (100, 100)
    assert recentguard.placed(-228, -171, 600, 400, area) == (0, 26)
    assert recentguard.placed(1000, 600, 600, 400, area) == (680, 400)
    assert recentguard.placed(-50, -50, 2000, 1000, area) == (0, 26)   # larger: its top left, its header bar, on it
    assert recentguard.placed(10, 30, 600, 400, (1280, 0, 1920, 1080)) == (1280, 30)   # a second monitor's


def test_run_fits_choosers_while_it_runs_and_stops_after():
    calls = []
    chooser = mock.Mock(spec=["run", "connect"])
    chooser.run.side_effect = lambda: calls.append("run") or -6

    def fitting():
        calls.append("fit")
        return lambda: calls.append("unfit")
    with mock.patch.object(recentguard, "keeper", return_value=mock.Mock()), \
            mock.patch.object(recentguard, "_fitting", side_effect=fitting):
        recentguard.run(chooser)
        assert calls == ["fit", "run", "unfit"]
        calls.clear()
        chooser.run.side_effect = RuntimeError("gone")
        with pytest.raises(RuntimeError):
            recentguard.run(chooser)
        assert calls == ["fit", "unfit"]
    calls.clear()
    chooser.run.side_effect = lambda: calls.append("run") or -6
    with mock.patch.object(recentguard, "keeper", return_value=None), \
            mock.patch.object(recentguard, "_fitting", side_effect=fitting):
        recentguard.run(chooser)                    # the list not kept: still fitted
    assert calls == ["fit", "run", "unfit"]


def test_a_hook_that_cannot_be_had_never_stops_the_chooser():
    with mock.patch.object(recentguard, "_fit_choosers", side_effect=RuntimeError("no")), \
            mock.patch.object(recentguard, "_say") as said:
        unfit = recentguard._fitting()
    unfit()
    said.assert_called_once()


def test_fit_holds_the_window_to_the_room_and_keeps_it_on_the_area():
    gi = pytest.importorskip("gi")
    gi.require_version("Gdk", "3.0")
    from gi.repository import Gdk
    window = mock.Mock()
    window.get_default_size.return_value = (1096, 822)
    with mock.patch.object(recentguard, "_area", return_value=(0, 0, 640, 480)):
        recentguard.fit(window)
    hints, flags = window.set_geometry_hints.call_args[0][1:]
    assert (hints.max_width, hints.max_height) == (576, 432) and flags == Gdk.WindowHints.MAX_SIZE
    window.set_default_size.assert_called_once_with(576, 432)
    window.connect.assert_called_once_with("map-event", recentguard._keep_on)
    window = mock.Mock()
    window.get_default_size.return_value = (-1, -1)            # GTK's own: left to the hints
    with mock.patch.object(recentguard, "_area", return_value=(0, 0, 640, 480)):
        recentguard.fit(window)
    window.set_default_size.assert_not_called()
    with mock.patch.object(recentguard, "_area", side_effect=RuntimeError("no screen")), \
            mock.patch.object(recentguard, "_say") as said:
        recentguard.fit(mock.Mock())
    said.assert_called_once()


def test_a_pages_file_input_and_pywebviews_dialog_are_fitted_until_they_answer():
    """The window's choosers: the page's <input type="file"> (attach, import a .vibe, restore a backup) and
    pywebview's own dialog."""
    calls, made = [], []

    def fitting():
        calls.append("fit")
        return lambda: calls.append("unfit")

    class Native:
        def __init__(self):
            self.handlers = []

        def connect(self, name, handler):
            self.handlers.append(handler)

        def show(self):
            calls.append("show")

        def __getattr__(self, name):
            return lambda *a: None

    class FileChooserNative:
        @staticmethod
        def new(*_args):
            made.append(Native())
            return made[-1]

    gtk = mock.Mock(FileChooserNative=FileChooserNative)
    gtk.Window, gtk.OffscreenWindow = type("W", (), {}), type("O", (), {})
    gtk.ResponseType.ACCEPT = -3
    request = mock.Mock()
    request.get_select_multiple.return_value = False
    request.get_mime_types_filter.return_value = None
    request.get_selected_files.return_value = None
    with mock.patch.object(recentguard, "_fitting", side_effect=fitting), \
            mock.patch.object(recentguard, "keeper", return_value=None), \
            mock.patch.object(recentguard, "_gtk", return_value=(None, gtk)):
        recentguard.answer_file_input(mock.Mock(), request)
        assert calls == ["fit", "show"]
        made[0].handlers[0](made[0], -6)
    assert calls == ["fit", "show", "unfit"]
    calls.clear()

    class BrowserView:
        def create_file_dialog(self, *args, **kwargs):
            calls.append("dialog")

    backend = mock.Mock(BrowserView=BrowserView)
    platforms = mock.Mock(gtk=backend)
    modules = {"webview": mock.Mock(platforms=platforms), "webview.platforms": platforms,
               "webview.platforms.gtk": backend}
    for kept in (mock.Mock(), None):
        BrowserView.create_file_dialog = lambda self, *a, **k: calls.append("dialog")
        with mock.patch.dict(sys.modules, modules), mock.patch.object(recentguard, "_fitting", side_effect=fitting), \
                mock.patch.object(recentguard, "keeper", return_value=kept), \
                mock.patch.object(recentguard, "_hook_responses", return_value=lambda: None):
            recentguard._wrap_pywebview_dialogs()
            BrowserView().create_file_dialog()
        assert calls == ["fit", "dialog", "unfit"]
        calls.clear()


FIT_SCRIPT = textwrap.dedent('''
    import json, os, sys
    sys.path.insert(0, {src!r})
    import gi
    gi.require_version("Gtk", "3.0")
    gi.require_version("Gdk", "3.0")
    from gi.repository import Gdk, GLib, Gtk
    from davibemanager import recentguard

    guarded = sys.argv[1] == "guarded"
    if not guarded:
        recentguard._fitting = lambda: (lambda: None)
    seen = {{}}

    def measure():
        # once the chooser is on the screen: where, and how large, then Cancel
        for window in Gtk.Window.list_toplevels():
            if isinstance(window, Gtk.FileChooserDialog) and window.get_mapped():
                frame = window.get_window().get_frame_extents()
                area = Gdk.Display.get_default().get_monitor(0).get_workarea()
                seen["frame"] = [frame.x, frame.y, frame.width, frame.height]
                seen["area"] = [area.x, area.y, area.width, area.height]
                window.response(Gtk.ResponseType.CANCEL)
                return False
        return True

    class Request:
        def get_select_multiple(self):
            return False
        def get_mime_types_filter(self):
            return None
        def get_selected_files(self):
            return None
        def select_files(self, paths):
            Gtk.main_quit()
        def cancel(self):
            Gtk.main_quit()

    window = Gtk.Window()
    window.set_default_size(300, 200)
    window.move(500, 380)              # near the screen's bottom right
    window.show()

    def choose():
        GLib.timeout_add(400, measure)
        view = type("View", (), {{"get_toplevel": lambda self: window}})()
        recentguard.answer_file_input(view, Request())     # the page's <input type="file">
        return False

    GLib.idle_add(choose)
    Gtk.main()
    print("RESULT", json.dumps(seen), flush=True)
''')


def shown_chooser(tmp_path, guarded):
    """A page's file input answered on a 640x480 screen, its window near the bottom right: (the chooser's frame,
    the work area), each [x, y, width, height]."""
    if not shutil.which("xvfb-run") or importlib.util.find_spec("gi") is None:
        pytest.skip("needs Xvfb and PyGObject")
    top = tmp_path / "fit"
    top.mkdir()
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C.UTF-8", "GTK_USE_PORTAL": "0",
           "NO_AT_BRIDGE": "1", "GSETTINGS_BACKEND": "memory", "GIO_USE_VFS": "local"}
    for name, sub in (("HOME", "home"), ("XDG_DATA_HOME", "data"), ("XDG_CONFIG_HOME", "config"),
                      ("XDG_CACHE_HOME", "cache"), ("XDG_RUNTIME_DIR", "run")):
        env[name] = str(top / sub)
        os.mkdir(env[name], 0o700)
    script = top / "fit.py"
    script.write_text(FIT_SCRIPT.format(src=str(SRC)), encoding="utf-8")
    command = ["xvfb-run", "-a", "-s", "-screen 0 640x480x24"]
    command += ["dbus-run-session", "--"] if shutil.which("dbus-run-session") else []
    command += [sys.executable, "-I", str(script), "guarded" if guarded else "unguarded"]
    done = subprocess.run(command, env=env, capture_output=True, text=True, timeout=180, check=False)
    assert done.returncode == 0, done.stderr[-3000:]
    results = [line[len("RESULT "):] for line in done.stdout.splitlines() if line.startswith("RESULT ")]
    assert len(results) == 1, done.stdout[-3000:] + done.stderr[-3000:]
    seen = json.loads(results[0])
    assert "frame" in seen, done.stderr[-3000:]
    return seen["frame"], seen["area"]


def test_a_pages_file_input_lies_inside_the_work_area(tmp_path):
    (x, y, width, height), (left, top, across, down) = shown_chooser(tmp_path, guarded=True)
    assert x >= left and y >= top and x + width <= left + across and y + height <= top + down


def test_gtks_own_chooser_on_this_screen_does_not(tmp_path):
    """What the guard changes: unfitted, the chooser is larger than the screen."""
    frame, area = shown_chooser(tmp_path, guarded=False)
    assert frame[2] * frame[3] > area[2] * area[3]
