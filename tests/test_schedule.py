"""When the user's apps are looked after: each app's official source asked as often as it chose, and
new versions built at the quiet time the user set (building slows the computer), never on battery
unless they allow it, one at a time."""

import time

import pytest

from davibemanager import apps, config
from davibemanager.appmanager import AppManager
from davibemanager.models import UserError
from davibemanager.workspace import scripts
from helpers import wait_for
from test_apps import gthumb  # noqa: F401 - the fixture


def at(hour, minute=0, days=0):
    """Today at that local time (plus some days), as a timestamp."""
    lt = time.localtime()
    return time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday + days, hour, minute, 0, 0, 0, -1))


def looked(sb):
    return [c for c in sb.calls if c[0] == "env" and not c[-1].startswith("refs/tags/")]


async def test_each_app_is_looked_at_as_often_as_it_chose(gthumb):
    engine, sb, _, _ = gthumb
    engine.cfg.settings.changelog_summary = "manual"
    m = engine.app_manager
    await m.tick(now=at(12))
    assert len(looked(sb)) == 1                          # never looked at yet: now
    checked = apps.load("gthumb")["update"]["checked"]
    await m.tick(now=checked + 10 * 3600)
    assert len(looked(sb)) == 1                          # every day: not after 10 hours
    await m.tick(now=checked + 21 * 3600)
    assert len(looked(sb)) == 2
    m.set_schedule("gthumb", check_every="week")
    checked = apps.load("gthumb")["update"]["checked"]
    await m.tick(now=checked + 3 * 86400)
    assert len(looked(sb)) == 2
    await m.tick(now=checked + 7 * 86400)
    assert len(looked(sb)) == 3
    assert apps.load("gthumb")["check_every"] == "week" and m.apps()[0]["schedule"]["check_every"] == "week"


async def test_a_new_version_is_built_at_the_quiet_time_not_before_or_long_after(gthumb):
    engine, sb, _, told = gthumb
    engine.cfg.settings.changelog_summary = "manual"
    engine.cfg.settings.build_time = "03:00"
    m = engine.app_manager
    m.on_battery = staticmethod(lambda: False)
    await m.check("gthumb", quiet=True)
    assert "will be built at 03:00" in told[-1][1]
    assert m.apps()[0]["schedule"]["waiting"] == "scheduled"
    for now in (at(2, 30), at(6), at(23)):              # before the quiet time, and hours after it (missed: next night)
        await m.tick(now=now)
        assert not sb.calls_of(scripts.CARRY) and not m.building
    await m.tick(now=at(3, 20))
    await wait_for(lambda: apps.load("gthumb")["update"].get("status") == "built", "the build")
    assert sb.calls_of(scripts.CARRY) and told[-1][0] == "gThumb 3.12.7 is ready" and not m.building
    n = len(sb.calls_of(scripts.CARRY))
    await m.tick(now=at(3, 40))                          # built: not again
    assert len(sb.calls_of(scripts.CARRY)) == n


async def test_not_on_battery_unless_the_user_allows_it(gthumb):
    engine, sb, _, _ = gthumb
    engine.cfg.settings.changelog_summary = "manual"
    m = engine.app_manager
    m.on_battery = staticmethod(lambda: True)
    await m.check("gthumb", quiet=True)
    await m.tick(now=at(3, 10))
    assert m.apps()[0]["schedule"]["waiting"] == "battery" and not sb.calls_of(scripts.CARRY)
    engine.cfg.settings.build_on_battery = True
    await m.tick(now=at(3, 10))
    await wait_for(lambda: apps.load("gthumb")["update"].get("status") == "built", "the build")


async def test_an_update_that_needs_the_assistant_isnt_tried_again_every_night(gthumb):
    engine, sb, _, told = gthumb
    engine.cfg.settings.changelog_summary = "manual"
    m = engine.app_manager
    m.on_battery = staticmethod(lambda: False)
    await m.check("gthumb", quiet=True)
    sb.carry_fail["drag-a-box-to-zoom"] = "CONFLICT (content)"
    await m.tick(now=at(3, 5))
    await wait_for(lambda: (apps.load("gthumb")["update"].get("port") or {}).get("status") == "failed", "the try")
    assert told[-1][0] == "gThumb 3.12.7 needs the assistant" and not m.building
    n = len(sb.calls_of(scripts.CARRY))
    await m.tick(now=at(3, 5, days=1))
    assert len(sb.calls_of(scripts.CARRY)) == n and m.apps()[0]["schedule"]["waiting"] == ""


async def test_each_app_can_be_built_when_the_user_says_or_straight_away(gthumb):
    engine, sb, _, told = gthumb
    engine.cfg.settings.changelog_summary = "manual"
    m = engine.app_manager
    m.set_schedule("gthumb", build_when="ask")
    await m.check("gthumb", quiet=True)
    await m.tick(now=at(3, 5))
    assert not sb.calls_of(scripts.CARRY) and "can be updated: open My apps" in told[-1][1]
    m.set_schedule("gthumb", build_when="auto")
    sb.tags.append("3.12.8")
    await m.check("gthumb", quiet=True)
    await wait_for(lambda: sb.calls_of(scripts.CARRY), "the build straight away")


def test_on_battery_is_read_from_the_computers_power_supplies(tmp_path):
    def supply(name, kind, online=None):
        (tmp_path / name).mkdir(parents=True, exist_ok=True)
        (tmp_path / name / "type").write_text(kind + "\n")
        if online is not None:
            (tmp_path / name / "online").write_text(f"{online}\n")
    assert not AppManager.on_battery(tmp_path)                 # nothing: a desktop
    supply("BAT0", "Battery")
    supply("AC", "Mains", 0)
    assert AppManager.on_battery(tmp_path)
    supply("AC", "Mains", 1)
    assert not AppManager.on_battery(tmp_path)


def test_settings_from_before_keep_their_choice():
    cfg = config.from_dict({"settings": {"check_updates": False, "rebuild": "auto"}})
    assert cfg.settings.check_every == "manual" and cfg.settings.rebuild == "auto"
    assert config.from_dict({"settings": {}}).settings.rebuild == "scheduled"


async def test_an_apps_own_choices_and_its_changes_from_the_window(gthumb):
    engine, _, _, _ = gthumb
    m = engine.app_manager
    m.set_schedule("gthumb", check_every="month", build_when="auto")
    assert m.apps()[0]["schedule"] == {"check_every": "month", "build_when": "auto", "waiting": "",
                                       "own": {"check_every": "month", "build_when": "auto"}}
    m.set_schedule("gthumb", check_every="", build_when="")          # like the others again: Settings'
    assert m.apps()[0]["schedule"]["check_every"] == "day" and m.apps()[0]["schedule"]["build_when"] == "scheduled"
    with pytest.raises(UserError):
        m.set_schedule("gthumb", check_every="hourly")
    c = m.change_detail("gthumb", "drag-a-box-to-zoom")
    assert c["title"] == "Drag a box to zoom" and "DVM-Change: drag-a-box-to-zoom" in c["patch"] and "The user asked" in c["feature"]


async def test_a_look_that_fails_forgets_nothing_and_a_build_isnt_told_or_tried_twice(gthumb):
    engine, sb, _, told = gthumb
    engine.cfg.settings.changelog_summary = "manual"
    engine.cfg.settings.rebuild = "auto"
    m = engine.app_manager
    sb.carry_fail["drag-a-box-to-zoom"] = "CONFLICT (content)"
    await m.check("gthumb", quiet=True)
    await wait_for(lambda: (apps.load("gthumb")["update"].get("port") or {}).get("status") == "failed", "the try")
    n = len(sb.calls_of(scripts.CARRY))
    # the next look fails (offline): the release, its change log and the app's own try stay, with the error beside them
    tags, sb.tags = sb.tags, None
    u = await m.check("gthumb", quiet=True)
    assert u["status"] == "available" and u["latest"] == "3.12.7" and u["changelog"] and u["port"]["status"] == "failed"
    assert u["error"] and m.apps()[0]["update"]["error"]
    # and once it works again, the release isn't news: not told again, not built again
    sb.tags = tags
    u = await m.check("gthumb", quiet=True)
    assert "error" not in u and u["port"]["status"] == "failed"
    assert [t[0] for t in told].count("gThumb 3.12.7 is out") == 1 and len(sb.calls_of(scripts.CARRY)) == n


async def test_a_look_saves_onto_the_app_as_it_is_after_the_look(gthumb, monkeypatch):
    from davibemanager.workspace import podman
    engine, sb, _, _ = gthumb
    engine.cfg.settings.changelog_summary = "manual"
    m = engine.app_manager
    real = podman.exec_agent

    async def during(name, argv, **kw):
        if argv[0] == "env" and not argv[-1].startswith("refs/tags/"):
            apps.save({**apps.load("gthumb"), "skip": "3.12.7"})      # the user, while the source is asked
        return await real(name, argv, **kw)
    monkeypatch.setattr(podman, "exec_agent", during)
    await m.check("gthumb", quiet=True)
    assert apps.load("gthumb")["skip"] == "3.12.7" and apps.load("gthumb")["update"]["latest"] == "3.12.7"


async def test_an_app_being_built_isnt_looked_at_and_isnt_built_twice(gthumb):
    engine, sb, _, told = gthumb
    engine.cfg.settings.changelog_summary = "manual"
    engine.cfg.settings.rebuild = "auto"
    m = engine.app_manager
    m.building["gthumb"] = {"step": "build", "started": time.time(), "tag": "3.12.7"}
    await m.tick(now=at(12))
    assert looked(sb) == []                                      # its release is changing under the look
    await m.check("gthumb", quiet=True)                          # the user's own click: told, not built on top
    assert told[-1][0] == "gThumb 3.12.7 is out" and "open My apps" in told[-1][1] and not sb.calls_of(scripts.CARRY)
    m.building.pop("gthumb")
