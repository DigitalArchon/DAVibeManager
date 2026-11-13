"""The two kinds of chat, never mixed: getting an app working on this computer (nothing is built
there; it hands what it finds to the app's chat, or points to one for a wish) and fixing or adding a
feature to one app (its prompt, its tools, told which app)."""

import asyncio

import pytest
from claude_agent_sdk import AssistantMessage, TextBlock, ToolUseBlock

from davibemanager import apps
from davibemanager.conversation import Conversation
from davibemanager.models import UserError
from helpers import wait_for
from test_builder import builder_env, result  # noqa: F401 - the fixture

GTHUMB = "https://gitlab.gnome.org/GNOME/gthumb.git"


def gthumb_app():
    a = apps.create("gThumb", "appimage", GTHUMB, base_ref="3.12.6")
    apps.write_file(a["id"], "changes/drag-zoom.md", "# Drag to zoom\n")
    return apps.save({**a, "changes": [{"id": "drag-zoom", "title": "Drag a box to zoom", "patch_ids": []}]})


def said(text):
    async def script(c, sent):
        c.sent = sent
        await c.queue.put(AssistantMessage([TextBlock(text)], "m"))
        await c.queue.put(result())
    return script


async def test_each_kind_of_chat_has_its_own_prompt_and_tools(builder_env):
    engine, _, _, clients = builder_env
    await engine.new_chat("computer")
    engine._script = said("Settings → Display.")
    engine.send("How do I make the text bigger?")
    await wait_for(lambda: len(engine.conv.chat) == 2, "the answer")
    opts = clients[-1].options
    assert "## This chat: getting an app working on this computer" in opts.system_prompt["append"]
    assert {"mcp__host__suggest_app_chat", "mcp__host__send_findings"} <= set(opts.allowed_tools)
    assert "mcp__host__deliver" not in opts.allowed_tools and "mcp__host__offer_build" not in opts.allowed_tools

    gthumb_app()
    await engine.new_chat("app", app="gthumb")
    engine.send("Make it zoom faster too")
    await wait_for(lambda: len(engine.conv.chat) == 2, "the answer")
    opts = clients[-1].options
    assert "## This chat: fixing or adding a feature to one app" in opts.system_prompt["append"]
    assert {"mcp__host__deliver", "mcp__host__offer_build"} <= set(opts.allowed_tools)
    assert "mcp__host__suggest_app_chat" not in opts.allowed_tools
    # told which app, with what it comes from and the changes it has, once
    assert clients[-1].sent.startswith("[DA Vibe Manager, for you: this chat is about the user's app gThumb (id gthumb).]")
    assert GTHUMB in clients[-1].sent and "drag-zoom: Drag a box to zoom" in clients[-1].sent
    assert clients[-1].sent.endswith("Make it zoom faster too")
    engine.send("Thanks")
    await wait_for(lambda: len(engine.conv.chat) == 4, "the second answer")
    assert clients[-1].sent == "Thanks"


async def test_nothing_is_built_in_a_computer_chat_and_it_points_to_an_app_chat(builder_env):
    engine, _, _, _ = builder_env
    gthumb_app()
    await engine.new_chat("computer")
    out = []

    async def script(c, text):
        await c.queue.put(AssistantMessage([TextBlock("gThumb can't do that, but an app chat can add it.")], "m"))
        await wait_for(lambda: engine.builder.entry["parts"], "the text")
        for call in (engine.builder_offer({"app": "gThumb", "change": "Drag to zoom"}),
                     engine.builder_deliver({"kind": "appimage", "path": "/work/out/x.AppImage"}),
                     engine.builder_suggest_app({"app": "gthumb", "wish": "Zoom by dragging a box"})):
            try:
                out.append(await call)
            except Exception as e:  # noqa: BLE001
                out.append(e)
        await c.queue.put(result())
    engine._script = script
    engine.send("I wish gThumb could zoom by dragging a box")
    await wait_for(lambda: len(out) >= 3, "the tools")
    assert isinstance(out[0], ValueError) and "suggest_app_chat" in str(out[0])
    assert "Nothing is built in a chat about the computer" in str(out[1])
    assert out[2].startswith("Shown to the user")
    await wait_for(lambda: not engine.busy, "the turn's end")
    card = next(p for p in engine.conv.chat[-1]["parts"] if p["t"] == "suggest")
    assert card == {"t": "suggest", "app": "gThumb", "app_id": "gthumb", "wish": "Zoom by dragging a box"}


async def test_an_app_chat_is_about_one_app_the_user_picked_or_named(env):
    engine, _, _ = env
    gthumb_app()
    await engine.new_chat("app", app_name="gthumb")         # typed, but they have it: that one
    assert (engine.conv.mode, engine.conv.app, engine.conv.app_name) == ("app", "gthumb", "gThumb")
    await engine.new_chat("app", app_name="  mpv  player ")
    assert (engine.conv.app, engine.conv.app_name) == ("", "mpv player")
    with pytest.raises(UserError):
        await engine.new_chat("app")
    with pytest.raises(UserError):
        await engine.new_chat("app", app="nope")
    await engine.new_chat()                                  # the empty chat is used again, to choose afresh
    assert engine.conv.mode == "" and len(Conversation.list_all()) == 1
    engine.send("Why is my Wi-Fi slow?")                     # written without choosing: about the computer
    assert engine.conv.mode == "computer"
    await engine.new_chat("app", app="gthumb")               # this one has a message: a new chat
    assert engine.conv.mode == "app" and len(Conversation.list_all()) == 2


def test_chats_from_before_have_their_kind_from_what_happened_in_them(tmp_path):
    c = Conversation.create(tmp_path)
    c.chat = [{"kind": "user", "text": "Why is my Wi-Fi slow?"}]
    c.save()
    assert Conversation.load(c.id, tmp_path).mode == "computer"
    c.chat.append({"kind": "assistant", "parts": [{"t": "delivery", "id": "D1"}]})
    c.save()
    data = (c.dir / "state.json").read_text().replace('"mode": "", ', "")
    (c.dir / "state.json").write_text(data)
    assert Conversation.load(c.id, tmp_path).mode == "app"
    assert Conversation.list_all(tmp_path)[0]["mode"] == "app"


async def test_a_chat_about_getting_an_app_working_here_is_told_about_it_and_hands_on_what_it_found(builder_env):
    engine, _, _, clients = builder_env
    a = gthumb_app()
    apps.save({**a, "share": {"id": "a" * 32, "build": {"id": "b" * 12, "history": []}, "shared": [],
                              "works_on": []}})
    await engine.new_chat("computer", app="gthumb")
    assert (engine.conv.mode, engine.conv.app, engine.conv.app_name) == ("computer", "gthumb", "gThumb")
    out = []

    async def script(c, text):
        c.sent = getattr(c, "sent", None) or text            # the first message (a nudge may follow)
        await c.queue.put(AssistantMessage([TextBlock("It needs libfuse2, which Arch doesn't have by default.")], "m"))
        await wait_for(lambda: engine.builder.entry["parts"], "the text")
        out.append(await engine.builder_findings({"app": "gthumb", "findings": "On Arch it stops: libfuse.so.2 is missing. "
                                                  "Bundle it, or build with the static runtime."}))
        await c.queue.put(result())
    engine._script = script
    engine.send("gThumb doesn't start")
    await wait_for(lambda: out and not engine.busy, "the turn")
    sent = clients[-1].sent
    assert sent.startswith("[DA Vibe Manager, for you: this chat is about getting the user's app gThumb (id gthumb) working")
    assert "not built yet" in sent and GTHUMB in sent and "drag-zoom: Drag a box to zoom" in sent and sent.endswith("gThumb doesn't start")
    card = next(p for p in engine.conv.chat[-1]["parts"] if p["t"] == "findings")
    assert card == {"t": "findings", "app": "gThumb", "app_id": "gthumb",
                    "findings": "On Arch it stops: libfuse.so.2 is missing. Bundle it, or build with the static runtime."}
    assert out[0].startswith("Shown to the user")


async def test_findings_are_for_a_chat_about_the_computer_only(env):
    engine, _, _ = env
    gthumb_app()
    await engine.new_chat("app", app="gthumb")
    with pytest.raises(ValueError, match="fix it here"):
        await engine.builder_findings({"app": "gthumb", "findings": "x"})


async def test_a_new_chat_refused_while_the_assistant_works_leaves_no_empty_chat_behind(builder_env):
    engine, _, _, _ = builder_env
    gate = asyncio.Event()

    async def script(c, text):
        await c.queue.put(AssistantMessage([TextBlock("Looking.")], "m"))
        await gate.wait()
        await c.queue.put(result())
    engine._script = script
    engine.send("Why is my Wi-Fi slow?")
    before = [c["id"] for c in Conversation.list_all()]
    for _ in range(3):
        with pytest.raises(UserError, match="Wait for the assistant"):
            await engine.new_chat()
    assert [c["id"] for c in Conversation.list_all()] == before
    gate.set()
    await wait_for(lambda: not engine.busy, "turn end")


async def test_what_is_sent_while_a_chat_opens_goes_to_that_chat(builder_env):
    """Closing the chat before's assistant takes Claude Code seconds: the window shows the new chat once
    it's open, and anything sent from then on is the new chat's, never a turn in the chat before."""
    engine, _, _, clients = builder_env
    engine._script = said("Hello.")
    engine.send("First chat")
    await wait_for(lambda: len(engine.conv.chat) == 2, "the answer")
    old = engine.conv.id
    gate = asyncio.Event()
    closing = engine.builder.close

    async def slow_close():
        await gate.wait()
        await closing()
    engine.builder.close = slow_close
    switching = asyncio.create_task(engine.new_chat("computer"))
    await asyncio.sleep(0.01)
    assert engine.conv.id != old and engine.conv.mode == "computer"   # open at once, its kind set
    engine.send("Second chat")
    gate.set()
    await switching
    await wait_for(lambda: len(engine.conv.chat) == 2, "the new chat's answer")
    assert [e.get("text") for e in Conversation.load(old).chat if e["kind"] == "user"] == ["First chat"]
    assert engine.conv.chat[0]["text"] == "Second chat" and clients[-1].sent.endswith("Second chat")


async def test_asking_the_assistant_twice_for_an_update_starts_it_once(builder_env, monkeypatch):
    """A second click while the first opens the update's chat (closing the chat before's assistant
    takes Claude Code seconds): refused, not a second turn in the same chat."""
    engine, _, _, _ = builder_env
    engine._script = said("Hello.")
    engine.send("An earlier chat")
    await wait_for(lambda: len(engine.conv.chat) == 2, "the answer")
    closing = engine.builder.close

    async def slow_close():
        await asyncio.sleep(0.05)
        await closing()
    engine.builder.close = slow_close
    a = gthumb_app()
    apps.save({**a, "update": {"status": "available", "latest": "3.12.7"}})
    gate = asyncio.Event()

    async def update_task(*args):
        await gate.wait()
        return "Please update my gThumb to version 3.12.7, with the same changes."
    monkeypatch.setattr(engine.app_manager, "_update_task", update_task)
    first = asyncio.create_task(engine.app_manager.assistant("gthumb"))
    second = asyncio.create_task(engine.app_manager.assistant("gthumb"))
    results = await asyncio.gather(first, second, return_exceptions=True)
    assert [type(r) for r in results].count(UserError) == 1 and engine.busy
    assert [e["kind"] for e in engine.conv.chat] == ["user"]
    assert apps.load("gthumb")["chat"]["id"] == engine.conv.id
    engine._script = said("On it.")
    gate.set()
    await wait_for(lambda: not engine.busy, "turn end")
    assert [e["kind"] for e in engine.conv.chat] == ["user", "assistant"]


async def test_a_turn_may_end_on_a_card_that_tells_the_user_something(builder_env):
    """An app chat to start, or what it found: the card says it, so the turn ends there, without being
    asked again (and paying again) for a message. Nor is the card's call a step of its own."""
    engine, _, _, _ = builder_env
    await engine.new_chat("computer")
    queries = []

    async def script(c, text):
        queries.append(text)
        await c.queue.put(AssistantMessage([TextBlock("gThumb can't do that, but an app chat can add it."),
                                            ToolUseBlock("t1", "mcp__host__suggest_app_chat", {"app": "gThumb"})], "m"))
        await wait_for(lambda: engine.builder.entry["parts"], "the text")
        await engine.builder_suggest_app({"app": "gThumb", "wish": "Zoom by dragging a box"})
        await c.queue.put(result())
    engine._script = script
    engine.send("I wish gThumb could zoom by dragging a box")
    await wait_for(lambda: not engine.busy and engine.conv.chat[-1]["kind"] == "assistant", "the turn's end")
    assert len(queries) == 1 and [p["t"] for p in engine.conv.chat[-1]["parts"]] == ["text", "suggest"]


async def test_apps_named_in_another_script_are_told_apart(env):
    """Names are compared as names, in any script: two apps in Cyrillic aren't the same app."""
    engine, _, _ = env
    foto = apps.create("Фото", "appimage", "https://github.com/example/foto.git")
    await engine.new_chat("app", app_name="Видео")
    assert (engine.conv.app, engine.conv.app_name) == ("", "Видео")                  # not Фото's chat
    await engine.new_chat("app", app_name="фото")
    assert engine.conv.app == foto["id"]
    assert apps.same_name("gThumb", "GThumb ") and not apps.same_name("Фото", "Видео")
