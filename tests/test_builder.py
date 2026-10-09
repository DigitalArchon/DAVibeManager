"""The assistant: the podman-exec wrapper, its tools, and how its turns reach the chat."""

import asyncio

import pytest
from claude_agent_sdk import (AssistantMessage, ResultMessage, SystemMessage, TextBlock, ThinkingBlock, ToolResultBlock,
                               ToolUseBlock, UserMessage)

from davibemanager.builder import bridge
from davibemanager.builder.tools import check_packages
from davibemanager.workspace import podman
from helpers import wait_for


def test_the_wrapper_passes_only_the_named_variables_into_the_container(tmp_path, monkeypatch):
    monkeypatch.setattr(podman, "podman", lambda: "/usr/bin/podman")
    path = bridge.write_wrapper(tmp_path / "claude-x", "dla-x")
    text = path.read_text()
    assert text.splitlines()[-1] == 'exec /usr/bin/podman exec -i --detach-keys= -w /work $E dla-x /usr/local/bin/claude "$@"'
    for name in ("ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_ENTRYPOINT", "ANTHROPIC_MODEL", "MCP_TOOL_TIMEOUT"):
        assert f'-e {name}"' in text
    for name in ("HOME", "PATH", "SSH_AUTH_SOCK", "DISPLAY", "DBUS_SESSION_BUS_ADDRESS", "PWD"):
        assert f"-e {name}\"" not in text
    assert oct(path.stat().st_mode & 0o777) == "0o700"


@pytest.mark.parametrize("bad", [["-o", "APT::x"], ["foo;rm -rf /"], ["../x"], ["Foo"], [], ["a b"], ["--purge"]])
def test_package_names_are_checked_before_apt_sees_them(bad):
    with pytest.raises(ValueError):
        check_packages(bad)


def test_ordinary_package_names_pass():
    assert check_packages(["libgtk-3-dev", "g++", "python3:amd64", "meson=1.3.2-1ubuntu1"]) == [
        "libgtk-3-dev", "g++", "python3:amd64", "meson=1.3.2-1ubuntu1"]


class FakeClaude:
    """Stands in for ClaudeSDKClient: each query plays a script of SDK messages, calling the
    host tools in between as the real CLI would."""

    def __init__(self, options, script):
        self.options = options
        self.script = script
        self.queue: asyncio.Queue = asyncio.Queue()

    async def connect(self):
        await self.queue.put(SystemMessage("init", {"session_id": "sess-1"}))

    async def query(self, text):
        asyncio.get_running_loop().create_task(self.script(self, text))

    async def receive_messages(self):
        while True:
            yield await self.queue.get()

    async def interrupt(self):
        pass

    async def disconnect(self):
        pass


def result(sid="sess-1"):
    return ResultMessage("success", 1, 1, False, 1, sid, total_cost_usd=0.01, usage={"input_tokens": 5})


@pytest.fixture
async def builder_env(env):
    engine, fake, events = env
    engine.workspace = {"state": "running"}

    class Gateway:                      # only its token reaches the assistant
        token = "tok"

        async def stop(self):
            pass
    engine.gateway = Gateway()
    clients = []

    def factory(options):
        c = FakeClaude(options, engine._script)
        clients.append(c)
        return c
    engine.builder_client_factory = factory
    return engine, fake, events, clients


async def test_a_turn_reads_in_order_and_waits_for_the_user_on_this_computer(builder_env):
    engine, fake, events, clients = builder_env
    tool_results = []

    async def script(c, text):
        q = c.queue
        await q.put(AssistantMessage([TextBlock("Let me check your version first.")], "m"))
        await asyncio.sleep(0.05)       # the CLI's messages arrive in order: the text before the tool call
        tool_results.append(await engine.builder_host_command(
            {"command": "echo gThumb 3.12.6", "purpose": "Which gThumb you have", "risk": "read_only"}))
        await q.put(AssistantMessage([TextBlock("You have 3.12.6. Building now."),
                                      ToolUseBlock("t1", "Bash", {"command": "git clone https://example/gthumb"})], "m"))
        await q.put(UserMessage([ToolResultBlock("t1", "Cloning into 'gthumb'...", False)]))
        await q.put(AssistantMessage([TextBlock("Done.")], "m"))
        await q.put(result())
    engine._script = script
    engine.send("I wish gThumb could zoom by dragging")
    await wait_for(lambda: engine.requests, "request card")
    r = next(iter(engine.requests.values()))
    assert r.status == "pending" and engine.busy
    engine.run_request(r.id)
    await wait_for(lambda: r.status == "done", "command")
    engine.send_request(r.id)
    await wait_for(lambda: engine.conv.chat[-1]["kind"] == "assistant", "turn end")
    entry = engine.conv.chat[-1]
    assert [p["t"] for p in entry["parts"]] == ["text", "request", "text", "steps", "text"]
    assert entry["parts"][3]["items"][0]["summary"] == "git clone https://example/gthumb"
    assert "gThumb 3.12.6" in tool_results[0]
    assert engine.conv.session == "sess-1" and engine.conv.title.startswith("I wish gThumb")
    opts = clients[0].options
    assert opts.permission_mode == "bypassPermissions" and opts.env["ANTHROPIC_AUTH_TOKEN"] == "tok"
    assert "sk-test" not in str(opts.env)              # the real key never goes towards the container
    # a long command goes on in the background after a minute, so the user can talk meanwhile
    assert opts.env["CLAUDE_CODE_AUTO_BACKGROUND_TIMEOUT_MS"] == "60000"
    assert opts.env["BASH_DEFAULT_TIMEOUT_MS"] == str(2 * 3600 * 1000)
    assert {"CLAUDE_CODE_AUTO_BACKGROUND_TIMEOUT_MS", "BASH_DEFAULT_TIMEOUT_MS"} <= set(bridge.FORWARD)


async def test_a_question_waits_for_the_answer_and_a_typed_reply_counts(builder_env):
    engine, _, _, _ = builder_env
    answers = []

    async def script(c, text):
        await c.queue.put(AssistantMessage([TextBlock("gThumb can't do that yet, but I can add it.")], "m"))
        answers.append(await engine.builder_ask([{"question": "Shall I build it?", "options": ["Yes", "No"]}]))
        await c.queue.put(AssistantMessage([TextBlock("Good.")], "m"))
        answers.append(await engine.builder_ask([{"question": "Which version?"}]))
        await c.queue.put(AssistantMessage([TextBlock("OK.")], "m"))
        await c.queue.put(result())
    engine._script = script
    engine.send("gThumb zoom please")
    await wait_for(lambda: engine.questions, "question")
    engine.answer_question(1, ["Yes"])
    await wait_for(lambda: 2 in engine.questions, "second question")
    engine.send("the newest one")
    await wait_for(lambda: len(answers) == 2, "answers")
    assert "A: Yes" in answers[0] and "the newest one" in answers[1]


async def test_a_question_needs_a_reply_in_the_chat_first(builder_env):
    """Opus once explained things only in its thinking, then asked again: the user saw no answer."""
    engine, _, _, _ = builder_env
    got = []

    async def script(c, text):
        await c.queue.put(AssistantMessage([TextBlock("Nemo can't do that, but I can add it.")], "m"))
        got.append(await engine.builder_ask([{"question": "Shall I build it?", "options": ["Yes", "No"]}]))
        await c.queue.put(AssistantMessage([ToolUseBlock("t1", "Bash", {"command": "grep -rn FileManager1 src"})], "m"))
        for _ in range(2):              # nothing written since that step: refused, whatever it asks
            try:
                await engine.builder_ask([{"question": "Shall I build it?", "options": ["Yes", "No"]}])
            except Exception as e:      # noqa: BLE001 - the tool turns it into its message
                got.append(e)
        await c.queue.put(AssistantMessage([TextBlock("Your own Nemo stays; the new one becomes the default.")], "m"))
        got.append(await engine.builder_ask([{"question": "Shall I build it?", "options": ["Yes", "No"]}]))
        await c.queue.put(AssistantMessage([TextBlock("OK.")], "m"))
        await c.queue.put(result())
    engine._script = script
    engine.send("Nemo with a wallpaper")
    await wait_for(lambda: engine.questions, "question")
    engine.answer_question(1, ["First explain how it works as my default file manager"])
    await wait_for(lambda: 2 in engine.questions, "the question again, after a reply")
    engine.answer_question(2, ["Yes"])
    await wait_for(lambda: engine.conv.chat[-1]["kind"] == "assistant", "turn end")
    refused = got[1:3]
    assert all(type(e).__name__ == "Unanswered" for e in refused)
    assert refused[0].typed == "First explain how it works as my default file manager"
    assert len(engine.questions) == 2
    parts = [p["t"] for p in engine.conv.chat[-1]["parts"]]
    assert parts == ["text", "question", "steps", "text", "question", "text"]


def test_long_quick_replies_reach_the_user_whole():
    from davibemanager.engine import questions
    long = "A background image inside Nemo's file windows (behind the files), the same in every folder"
    assert questions([{"question": "Which?", "options": [long, "No"]}])[0]["options"] == [long, "No"]


async def test_a_question_after_a_command_needs_no_new_message(builder_env):
    """Opus asked "Shall I build it?" right after the user ran its command, having said what it would
    build before it: refusing that made it think its cards were broken."""
    engine, _, _, _ = builder_env
    got = []

    async def script(c, text):
        await c.queue.put(AssistantMessage([TextBlock("I can add it. First I'll check your Nemo version.")], "m"))
        await c.queue.put(AssistantMessage([ToolUseBlock("t1", "Bash", {"command": "git describe"})], "m"))
        got.append(await engine.builder_ask([{"question": "Shall I build it?", "options": ["Yes", "No"]}]))
        await c.queue.put(AssistantMessage([TextBlock("OK.")], "m"))
        await c.queue.put(result())
    engine._script = script
    engine.send("Nemo with a wallpaper")
    await wait_for(lambda: engine.questions, "question")
    engine.answer_question(1, ["Yes"])
    await wait_for(lambda: got, "answer")
    assert "A: Yes" in got[0]


async def test_no_question_before_a_word_in_the_turn(builder_env):
    engine, _, _, _ = builder_env
    got = []

    async def script(c, text):
        try:
            await engine.builder_ask([{"question": "Shall I build it?", "options": ["Yes", "No"]}])
        except Exception as e:  # noqa: BLE001
            got.append(e)
        await c.queue.put(AssistantMessage([TextBlock("OK.")], "m"))
        await c.queue.put(result())
    engine._script = script
    engine.send("Nemo with a wallpaper")
    await wait_for(lambda: got, "refusal")
    assert type(got[0]).__name__ == "Unanswered" and got[0].typed == "" and not engine.questions


async def test_the_refusal_tells_the_assistant_what_to_answer(monkeypatch):
    import claude_agent_sdk
    from davibemanager.builder import tools
    from davibemanager.builder.tools import Unanswered

    class Host:
        async def builder_ask(self, questions):
            raise Unanswered("First tell me how hard it is")
    monkeypatch.setattr(claude_agent_sdk, "create_sdk_mcp_server", lambda name, version, made: made)
    ask = next(t for t in tools.make_server(Host()) if t.name == "ask_user")
    out = await ask.handler({"questions": [{"question": "Build it?"}]})
    assert out["is_error"] and '"First tell me how hard it is"' in out["content"][0]["text"]
    assert "never sees your thinking" in out["content"][0]["text"]


async def test_a_turn_that_ends_without_a_message_is_asked_for_one_once(builder_env):
    """DA Toolkit's fix for Opus: it thought its answer, worked, and ended the turn without a word."""
    engine, _, _, _ = builder_env
    sent = []

    async def script(c, text):
        sent.append(text)
        if len(sent) == 1:
            await c.queue.put(AssistantMessage([TextBlock("Let me check how Cinnamon opens folders.")], "m"))
            await c.queue.put(AssistantMessage([ThinkingBlock("Your Nemo stays; the new one becomes the default.", "sig")], "m"))
            await c.queue.put(AssistantMessage([ToolUseBlock("t1", "Bash", {"command": "grep -rn FileManager1 src"})], "m"))
            await c.queue.put(AssistantMessage([ToolUseBlock("t2", "Bash", {"command": "ls data"})], "m"))
        elif len(sent) == 2:
            await c.queue.put(AssistantMessage([TextBlock("Your own Nemo stays installed; the new one becomes the default.")], "m"))
        await c.queue.put(result())
    engine._script = script
    engine.send("How would it work as my default file manager?")
    await wait_for(lambda: engine.conv.chat[-1]["kind"] == "assistant", "turn end")
    assert len(sent) == 2 and "2 steps in your sandbox" in sent[1] and "since your last step" in sent[1]
    entry = engine.conv.chat[-1]
    assert [p["t"] for p in entry["parts"]] == ["text", "thinking", "steps", "text"]
    assert "cost_usd" not in entry                    # Claude Code's own figure prices everything as Claude
    assert "no_message_nudge" in (engine.conv.dir / "events.jsonl").read_text()


async def test_the_nudge_is_said_only_once(builder_env):
    engine, _, _, _ = builder_env
    sent = []

    async def script(c, text):
        sent.append(text)
        await c.queue.put(AssistantMessage([ThinkingBlock("I'll just think.", "sig")], "m"))
        await c.queue.put(result())
    engine._script = script
    engine.send("hello")
    await wait_for(lambda: engine.conv.chat[-1]["kind"] == "assistant", "turn end")
    await asyncio.sleep(0.05)
    assert len(sent) == 2 and "(only thinking)" in sent[1] and "since your last message from the user" in sent[1]
    assert [p["t"] for p in engine.conv.chat[-1]["parts"]] == ["thinking"]


async def test_a_question_asked_only_in_the_message_is_put_on_a_card(builder_env):
    """Opus wrote "1. Shall I build it?  2. How should the image fill the window?" and ended its turn."""
    engine, _, _, _ = builder_env
    sent, answers = [], []

    async def script(c, text):
        sent.append(text)
        if len(sent) == 1:
            await c.queue.put(AssistantMessage([TextBlock("I can add it.\n\n**Two quick questions:**\n\n1. Shall I build it?\n"
                                                          "2. How should the image fill the window? Zoom, tile or centred.")], "m"))
        elif len(sent) == 2:
            answers.append(await engine.builder_ask([{"question": "Shall I build it?", "options": ["Yes, build it", "No thanks"]}]))
            await c.queue.put(AssistantMessage([TextBlock("Starting now.")], "m"))
        await c.queue.put(result())
    engine._script = script
    engine.send("Nemo with a wallpaper")
    await wait_for(lambda: engine.questions, "the question card")
    engine.answer_question(1, ["Yes, build it"])
    await wait_for(lambda: engine.conv.chat[-1]["kind"] == "assistant", "turn end")
    # a build offered with ask_user gets the offer's card: its cost, and finding out how big it is first
    assert len(sent) == 2 and "ask_user" in sent[1] and answers[0] == "The user said yes: build it."
    assert engine.questions[1]["offer"] and "First, tell me how big a change it is" in engine.questions[1]["questions"][0]["options"]
    assert [p["t"] for p in engine.conv.chat[-1]["parts"]] == ["text", "question", "text"]
    assert "question_in_text_nudge" in (engine.conv.dir / "events.jsonl").read_text()


def test_only_a_question_counts_as_one():
    from davibemanager.builder.bridge import asks_in_text
    entry = lambda text: {"parts": [{"t": "text", "text": text}]}
    assert asks_in_text(entry("Shall I build it?")) and asks_in_text(entry("**Want me to?**"))
    assert not asks_in_text(entry("Done. Open it from your menu.")) and not asks_in_text(entry("See https://x.org/?a=1 for more."))
    assert not asks_in_text({"parts": [{"t": "text", "text": "Ready?"}, {"t": "question", "id": 1}]})


async def test_what_the_user_shares_about_this_computer_goes_with_the_first_message_only(builder_env, monkeypatch):
    from davibemanager import sysinfo
    engine, _, _, _ = builder_env
    engine.conv.mode = "computer"
    monkeypatch.setattr(sysinfo, "gather", lambda parts: "- System: Linux Mint 22.3 (Zena)\n- Kernel: 7.0.0-38-generic (x86_64)"
                        if "system" in parts else "")
    sent = []

    async def script(c, text):
        sent.append(text)
        await c.queue.put(AssistantMessage([TextBlock("OK.")], "m"))
        await c.queue.put(result())
    engine._script = script
    engine.send("Nemo with a wallpaper")              # nothing shared: just the message
    await wait_for(lambda: len(engine.conv.chat) == 2, "first turn")
    engine.save_settings({"share_about": ["system"]})
    engine.send("And per folder?")
    await wait_for(lambda: len(engine.conv.chat) == 4, "second turn")
    engine.send("Thanks")
    await wait_for(lambda: len(engine.conv.chat) == 6, "third turn")
    assert sent[0] == "Nemo with a wallpaper"
    assert sent[1].startswith(sysinfo.HEADER) and "Linux Mint 22.3" in sent[1] and sent[1].endswith("And per folder?")
    assert sent[2] == "Thanks"                          # the session has it already
    assert engine.conv.chat[2]["shared"].startswith("- System: Linux Mint 22.3")
    assert engine._outside().check("nemo 7.0.0-38-generic wallpaper")   # never in a web search


def test_what_is_shared_is_checked():
    import pytest as _pytest
    from davibemanager.models import UserError
    from davibemanager.engine import Engine
    e = Engine.__new__(Engine)
    class C: pass
    e.cfg = C(); e.cfg.settings = __import__("davibemanager.config", fromlist=["Settings"]).Settings()
    e._save_config = lambda c: None; e._changed = lambda: None
    with _pytest.raises(UserError):
        e.save_settings({"share_about": ["system", "my files"]})
    e.save_settings({"share_about": ["hardware", "system"]})
    assert e.cfg.settings.share_about == ["system", "hardware"]


def test_the_computer_is_described_from_the_system_only():
    from davibemanager import sysinfo
    text = sysinfo.gather(["system", "hardware"])
    assert "- System: " in text and "- Processor: " in text and "- Memory: " in text
    assert sysinfo.gather([]) == ""


def state(s):
    """The CLI's session_state_changed: running, or idle once it has nothing more to do."""
    return SystemMessage("session_state_changed", {"type": "system", "subtype": "session_state_changed", "state": s})


async def test_a_message_while_it_works_reaches_it_straight_away_and_shows_where_it_was_written(builder_env):
    engine, _, events, clients = builder_env
    seen = []
    gate = asyncio.Event()

    async def script(c, text):
        seen.append(text)
        if len(seen) == 1:
            await c.queue.put(state("running"))
            await c.queue.put(AssistantMessage([TextBlock("Building it now."), ToolUseBlock("t1", "Bash", {"command": "make"})], "m"))
            await gate.wait()
            # the CLI hands the message over with the step's result, in the same turn
            await c.queue.put(UserMessage([ToolResultBlock("t1", "built", False)]))
            await c.queue.put(AssistantMessage([TextBlock("Built, and yes: it'll keep your settings.")], "m"))
            await c.queue.put(result())
            await c.queue.put(state("idle"))
    engine._script = script
    engine.send("Build it")
    await wait_for(lambda: engine.builder and engine.builder.entry and engine.builder.entry["parts"], "first step")
    engine.send("Will it keep my settings?")
    await wait_for(lambda: len(seen) == 2, "message sent during the turn")
    assert seen[1] == "Will it keep my settings?" and engine.busy
    assert [p["t"] for p in engine.builder.entry["parts"]] == ["text", "steps", "user"]
    gate.set()
    await wait_for(lambda: engine.conv.chat[-1]["kind"] == "assistant", "turn end")
    assert [e["kind"] for e in engine.conv.chat] == ["user", "assistant"]
    assert [p["t"] for p in engine.conv.chat[-1]["parts"]] == ["text", "steps", "user", "text"]
    assert clients[0].options.env["CLAUDE_CODE_EMIT_SESSION_STATE_EVENTS"] == "1"


async def test_a_message_late_in_a_turn_gets_its_reply_in_the_same_entry(builder_env):
    """Written while the final text streamed: the CLI answers it in a turn of its own straight after,
    and only then goes idle."""
    engine, _, _, _ = builder_env
    seen = []
    gate = asyncio.Event()

    async def script(c, text):
        seen.append(text)
        if len(seen) == 1:
            await c.queue.put(state("running"))
            await gate.wait()
            await c.queue.put(AssistantMessage([TextBlock("Here's how to change it.")], "m"))
            await c.queue.put(result())
            await asyncio.sleep(0.05)
            await c.queue.put(AssistantMessage([TextBlock("And for your second question: yes.")], "m"))
            await c.queue.put(result())
            await c.queue.put(state("idle"))
    engine._script = script
    engine.send("How do I change my wallpaper?")
    await wait_for(lambda: engine.busy and engine.builder._state == "running", "running")
    engine.send("Can it change by itself?")
    gate.set()
    await wait_for(lambda: engine.conv.chat[-1]["kind"] == "assistant", "turn end")
    await asyncio.sleep(0.05)
    assert [e["kind"] for e in engine.conv.chat] == ["user", "assistant"]
    entry = engine.conv.chat[-1]
    assert [p["t"] for p in entry["parts"]] == ["user", "text"]
    assert "second question: yes" in entry["parts"][1]["text"]
    assert not engine.busy and len(seen) == 2       # no nudge: the user had their answer


async def test_a_finished_background_task_gets_an_entry_of_its_own(builder_env):
    """A build left running in the background wakes the CLI when it finishes, without a message
    from the user: what it says then is shown, and nobody's message is answered by it."""
    engine, _, events, _ = builder_env
    seen = []

    async def script(c, text):
        seen.append(text)
        await c.queue.put(state("running"))
        await c.queue.put(AssistantMessage([TextBlock("The build is running; it takes a few minutes."),
                                            ToolUseBlock("t1", "Bash", {"command": "make", "run_in_background": True})], "m"))
        await c.queue.put(UserMessage([ToolResultBlock("t1", "Command running in background with ID: b1", False)]))
        await c.queue.put(AssistantMessage([TextBlock("I'll tell you when it's done.")], "m"))
        await c.queue.put(result())
        await c.queue.put(state("idle"))
    engine._script = script
    engine.send("Build it")
    await wait_for(lambda: engine.conv.chat[-1]["kind"] == "assistant" and not engine.busy, "first turn")
    q = engine.builder._client.queue
    await q.put(state("running"))
    await q.put(AssistantMessage([TextBlock("The build finished: your new gThumb is ready.")], "m"))
    await q.put(result())
    await q.put(state("idle"))
    await wait_for(lambda: len(engine.conv.chat) == 3, "the woken entry")
    woken = engine.conv.chat[-1]
    assert woken.get("woken") and woken["parts"] == [{"t": "text", "text": "The build finished: your new gThumb is ready."}]
    assert not engine.busy and len(seen) == 1
    assert sum(1 for e in events if e["type"] == "turn_start") == 2


async def test_a_turn_with_work_still_running_ends_only_when_the_cli_is_idle(builder_env):
    """A background agent keeps the CLI running past a result: the entry stays open, the nudge waits."""
    engine, _, _, _ = builder_env
    seen = []

    async def script(c, text):
        seen.append(text)
        if len(seen) == 1:
            await c.queue.put(state("running"))
            await c.queue.put(AssistantMessage([ToolUseBlock("t1", "Agent", {"description": "build gThumb"})], "m"))
            await c.queue.put(UserMessage([ToolResultBlock("t1", "Agent started in the background", False)]))
            await c.queue.put(result())
        elif len(seen) == 2:
            await c.queue.put(AssistantMessage([TextBlock("Done: it's ready to try.")], "m"))
            await c.queue.put(result())
            await c.queue.put(state("idle"))
    engine._script = script
    engine.send("Build it")
    await wait_for(lambda: engine.builder and engine.builder._ended, "the first result")
    await asyncio.sleep(0.05)
    assert engine.busy and len(seen) == 1 and engine.conv.chat[-1]["kind"] == "user"
    await engine.builder._client.queue.put(state("idle"))
    await wait_for(lambda: engine.conv.chat[-1]["kind"] == "assistant", "turn end")
    assert len(seen) == 2 and "since your last step" in seen[1]


async def test_stopping_ends_the_entry_whatever_still_runs(builder_env):
    engine, _, _, _ = builder_env

    async def script(c, text):
        await c.queue.put(state("running"))
        await c.queue.put(AssistantMessage([TextBlock("Starting."), ToolUseBlock("t1", "Bash", {"command": "make"})], "m"))
    engine._script = script
    engine.send("Build it")
    await wait_for(lambda: engine.busy and engine.builder.entry["parts"], "working")
    await engine.builder._client.queue.put(ResultMessage("success", 1, 1, False, 1, "sess-1", terminal_reason="aborted_tools"))
    await wait_for(lambda: engine.conv.chat[-1]["kind"] == "assistant", "turn end")
    assert engine.conv.chat[-1]["error"] == "stopped" and not engine.busy
    # what it says when its build finishes, still running all along, gets an entry of its own
    q = engine.builder._client.queue
    await q.put(AssistantMessage([TextBlock("The build you stopped me during has finished.")], "m"))
    await q.put(result())
    await q.put(state("idle"))
    await wait_for(lambda: len(engine.conv.chat) == 3, "the woken entry")
    assert engine.conv.chat[-1].get("woken") and not engine.busy


async def test_a_question_straight_after_a_message_written_during_the_turn_waits_for_an_answer(builder_env):
    engine, _, _, _ = builder_env
    engine.conv.mode = "computer"
    out = []
    gate = asyncio.Event()

    async def script(c, text):
        if text == "Build it":
            await c.queue.put(AssistantMessage([TextBlock("Building.")], "m"))
            await gate.wait()
            try:
                out.append(await engine.builder_ask([{"question": "Zoom or tile?", "options": ["Zoom", "Tile"]}]))
            except Exception as e:  # noqa: BLE001
                out.append(e)
            await c.queue.put(result())
    engine._script = script
    engine.send("Build it")
    await wait_for(lambda: engine.busy and engine.builder.entry["parts"], "working")
    engine.send("How long will it take?")
    gate.set()
    await wait_for(lambda: out, "the question")
    assert getattr(out[0], "typed", None) == "How long will it take?"


async def test_the_assistant_needs_a_key_before_anything(env):
    engine, _, _ = env
    from davibemanager import creds
    creds.delete_secret("provider", "Fake")
    with pytest.raises(Exception, match="API key"):
        engine.send("hi")


async def test_installing_packages_runs_apt_as_root_with_the_names_after_a_double_dash(builder_env, monkeypatch):
    engine, _, _, _ = builder_env
    calls = []

    async def exec_root(name, argv, **kw):
        calls.append(argv)
        return 0, "Setting up meson"
    monkeypatch.setattr(podman, "exec_root", exec_root)
    out = await engine.builder_install(["meson", "ninja-build"])
    assert "Installed: meson ninja-build" in out
    assert calls[-1][-3:] == ["--", "meson", "ninja-build"] and "apt-get" in calls[-1]


def test_steps_are_summarised():
    assert bridge.summarize_tool("Bash", {"command": "make -j8\nmake install"}) == "make -j8 ⏎ make install"
    assert bridge.summarize_tool("mcp__host__install_packages", {"packages": ["meson", "ninja-build"]}) == "meson ninja-build"
    assert bridge.summarize_tool("TodoWrite", {"todos": [{"status": "in_progress", "activeForm": "Building gThumb"}]}) == "Building gThumb"


async def test_retries_reaching_the_model_are_shown_with_the_gateways_reason(builder_env):
    engine, _, events, _ = builder_env
    engine.network.append({"kind": "model", "status": 502, "error": "NanoGPT redirected the request; refusing to follow."})
    done = asyncio.Event()

    async def script(c, text):
        await c.queue.put(SystemMessage("api_retry", {"attempt": 2, "max_retries": 10, "error_status": 502, "error": "unknown"}))
        await done.wait()
        await c.queue.put(AssistantMessage([TextBlock("hello")], "m"))
        await c.queue.put(result())
    engine._script = script
    engine.send("hi")
    await wait_for(lambda: engine.builder and engine.builder.entry and engine.builder.entry.get("retry"), "retry")
    retry = engine.builder.entry["retry"]
    assert retry["attempt"] == 2 and "redirected" in retry["reason"]
    assert any(e["type"] == "entry" and e["entry"].get("retry") for e in events)
    done.set()
    await wait_for(lambda: engine.conv.chat[-1]["kind"] == "assistant", "turn end")
    assert "retry" not in engine.conv.chat[-1]


def test_the_assistants_commits_carry_no_attribution_of_its_own(tmp_path):
    import json
    session = bridge.BuilderSession(container="c", wrapper=tmp_path / "claude", host=None, env=dict, emit=lambda *a, **k: None,
                                    on_session=print, on_change=print, on_turn_end=print)
    settings = json.loads(session._options().settings)
    assert settings["includeCoAuthoredBy"] is False and settings["attribution"] == {"commit": "", "pr": ""}


def test_none_of_the_assistants_tools_can_install_or_run_anything_on_this_computer():
    """Its only tools: ask, request (the user runs it), apt in the sandbox, show a picture, search the web (checked for
    anything from this computer); in an app chat, offer a build (a question on the app's card) and hand over to
    quarantine; in a computer chat, point to an app chat (a card). Installing and running on this computer are the
    user's clicks, through the window's own API (per-launch token, unreachable from the sandbox's network)."""
    from davibemanager.builder.tools import tool_names
    common = ("ask_user", "request_host_command", "install_packages", "show_screenshot", "web_search")
    assert sorted(tool_names("app")) == sorted(f"mcp__host__{n}" for n in (*common, "offer_build", "deliver"))
    assert sorted(tool_names("computer")) == sorted(f"mcp__host__{n}" for n in (*common, "suggest_app_chat", "send_findings"))


# ---------------------------------------------------------------- what the user sees of the work

def test_what_the_sandbox_is_doing_is_read_from_the_probe():
    from davibemanager.engine import parse_activity
    out = ("@@CPU 5000000\n@@MEM 2147483648\n@@PS\n"
           " 95.0 cc1plus\n 90.0 cc1plus\n 12.0 ninja\n 40.0 claude\n  0.0 sleep\n  0.1 bash\n"
           "@@TAIL bx1 1791450000\n[ 41%] Building CXX object a.o\n\x1b[32m[ 42%] Building CXX object b.o\x1b[0m\n")
    a = parse_activity(out)
    assert a["usage"] == 5000000 and a["mem"] == 2147483648
    assert a["procs"] == [["cc1plus", 2], ["ninja", 1]]           # the sandbox's own programs left out
    assert a["tails"]["bx1"][-1] == "[ 42%] Building CXX object b.o" and a["mtimes"]["bx1"] == "1791450000"


async def test_while_it_works_the_chat_shows_what_the_sandbox_is_doing(builder_env, monkeypatch):
    from davibemanager import engine as engine_mod
    from fakesandbox import FakeSandbox
    monkeypatch.setattr(engine_mod, "ACTIVITY_EVERY", 0.02)
    engine, _, events, _ = builder_env
    sb = FakeSandbox()
    sb.install(monkeypatch, engine)
    sb.activity = [f"@@CPU {n * 1000000}\n@@MEM 1048576\n@@PS\n 99.0 cc1\n@@TAIL t1 1\nlinking gthumb\n" for n in range(1, 4)]
    gate = asyncio.Event()

    async def script(c, text):
        await c.queue.put(AssistantMessage([TextBlock("Building."), ToolUseBlock("u1", "Bash", {"command": "ninja -C build"})], "m"))
        await c.queue.put(SystemMessage("task_started", {"subtype": "task_started", "task_id": "t1", "tool_use_id": "u1",
                                                         "description": "ninja -C build"}))
        await gate.wait()
        await c.queue.put(SystemMessage("task_notification", {"subtype": "task_notification", "task_id": "t1", "status": "completed"}))
        await c.queue.put(UserMessage([ToolResultBlock("u1", "done", False)]))
        await c.queue.put(AssistantMessage([TextBlock("Built.")], "m"))
        await c.queue.put(result())
    engine._script = script
    engine.send("Build it")
    await wait_for(lambda: engine.activity and engine.activity["tasks"] and engine.activity["cpu"] is not None, "activity")
    a = engine.activity
    assert a["procs"] == [["cc1", 1]] and a["mem"] == 1048576 and a["cpu"] > 0
    assert 0 < a["cpu_share"] <= 100                   # of what the sandbox may use, not per core (up to 400%)

    assert a["tasks"][0]["description"] == "ninja -C build" and a["tasks"][0]["last"] == ["linking gthumb"]
    assert ["-", "t1"] in sb.activity_args            # the task's output asked for by its id
    gate.set()
    await wait_for(lambda: engine.conv.chat[-1]["kind"] == "assistant", "turn end")
    await wait_for(lambda: engine.activity is None, "the look ends with the work")
    assert events[-1]["type"] == "activity" or any(e["type"] == "activity" and e["activity"] is None for e in events)
    assert engine.builder.tasks == {}


async def test_the_sandbox_going_quiet_while_a_step_runs_is_counted(builder_env, monkeypatch):
    from davibemanager import engine as engine_mod
    from fakesandbox import FakeSandbox
    monkeypatch.setattr(engine_mod, "ACTIVITY_EVERY", 0.02)
    engine, _, _, _ = builder_env
    sb = FakeSandbox()
    sb.install(monkeypatch, engine)
    sb.activity = ["@@CPU 1000\n@@MEM 1\n@@PS\n"] * 200     # no processor time used, nothing written
    gate = asyncio.Event()

    async def script(c, text):
        await c.queue.put(AssistantMessage([TextBlock("Fetching."), ToolUseBlock("u1", "Bash", {"command": "git clone x"})], "m"))
        await gate.wait()
        await c.queue.put(result())
    engine._script = script
    engine.send("Build it")
    await wait_for(lambda: engine.activity and engine.activity["quiet"] > 0, "quiet counted")
    gate.set()
    await wait_for(lambda: not engine.busy, "turn end")


async def test_a_build_offer_has_the_apps_card_and_can_ask_how_big_first(builder_env):
    engine, _, _, _ = builder_env
    replies = []

    async def script(c, text):
        if replies:                     # the nudge for a message after the last card
            await c.queue.put(AssistantMessage([TextBlock("All right, I won't build it.")], "m"))
            await c.queue.put(result())
            return
        await c.queue.put(AssistantMessage([TextBlock("gThumb is open source, so I can probably add it.")], "m"))
        await asyncio.sleep(0.02)
        replies.append(await engine.builder_offer({"app": "gThumb", "change": "Drag a box to zoom"}))
        await c.queue.put(AssistantMessage([TextBlock("I read its viewer code: about four files.")], "m"))
        await asyncio.sleep(0.02)
        replies.append(await engine.builder_offer({"app": "gThumb", "change": "Drag a box to zoom", "size": "significant",
                                                   "size_reason": "A new tool in the image viewer."}))
        await c.queue.put(result())
    engine._script = script
    engine.send("Drag to zoom in gThumb")
    await wait_for(lambda: engine.questions, "the offer")
    q = engine.questions[1]
    assert q["offer"] == {"app": "gThumb", "change": "Drag a box to zoom"}
    assert q["questions"][0]["options"] == ["Yes, build it", "First, tell me how big a change it is", "No thanks"]
    engine.answer_question(1, ["First, tell me how big a change it is"])
    await wait_for(lambda: len(engine.questions) == 2, "the offer with its size")
    q2 = engine.questions[2]
    assert q2["offer"]["size"] == "significant" and q2["questions"][0]["options"] == ["Yes, build it", "No thanks"]
    engine.answer_question(2, ["No thanks"])
    await wait_for(lambda: engine.conv.chat[-1]["kind"] == "assistant", "turn end")
    assert "read the code" in replies[0] and "simple fix, a significant modification or a major rewrite" in replies[0]
    assert "doesn't want it built" in replies[1]


async def test_an_offer_needs_the_app_and_the_change(builder_env):
    engine, _, _, _ = builder_env
    with pytest.raises(ValueError):
        await engine.builder_offer({"app": "gThumb"})


async def test_the_chats_cost_is_the_tokens_counted_at_each_models_listed_price(env):
    from davibemanager.conversation import Conversation
    from davibemanager.llm import capabilities
    engine, _, events = env
    engine.models._caps["Fake"] = capabilities.parse([
        {"id": "z-ai/glm-5.3", "subscription": {"included": True}, "pricing": {
            "prompt": 0.7, "completion": 2.2, "cacheReadInputPer1kTokens": 0.00013, "currency": "USD", "unit": "per_million_tokens"}},
        {"id": "TEE/glm-5.3", "subscription": {"included": False}, "pricing": {
            "prompt": 1.4, "completion": 4.4, "currency": "USD", "unit": "per_million_tokens"}}])
    million = {"input": 1_000_000, "output": 100_000, "cache_read": 0, "cache_write": 0}
    for model in ("private/glm-5-3", "private/glm-5-3", "z-ai/glm-5.3", "some/unlisted-model"):
        engine._network_event({"kind": "model", "model": model, "status": 200, "usage": million})
    engine._network_event({"kind": "model", "model": "z-ai/glm-5.3", "status": 200,
                           "usage": {"input": 0, "output": 0, "cache_read": 1_000_000, "cache_write": 0}})
    sp = engine.spend()
    assert sp["paid"] == pytest.approx(2 * (1.4 + 0.44))         # a private model at its enclave twin's price
    assert sp["included"] == pytest.approx(0.7 + 0.22 + 0.13)    # cache reads at their own price
    assert sp["unpriced"] == ["some/unlisted-model"] and sp["tokens"] == 5_400_000
    assert events[-2]["type"] == "spend" and events[-2]["spend"]["tokens"] == sp["tokens"]
    engine._persist()
    assert Conversation.load(engine.conv.id).tokens["private/glm-5-3"]["requests"] == 2
    engine.conv.chat.append({"kind": "user", "text": "hi", "at": 0})
    await engine.new_chat()
    assert engine.spend()["tokens"] == 0                          # each chat its own


def test_listed_prices_are_read_per_million_and_the_cache_per_thousand():
    from davibemanager.llm import capabilities
    caps = capabilities.parse([{"id": "a", "pricing": {"prompt": 4, "completion": 20, "cacheReadInputPer1kTokens": 0.0002,
                                                       "cacheWriteInputPer1kTokens": 0.005, "currency": "USD"}},
                               {"id": "b", "pricing": {"currency": "USD", "note": "per image"}}])
    assert caps["a"]["pricing"] == {"input": 4, "output": 20, "cache_read": pytest.approx(0.2), "cache_write": pytest.approx(5)}
    assert caps["b"]["pricing"] is None and capabilities.cost(caps["b"], {"input": 5}) is None


def test_the_processor_is_shown_as_a_share_of_what_the_sandbox_may_use(monkeypatch):
    from davibemanager import engine as engine_mod
    from davibemanager.config import Config
    e = engine_mod.Engine(Config(), lambda ev: None, None, save_config=lambda c: None)
    monkeypatch.setattr(engine_mod.os, "cpu_count", lambda: 4)
    for limit, cores in (("4", 4), ("2", 2), ("16", 4), ("1.5", 1.5), ("0", 4)):
        e.cfg.settings.container_cpus = limit
        assert e._sandbox_cores() == cores


def _photo_with_location() -> bytes:
    from io import BytesIO

    from PIL import Image
    im = Image.new("RGB", (40, 30), (200, 10, 10))
    exif = Image.Exif()
    exif[0x8825] = {2: (35.0, 41.0, 0.0)}              # GPS: where it was taken
    exif[0x010F] = "PhoneMaker"
    out = BytesIO()
    im.save(out, "JPEG", exif=exif.tobytes())
    return out.getvalue()


async def test_files_the_user_attaches_reach_the_sandbox_with_the_message(builder_env, monkeypatch):
    from io import BytesIO

    from PIL import Image
    from fakesandbox import FakeSandbox
    engine, _, _, _ = builder_env
    sb = FakeSandbox()
    sb.install(monkeypatch, engine)
    sent = []

    async def script(c, text):
        sent.append(text)
        await c.queue.put(AssistantMessage([TextBlock("Got them.")], "m"))
        await c.queue.put(result())
    engine._script = script
    photo = await engine.attach("Holiday photo.JPG", _photo_with_location())
    spec = await engine.attach("spec.md", b"Use the colour #4a90d9 for the toolbar of zorblatt-viewer 7.2\n")
    again = await engine.attach("spec.md", b"a second spec")
    assert photo["kind"] == "image" and photo["name"] == "Holiday-photo.jpg" and spec["kind"] == "file"
    assert again["path"].endswith("/spec-2.md")                         # a name used in this chat isn't reused
    engine.unattach(again["id"])
    await engine.send_with_files("Make it look like this", [photo["id"], spec["id"]])
    await wait_for(lambda: engine.conv.chat[-1]["kind"] == "assistant", "turn end")
    # in the sandbox before the assistant reads the message, the picture without its hidden details
    folder = f"/work/from-you/{engine.conv.id}"
    pic = sb.files[f"{folder}/Holiday-photo.jpg"]
    with Image.open(BytesIO(pic)) as im:
        assert not im.getexif() and im.size == (40, 30)
    assert sb.files[f"{folder}/spec.md"].startswith(b"Use the colour")
    assert f"{folder}/spec-2.md" not in sb.files
    assert "Make it look like this" in sent[0] and f"{folder}/Holiday-photo.jpg (a picture" in sent[0] and "Read" in sent[0]
    user = engine.conv.chat[0]
    assert user["text"] == "Make it look like this" and [f["name"] for f in user["files"]] == ["Holiday-photo.jpg", "spec.md"]
    assert engine.attachment_file(photo["id"]).read_bytes() == pic          # shown in the chat
    # from this computer: never in a web search
    assert engine._outside().check("zorblatt-viewer 7.2 toolbar colour")
    assert not engine._attached


async def test_files_sent_while_the_sandbox_starts_are_put_there_before_the_turn(builder_env, monkeypatch):
    from fakesandbox import FakeSandbox
    engine, _, _, _ = builder_env
    sb = FakeSandbox()
    sb.install(monkeypatch, engine)
    engine.workspace = {"state": "starting"}
    seen = []

    async def script(c, text):
        seen.append(any(p.startswith("/work/from-you/") for p in sb.files))
        await c.queue.put(AssistantMessage([TextBlock("Seen.")], "m"))
        await c.queue.put(result())
    engine._script = script
    f = await engine.attach("notes.txt", b"step one")
    await engine.send_with_files("", [f["id"]])                            # a file alone is a message too
    assert engine.conv.chat[-1]["queued"] and not sb.files
    engine.workspace = {"state": "running"}
    engine._start_turn(engine._queued.pop())
    await wait_for(lambda: engine.conv.chat[-1]["kind"] == "assistant", "turn end")
    assert seen == [True]


async def test_a_picture_that_cant_be_cleaned_or_a_file_too_big_isnt_attached(env, monkeypatch):
    from io import BytesIO

    from PIL import Image

    from davibemanager import engine as engine_mod
    engine, _, _ = env
    out = BytesIO()
    Image.new("RGB", (4, 4)).save(out, "PPM")
    with pytest.raises(engine_mod.UserError, match="hidden details"):
        await engine.attach("scan.ppm", out.getvalue())
    monkeypatch.setattr(engine_mod, "MAX_ATTACHMENT", 10)
    with pytest.raises(engine_mod.UserError, match="too big"):
        await engine.attach("big.txt", b"x" * 11)
    with pytest.raises(engine_mod.UserError, match="no longer there"):
        await engine.send_with_files("hi", ["0123456789abcdef"])
    assert not engine._attached and not list(engine.conv.dir.glob("attachments/*"))


async def test_a_build_left_running_after_its_turn_is_still_shown_until_it_finishes(builder_env, monkeypatch):
    from davibemanager import engine as engine_mod
    from fakesandbox import FakeSandbox
    monkeypatch.setattr(engine_mod, "ACTIVITY_EVERY", 0.02)
    engine, _, events, clients = builder_env
    sb = FakeSandbox()
    sb.install(monkeypatch, engine)
    sb.activity = [f"@@CPU {n * 1000000}\n@@MEM 1048576\n@@PS\n 99.0 cc1\n@@TAIL t9 1\n[ 40%] gthumb\n" for n in range(1, 400)]

    async def script(c, text):
        await c.queue.put(AssistantMessage([ToolUseBlock("u9", "Bash", {"command": "ninja -C build"})], "m"))
        await c.queue.put(SystemMessage("task_started", {"subtype": "task_started", "task_id": "t9", "tool_use_id": "u9",
                                                         "description": "ninja -C build"}))
        await c.queue.put(UserMessage([ToolResultBlock("u9", "Command did not complete within its 60s timeout and was "
                                                       "moved to the background (ID: t9).", False)]))
        await c.queue.put(AssistantMessage([TextBlock("It's building; ask me anything meanwhile.")], "m"))
        await c.queue.put(result())
    engine._script = script
    engine.send("Build it")
    await wait_for(lambda: engine.conv.chat[-1]["kind"] == "assistant" and not engine.busy, "turn end")
    await wait_for(lambda: engine.activity and engine.activity["tasks"], "the build, after the turn")
    assert engine.activity["tasks"][0]["last"] == ["[ 40%] gthumb"]
    await clients[0].queue.put(SystemMessage("task_notification", {"subtype": "task_notification", "task_id": "t9",
                                                                   "status": "completed"}))
    await wait_for(lambda: engine.activity is None, "shown no more once it's done")
