"""The assistant's tools on the host: the only things it can ask of the app.

They run in this process (an in-process MCP server, carried over the CLI's stdio), and each is
a thin call into the engine through BuilderHost. Only request_host_command concerns this
computer, and it doesn't run anything: it shows the command to the user and waits for what
they decide, and for the output they choose to send.
"""

from __future__ import annotations

import re
from typing import Any, Awaitable, Protocol

from ..llm.prompts import BUILDER_TOOL_DOCS, QUESTIONS_SCHEMA

# apt package names (Debian policy), optionally with an architecture or version: nothing that
# could be read as an apt option or a path
PACKAGE_RE = re.compile(r"^[a-z0-9][a-z0-9+.-]*(:[a-z0-9-]+)?(=[A-Za-z0-9.+:~-]+)?$")
MAX_PACKAGES = 60


class Unanswered(Exception):
    """ask_user without a reply in the chat first; carries what the user last typed, if anything."""

    def __init__(self, typed: str = ""):
        super().__init__(typed)
        self.typed = typed


class BuilderHost(Protocol):
    def builder_ask(self, questions: list) -> Awaitable[str]: ...
    def builder_offer(self, args: dict) -> Awaitable[str]: ...
    def builder_host_command(self, args: dict) -> Awaitable[str]: ...
    def builder_install(self, packages: list[str]) -> Awaitable[str]: ...
    def builder_screenshot(self, args: dict) -> Awaitable[str]: ...
    def builder_deliver(self, args: dict) -> Awaitable[str]: ...
    def builder_suggest_app(self, args: dict) -> Awaitable[str]: ...
    def builder_findings(self, args: dict) -> Awaitable[str]: ...
    def builder_change_notes(self, args: dict) -> Awaitable[str]: ...
    def builder_search(self, args: dict) -> Awaitable[str]: ...
    def builder_fetch_check(self, url: str) -> str: ...


def check_packages(packages: Any) -> list[str]:
    if not isinstance(packages, list) or not packages:
        raise ValueError("packages must be a non-empty list of package names")
    if len(packages) > MAX_PACKAGES:
        raise ValueError(f"at most {MAX_PACKAGES} packages at a time")
    out = []
    for p in packages:
        p = str(p).strip()
        if not PACKAGE_RE.fullmatch(p):
            raise ValueError(f"{p[:60]!r} isn't an apt package name")
        out.append(p)
    return out


SCHEMAS: dict[str, dict] = {
    "ask_user": {"type": "object", "properties": {"questions": QUESTIONS_SCHEMA}, "required": ["questions"]},
    "offer_build": {
        "type": "object",
        "properties": {
            "app": {"type": "string", "description": "The app as the user knows it, e.g. 'gThumb'."},
            "change": {"type": "string", "description": "What it would do, in a few plain words, e.g. 'Drag a box to zoom'."},
            "upstream": {"type": "string", "description": (
                "For an app the user doesn't have from you yet: the original project's official repository, its https:// "
                "git address (e.g. https://gitlab.gnome.org/GNOME/gthumb.git), never a fork's. The user sees it on the card, "
                "and the delivery must come from it.")},
            "size": {"type": "string", "enum": ["simple", "significant", "major"], "description": (
                "Only once you have looked at the app's code: simple (a few lines in one or two places), "
                "significant (several files, or a new part of the app), major (deep changes to how the app works).")},
            "size_reason": {"type": "string", "description": "With size: what you found in the code, in a sentence or two for the user."},
        },
        "required": ["app", "change"],
    },
    "request_host_command": {
        "type": "object",
        "properties": {
            "command": {"type": "string", "description": "Exact bash command for the user's computer. No sudo: set as_root."},
            "purpose": {"type": "string", "description": "One plain sentence for the user, no jargon: what this finds out or changes, and why you need it."},
            "risk": {"type": "string", "enum": ["read_only", "modifying", "disruptive"]},
            "rollback": {"type": "string", "description": "Required unless read_only: the exact command that undoes it."},
            "as_root": {"type": "boolean", "description": "Run as administrator (the desktop asks the user for their password)."},
            "timeout": {"type": "integer", "description": "Seconds before it is stopped (default 120, at most 1800)."},
        },
        "required": ["command", "purpose", "risk"],
    },
    "install_packages": {
        "type": "object",
        "properties": {"packages": {"type": "array", "items": {"type": "string"}, "minItems": 1}},
        "required": ["packages"],
    },
    "show_screenshot": {
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "A PNG or JPEG under /work, e.g. taken of the app running under xvfb-run."},
            "caption": {"type": "string", "description": "One sentence for the user."},
        },
        "required": ["path"],
    },
    "web_search": {
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "What to look for, in plain words. Only from your sandbox and the user's own words: never anything from their computer (it is refused)."},
            "purpose": {"type": "string", "enum": ["answer", "links"],
                        "description": "answer: gather information, with substantial extracts and sources (how-tos, whether a fork or plug-in already does it). links: find the official site or repository quickly and accurately."},
            "sites": {"type": "array", "items": {"type": "string"}, "description": "Optional: search only these domains, e.g. github.com."},
            "after": {"type": "string", "description": "Optional: only pages from this date on, YYYY-MM-DD."},
        },
        "required": ["query"],
    },
    "suggest_app_chat": {
        "type": "object",
        "properties": {
            "app": {"type": "string", "description": "The app as the user knows it, e.g. 'gThumb'."},
            "wish": {"type": "string", "description": "What they want it to do, in their words, e.g. 'Zoom by dragging a box, like ACDSee'."},
        },
        "required": ["app", "wish"],
    },
    "update_change_notes": {
        "type": "object",
        "properties": {
            "changes": {"type": "object", "description": (
                "Change id (app.json) -> {\"notes\": the change's notes as they should be, \"title\": its title, "
                "if it should change}."),
                "additionalProperties": {"type": "object", "properties": {"notes": {"type": "string"},
                                                                          "title": {"type": "string"}},
                                         "required": ["notes"]}},
        },
        "required": ["changes"],
    },
    "send_findings": {
        "type": "object",
        "properties": {
            "app": {"type": "string", "description": "The app's id (as the note at the start says), or its name for one DA Vibe Manager didn't build."},
            "findings": {"type": "string", "description": (
                "For the chat that fixes the app's build, in plain words the user can read: what goes wrong on this computer "
                "and how it shows, what you found (the key lines of output, the missing library, the versions), what you "
                "think the cause is, and how the build could be fixed so it works here and still works where it did.")},
        },
        "required": ["app", "findings"],
    },
    "deliver": {
        "type": "object",
        "properties": {
            "kind": {"type": "string", "enum": ["appimage", "source", "addon"]},
            "path": {"type": "string", "description": "The AppImage file, the source directory, or the add-on (a file, or a folder of them), under /work."},
            "name": {"type": "string", "description": "The app's name as the user knows it, e.g. 'gThumb'."},
            "version": {"type": "string", "description": "Upstream version plus your change, e.g. '3.12.6-dvm1'."},
            "repo": {"type": "string", "description": "The git repository (under /work) holding your commits: for an app the user has, the tree the app prepared (/work/apps/<app id>). Its origin is the official repository."},
            "base_ref": {"type": "string", "description": "The official release (tag) your branch starts from. Empty for something new of your own (the patch then holds all of it)."},
            "summary": {"type": "string", "description": "Two or three plain sentences for the user: what's new."},
            "feature": {"type": "string", "description": (
                "FEATURE.md, the new change's notes (shared with the app): what it does and why in your own words, "
                "how it is done, how to build it, and how to re-apply it to a new version.")},
            "change_notes": {"type": "object", "description": (
                "For each change the user already has whose code this delivery changes: its id (app.json) -> "
                "{\"notes\": its notes as they are now, \"title\": its new title, if that changed}. Required for "
                "every such change: notes must describe the code as it is."),
                "additionalProperties": {"type": "object", "properties": {"notes": {"type": "string"},
                                                                          "title": {"type": "string"}},
                                         "required": ["notes"]}},
            "run_instructions": {"type": "string", "description": "How the user runs it (and for source: builds it) on their computer."},
            "integration": {"type": "string", "enum": ["app", "desktop", "system"], "description": (
                "How deep it goes: app (an ordinary app the user opens), desktop (part of the desktop: file manager, panel, "
                "window manager, settings...), system (below the desktop). The user is warned for desktop and system.")},
            "tested": {"type": "string", "description": "What you tested here, in the sandbox, specifically."},
            "not_tested": {"type": "string", "description": (
                "What you could not test here, specifically: e.g. the user's desktop and theme, their other apps and "
                "extras, being their default app, real use over time.")},
            "try_steps": {"type": "array", "items": {"type": "string"}, "maxItems": 8, "description": (
                "A short checklist for the user's first try on their computer, one check each, in plain words.")},
            "screenshots": {"type": "array", "items": {"type": "string"}, "description": "Up to 4 PNG/JPEG paths under /work showing it working."},
            "install_to": {"type": "string", "description": "addon only: the folder on the user's computer the app loads it from, as ~/…, e.g. ~/.config/mpv/scripts."},
            "build_script": {"type": "string", "description": "appimage: the PATH of a script file under /work (e.g. /work/apps/gthumb/build.sh; not the script's text) that builds and packages it from the top of a clean checkout of your branch, leaving exactly one .AppImage in $DVM_OUT (SOURCE_DATE_EPOCH is set). The app builds your commit with it once, in a clean container, delivers that build, and uses the script for future versions."},
            "build_packages": {"type": "array", "items": {"type": "string"}, "description": "Every Ubuntu package the build needs (as for install_packages): the app builds it in a clean container with only these installed."},
            "change_title": {"type": "string", "description": "The user's change in a few words, e.g. 'Drag a box to zoom'."},
            "app": {"type": "string", "description": "When this adds a change to an app the user already has: its id (a folder name in /work/.dvm/apps)."},
            "updates": {"type": "string", "description": "When this makes the user's app on a new upstream version (the same changes): the app's id."},
            "leaves_out": {"type": "array", "items": {"type": "string"}, "description": (
                "Only when the user chose to drop changes they already have in this app: those changes' ids (app.json). "
                "The user confirms on a card, and they come off the app's record. Never rebuild commits only to revert them.")},
        },
        "required": ["kind", "path", "name", "version", "repo", "summary", "feature", "integration", "tested",
                     "not_tested"],
    },
}


def _text(text: str, error: bool = False) -> dict:
    return {"content": [{"type": "text", "text": text}], **({"is_error": True} if error else {})}


def _unanswered_text(e: Unanswered) -> str:
    if e.typed:
        why = f'The user last wrote to you: "{e.typed}". Answer that first, in the text of your reply'
    else:
        why = "You haven't written anything to the user in this turn. Write your reply first, as text"
    return (f"Not asked yet. {why}: ordinary text, not your thinking (the user never sees your thinking). "
            "Then call the tool again, after that text in the same reply.")


# the tools of each kind of chat: only an app chat builds; a computer chat can point to one
COMMON = ("ask_user", "request_host_command", "install_packages", "show_screenshot", "web_search")
MODE_TOOLS = {"computer": (*COMMON, "suggest_app_chat", "send_findings"),
              "app": (*COMMON, "offer_build", "deliver", "update_change_notes")}


def tool_names(mode: str) -> list[str]:
    return [f"mcp__host__{n}" for n in MODE_TOOLS["app" if mode == "app" else "computer"]]


def make_server(host: BuilderHost, mode: str = "app"):
    """The in-process MCP server "host" with the tools of this kind of chat ("computer" or "app")."""
    from claude_agent_sdk import create_sdk_mcp_server, tool

    @tool("ask_user", BUILDER_TOOL_DOCS["ask_user"], SCHEMAS["ask_user"])
    async def ask_user(args: dict) -> dict:
        try:
            return _text(await host.builder_ask(args.get("questions")))
        except Unanswered as e:
            return _text(_unanswered_text(e), True)
        except (TypeError, ValueError) as e:
            return _text(f"Invalid questions ({e}). Ask in your message instead.", True)

    @tool("offer_build", BUILDER_TOOL_DOCS["offer_build"], SCHEMAS["offer_build"])
    async def offer_build(args: dict) -> dict:
        try:
            return _text(await host.builder_offer(args))
        except Unanswered as e:
            return _text(_unanswered_text(e), True)
        except (TypeError, ValueError) as e:
            return _text(f"Not offered ({e}).", True)

    @tool("request_host_command", BUILDER_TOOL_DOCS["request_host_command"], SCHEMAS["request_host_command"])
    async def request_host_command(args: dict) -> dict:
        try:
            return _text(await host.builder_host_command(args))
        except (TypeError, ValueError) as e:
            return _text(f"Not shown to the user: {e}", True)

    @tool("install_packages", BUILDER_TOOL_DOCS["install_packages"], SCHEMAS["install_packages"])
    async def install_packages(args: dict) -> dict:
        try:
            packages = check_packages(args.get("packages"))
        except ValueError as e:
            return _text(f"Nothing installed: {e}", True)
        try:
            return _text(await host.builder_install(packages))
        except Exception as e:  # noqa: BLE001 - the assistant should see why
            return _text(f"Installing failed: {e}", True)

    @tool("show_screenshot", BUILDER_TOOL_DOCS["show_screenshot"], SCHEMAS["show_screenshot"])
    async def show_screenshot(args: dict) -> dict:
        try:
            return _text(await host.builder_screenshot(args))
        except Exception as e:  # noqa: BLE001
            return _text(f"Not shown: {e}", True)

    @tool("web_search", BUILDER_TOOL_DOCS["web_search"], SCHEMAS["web_search"])
    async def web_search(args: dict) -> dict:
        try:
            text = await host.builder_search(args)
        except Exception as e:  # noqa: BLE001 - the assistant should see why
            return _text(f"Not searched: {e}", True)
        return _text(text, text.startswith("Not searched"))

    @tool("deliver", BUILDER_TOOL_DOCS["deliver"], SCHEMAS["deliver"])
    async def deliver(args: dict) -> dict:
        try:
            return _text(await host.builder_deliver(args))
        except Exception as e:  # noqa: BLE001 - the assistant should see why, and can fix and try again
            return _text(f"Not delivered: {e}", True)

    @tool("suggest_app_chat", BUILDER_TOOL_DOCS["suggest_app_chat"], SCHEMAS["suggest_app_chat"])
    async def suggest_app_chat(args: dict) -> dict:
        try:
            return _text(await host.builder_suggest_app(args))
        except Unanswered as e:
            return _text(_unanswered_text(e), True)
        except (TypeError, ValueError) as e:
            return _text(f"Not shown: {e}", True)

    @tool("send_findings", BUILDER_TOOL_DOCS["send_findings"], SCHEMAS["send_findings"])
    async def send_findings(args: dict) -> dict:
        try:
            return _text(await host.builder_findings(args))
        except Unanswered as e:
            return _text(_unanswered_text(e), True)
        except (TypeError, ValueError) as e:
            return _text(f"Not shown: {e}", True)

    @tool("update_change_notes", BUILDER_TOOL_DOCS["update_change_notes"], SCHEMAS["update_change_notes"])
    async def update_change_notes(args: dict) -> dict:
        try:
            return _text(await host.builder_change_notes(args))
        except Exception as e:  # noqa: BLE001 - the assistant should see why
            return _text(f"Not updated: {e}", True)

    every = [ask_user, offer_build, request_host_command, install_packages, show_screenshot, web_search, deliver,
             suggest_app_chat, send_findings, update_change_notes]
    names = MODE_TOOLS["app" if mode == "app" else "computer"]
    return create_sdk_mcp_server("host", "1.0.0", [t for t in every if t.name in names])

