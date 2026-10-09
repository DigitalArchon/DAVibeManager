"""A conversation with the assistant: its chat, its audit log, and the Claude Code session that
carries it in the sandbox, so it resumes after a restart."""

from __future__ import annotations

import json
import re
import shutil
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from .config import data_dir


def root_dir(root: Path | None = None) -> Path:
    return root or data_dir() / "conversations"


@dataclass
class Conversation:
    id: str
    dir: Path
    title: str = ""
    started: str = ""
    session: str = ""          # Claude Code session id in the sandbox
    chat: list[dict] = field(default_factory=list)
    requests: list[dict] = field(default_factory=list)    # HostRequest.to_dict() of every request made here
    questions: list[dict] = field(default_factory=list)   # questions the assistant asked, with the answers
    tokens: dict[str, dict] = field(default_factory=dict)  # model -> tokens it used here, by kind (the gateway's count)
    # the kind of chat, chosen when it starts and never changed: "computer" (getting an app working on
    # this computer, or the computer itself) or "app" (fixing or adding a feature to one app); "" until
    # the user chooses
    mode: str = ""
    app: str = ""              # the chat's app (its id): an app chat's, once it has one, or the app a computer chat is about
    app_name: str = ""         # an app chat's app as the user named it (a new one, not built yet)
    remake: bool = False       # an app chat that makes its app again, cleanly, from the official source

    @classmethod
    def create(cls, root: Path | None = None) -> "Conversation":
        now = datetime.now()
        base = root_dir(root)
        cid = f"{now:%Y%m%d-%H%M%S}"
        n = 1
        while (base / cid).exists():
            n += 1
            cid = f"{now:%Y%m%d-%H%M%S}-{n}"
        d = base / cid
        d.mkdir(parents=True, mode=0o700)
        c = cls(id=cid, dir=d, started=now.isoformat(timespec="seconds"))
        c.save()
        return c

    @classmethod
    def load(cls, cid: str, root: Path | None = None) -> "Conversation":
        if not re.fullmatch(r"[\w-]+", cid or ""):
            raise FileNotFoundError(f"No conversation {cid}")
        d = root_dir(root) / cid
        try:
            data = json.loads((d / "state.json").read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            raise FileNotFoundError(f"No conversation {cid}") from e
        return cls(id=cid, dir=d, title=data.get("title", ""), started=data.get("started", ""),
                   session=data.get("session", ""), chat=list(data.get("chat", [])),
                   requests=list(data.get("requests", [])), questions=list(data.get("questions", [])),
                   tokens=dict(data.get("tokens") or {}), mode=data.get("mode") or _old_mode(data),
                   app=data.get("app", ""), app_name=data.get("app_name", ""), remake=bool(data.get("remake")))

    @staticmethod
    def list_all(root: Path | None = None) -> list[dict]:
        base = root_dir(root)
        out = []
        if base.is_dir():
            for d in base.iterdir():
                try:
                    data = json.loads((d / "state.json").read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    continue
                out.append({"id": d.name, "title": data.get("title") or "New chat", "started": data.get("started", ""),
                            "messages": sum(1 for e in data.get("chat", []) if e.get("kind") in ("user", "assistant")),
                            "mode": data.get("mode") or _old_mode(data), "app": data.get("app", ""),
                            "app_name": data.get("app_name", ""), "remake": bool(data.get("remake"))})
        out.sort(key=lambda c: c["id"], reverse=True)
        return out

    @staticmethod
    def delete(cid: str, root: Path | None = None) -> None:
        base = root_dir(root).resolve()
        if not re.fullmatch(r"[\w-]+", cid or ""):
            raise ValueError(f"Bad conversation id {cid!r}")
        d = base / cid
        if d.is_symlink() or not (d / "state.json").is_file() or d.resolve().parent != base:
            raise FileNotFoundError(f"No conversation {cid}")
        shutil.rmtree(d)

    def save(self) -> None:
        tmp = self.dir / "state.json.tmp"
        tmp.write_text(json.dumps({"version": 1, "title": self.title, "started": self.started, "session": self.session,
                                   "chat": self.chat, "requests": self.requests, "questions": self.questions,
                                   "tokens": self.tokens, "mode": self.mode, "app": self.app, "app_name": self.app_name,
                                   "remake": self.remake},
                                  ensure_ascii=False, default=str), encoding="utf-8")
        tmp.replace(self.dir / "state.json")

    def log(self, event: str, **data) -> None:
        with (self.dir / "events.jsonl").open("a", encoding="utf-8") as f:
            f.write(json.dumps({"ts": time.time(), "event": event, **data}, ensure_ascii=False, default=str) + "\n")

    def to_dict(self) -> dict:
        return {"id": self.id, "title": self.title or "New chat", "started": self.started, "dir": str(self.dir),
                "mode": self.mode, "app": self.app, "app_name": self.app_name, "remake": self.remake}


def _old_mode(data: dict) -> str:
    """The kind of a chat from before there were two: an app chat if something was delivered in it."""
    chat = data.get("chat") or []
    if any(p.get("t") == "delivery" for e in chat for p in e.get("parts") or []):
        return "app"
    return "computer" if chat else ""


def fence(text: str, lang: str = "") -> str:
    """Code fence longer than any backtick run inside the text."""
    longest = max((len(m) for m in re.findall(r"`+", text)), default=0)
    ticks = "`" * max(3, longest + 1)
    return f"{ticks}{lang}\n{text}\n{ticks}"
