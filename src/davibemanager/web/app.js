"use strict";
/* DA Vibe Manager's window. The assistant works in its sandbox; nothing it asks for runs on this
   computer until the user clicks Run on its card, and its output goes back only when they send it
   (or, if they chose so in Settings, automatically and redacted). */

// ------------------------------------------------------------------ token & helpers

const DESKTOP = (() => {
  const fromUrl = new URLSearchParams(location.search).get("desktop") === "1";
  try {
    if (fromUrl) sessionStorage.setItem("dvm-desktop", "1");
    return fromUrl || sessionStorage.getItem("dvm-desktop") === "1";
  } catch { return fromUrl; }
})();

const TOKEN = (() => {
  const fromUrl = new URLSearchParams(location.search).get("t");
  try {
    if (fromUrl) sessionStorage.setItem("dvm-token", fromUrl);
    const t = fromUrl || sessionStorage.getItem("dvm-token");
    history.replaceState(null, "", "/");
    return t;
  } catch { return fromUrl; }
})();

// the colours: remembered from last time so the window opens in them, then taken from Settings
function applyTheme(theme) {
  document.documentElement.dataset.theme = theme || "dark";
  try { localStorage.setItem("dvm-theme", theme || "dark"); } catch { /* not kept */ }
}
try { applyTheme(localStorage.getItem("dvm-theme") || "dark"); } catch { applyTheme("dark"); }

const S = { state: null, live: null, liveText: "", thinking: false, panel: null, imgs: new Map(), editing: null, files: [] };
const $ = (sel, root = document) => root.querySelector(sel);

function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k === "html") el.innerHTML = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "value") el.value = v;
    else if (v === true) el.setAttribute(k, "");
    else el.setAttribute(k, v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

async function api(method, path, body) {
  const res = await fetch(path, {
    method, headers: { "X-Token": TOKEN, "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let data = {};
  try { data = await res.json(); } catch { /* empty */ }
  if (!res.ok) throw new Error(data.error || data.detail || `${res.status} ${res.statusText}`);
  return data;
}

function toast(text, kind = "info", ms = 6000) {
  const el = h("div", { class: `toast ${kind}` }, text);
  $("#toasts").append(el);
  setTimeout(() => el.remove(), ms);
}

// the app window's clipboard goes through GTK (WebKitGTK's own is unreliable there)
async function clipWrite(text) {
  try {
    if (DESKTOP) return await api("POST", "/api/desktop/clipboard", { text });
    await navigator.clipboard.writeText(text);
  } catch {
    const ta = h("textarea", { value: text });
    document.body.append(ta); ta.select(); document.execCommand("copy"); ta.remove();
  }
}

async function guarded(fn) {
  try { return await fn(); } catch (e) { toast(e.message, "error"); }
}

// AI output is untrusted (it can be steered by what it reads), so it may not load anything:
// no images or embeds in its markdown, and links open outside.
const MD_OPTS = {
  FORBID_TAGS: ["img", "picture", "source", "svg", "math", "video", "audio", "iframe", "object", "embed", "form", "input", "button", "style", "link", "meta", "base"],
  FORBID_ATTR: ["style", "srcset", "poster", "background", "ping", "formaction"],
  ALLOWED_URI_REGEXP: /^(?:https?|mailto):/i,
};
DOMPurify.addHook("afterSanitizeAttributes", (node) => {
  if (node.tagName === "A") { node.setAttribute("target", "_blank"); node.setAttribute("rel", "noopener noreferrer"); }
});
const md = (text) => DOMPurify.sanitize(marked.parse(text || "", { breaks: true }), MD_OPTS);

function fmtBytes(n) {
  if (!n) return "0 B";
  const u = ["B", "KB", "MB", "GB"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(i ? 1 : 0)} ${u[i]}`;
}
const fmtDay = (ts) => new Date(ts * 1000).toLocaleDateString([], { day: "numeric", month: "short" });
const fmtTime = (ts) => new Date(ts * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });

// Images are fetched with the token and shown from blob URLs (the page loads nothing else).
function authImg(url, cls = "") {
  const img = h("img", { class: cls, alt: "" });
  if (S.imgs.has(url)) img.src = S.imgs.get(url);
  else fetch(url, { headers: { "X-Token": TOKEN } }).then((r) => (r.ok ? r.blob() : null)).then((b) => {
    if (!b) return;
    const src = URL.createObjectURL(b);
    S.imgs.set(url, src);
    img.src = src;
  }).catch(() => {});
  img.addEventListener("click", () => modal({ title: "", body: h("img", { class: "full", src: img.src }), buttons: [{ label: "Close" }] }));
  return img;
}

function modal({ title, body, buttons = [], onClose }) {
  const box = h("div", { class: "modal" });
  const overlay = h("div", { class: "overlay" }, box);
  const close = () => { overlay.remove(); onClose?.(); };
  if (title) box.append(h("h2", {}, title));
  box.append(h("div", { class: "content" }, body));
  const bar = h("div", { class: "buttons" });
  for (const b of buttons) {
    const btn = h("button", { class: b.kind || "", type: "button" }, b.label);
    btn.addEventListener("click", async () => {
      btn.disabled = true;
      try { if ((await b.onClick?.()) !== true) close(); } catch (e) { toast(e.message, "error"); } finally { btn.disabled = false; }
    });
    bar.append(btn);
  }
  if (buttons.length) box.append(bar);
  overlay.addEventListener("mousedown", (e) => { if (e.target === overlay) close(); });
  overlay.addEventListener("keydown", (e) => { if (e.key === "Escape") close(); });
  $("#modal-root").append(overlay);
  return { close, box };
}

function confirmModal(title, message, okLabel = "OK", kind = "primary") {
  return new Promise((resolve) => {
    let ok = false;
    modal({ title, body: h("div", {}, message), buttons: [{ label: "Cancel" }, { label: okLabel, kind, onClick: () => { ok = true; } }],
      onClose: () => resolve(ok) });
  });
}

// ------------------------------------------------------------------ events

function connect() {
  const ws = new WebSocket(`ws://${location.host}/ws/events?t=${encodeURIComponent(TOKEN)}`);
  ws.onmessage = (m) => handle(JSON.parse(m.data));
  ws.onclose = () => setTimeout(connect, 1500);
}

function handle(ev) {
  const st = S.state;
  switch (ev.type) {
    case "state":
      if (st && st.conversation?.id !== ev.state.conversation?.id && S.files.length) { S.files = []; renderFiles(); }
      S.state = ev.state;
      S.live = ev.state.live;
      S.activity = ev.state.activity;
      render();
      break;
    case "chat":
      st.chat.push(ev.entry);
      renderChat(true);
      break;
    case "turn_start":
      st.busy = true; S.live = ev.entry; S.liveText = ""; S.thinking = true;
      renderChat(true); renderStatus();
      break;
    case "entry":
      S.live = ev.entry;
      if (!ev.interjected) { S.liveText = ""; S.thinking = false; S.thinkingFor = 0; }
      scheduleRender();
      break;
    case "thinking":
      S.thinkingFor = ev.seconds; S.thinkingWords = Math.round((ev.reasoning_chars || 0) / 6); S.thinking = true;
      scheduleRender();
      break;
    case "delta":
      if (ev.kind === "text") { S.liveText += ev.text; S.thinking = false; } else S.thinking = true;
      scheduleRender();
      break;
    case "activity": {
      // every few seconds while it works: updated in place, so the chat isn't redrawn under the user
      S.activity = ev.activity;
      const old = document.querySelector("#chat .activity");
      const now = S.activity ? activityEl(S.activity, S.live || {}) : null;
      if (old && now) old.replaceWith(now);
      else if (old || now) scheduleRender();
      renderStatus();
      break;
    }
    case "turn_end":
      st.busy = false; S.live = null; S.liveText = ""; st.chat = ev.chat;
      renderChat(true); renderStatus();
      break;
    case "request":
      st.requests[ev.request.id] = ev.request;
      scheduleRender(); renderStatus();
      break;
    case "question":
      st.questions[ev.question.id] = ev.question;
      scheduleRender(); renderStatus();
      break;
    case "workspace":
      st.workspace = ev.workspace;
      renderStatus();
      if (S.panel === "activity") openPanel("activity");
      break;
    case "backups":
      st.backups = ev.backups;
      if (S.panel === "settings" && !document.activeElement?.closest?.("#panel")) openPanel("settings");
      break;
    case "apps":
      st.apps = ev.apps;
      renderAppsCount();
      if (S.panel === "apps") openPanel("apps");
      break;
    case "deliveries":
      st.deliveries = ev.deliveries;
      scheduleRender();
      renderAppsCount();
      if (S.panel === "apps") openPanel("apps");
      break;
    case "network":
      st.network.push(ev.event);
      if (st.network.length > 300) st.network.shift();
      if (S.panel === "activity") openPanel("activity");
      break;
    case "spend":
      st.spend = ev.spend;
      renderStatus();
      break;
    case "toast":
      toast(ev.text, ev.level || "info", 9000);
      break;
  }
}

let pending = false;
function scheduleRender() {
  if (pending) return;
  pending = true;
  requestAnimationFrame(() => { pending = false; renderChat(false); });
}

// ------------------------------------------------------------------ top bar & status

function waitingOnUser() {
  const st = S.state;
  return Object.values(st.requests).some((r) => ["pending", "done"].includes(r.status))
    || Object.values(st.questions).some((q) => q.status === "pending");
}

function renderStatus() {
  const st = S.state;
  const el = $("#status"), text = $("#status-text");
  const w = st.workspace || {};
  let cls = "ok", msg = "Ready";
  if (!st.ready) { cls = "wait"; msg = st.keyring_wait ? "Waiting for your keyring" : "Needs setting up"; }
  else if (w.state === "needs_podman") { cls = "wait"; msg = "Install Podman first"; }
  else if (w.state === "failed") { cls = "bad"; msg = "The sandbox couldn't start"; }
  else if (waitingOnUser()) { cls = "wait"; msg = "Waiting for you"; }
  else if (st.busy) { cls = "busy"; msg = "Working…"; }
  else if (S.activity?.tasks?.length) { cls = "busy"; msg = "Ready to talk · still working in its sandbox"; }
  else if (w.state === "building") { cls = "busy"; msg = "Preparing its sandbox (first time: a few minutes)…"; }
  else if (w.state === "starting") { cls = "busy"; msg = "Starting its sandbox…"; }
  else if (w.state !== "running") { cls = ""; msg = "Sandbox stopped"; }
  el.className = `status ${cls}`;
  const [cost, costWhy] = spendText(st.spend);
  text.textContent = msg + cost;
  el.title = [w.state === "failed" ? w.error : w.step || "", costWhy].filter(Boolean).join("\n\n");
  $("#stop-btn").classList.toggle("hidden", !st.busy);
  $("#send-btn").classList.toggle("hidden", st.busy && !$("#input").value.trim() && !S.files.length);
  $("#input").placeholder = !st.ready ? "Set up first…"
    : waitingOnUser() ? "Reply, or decide on the card above…"
    : st.busy ? "Write any time: it reads it with its next step…"
    : w.state === "needs_podman" ? "Install Podman first (above)…"
    : ["building", "starting"].includes(w.state) ? "Type away: it's sent as soon as the sandbox is ready…"
    : "Ask anything about your computer…";
}

// this chat's cost: the tokens the app counted, at the provider's listed prices (Engine.spend)
function spendText(sp) {
  if (!sp || !sp.tokens) return ["", ""];
  const usd = (n) => (n < 0.01 ? "under $0.01" : `about $${n.toFixed(2)}`);
  const why = [`This chat so far: ${sp.tokens.toLocaleString()} tokens. The cost is an estimate, at the provider's listed prices.`];
  if (sp.included >= 0.005) why.push(`Models a NanoGPT subscription includes count as $0 here; without a subscription they'd cost ${usd(sp.included)}.`);
  if (sp.unpriced.length) why.push(`No prices are known for ${sp.unpriced.join(", ")}, so they aren't counted.`);
  return [sp.paid >= 0.01 ? ` · this chat ${usd(sp.paid)}` : "", why.join("\n")];
}

function renderAppsCount() {
  const list = S.state.apps || [];
  const news = list.filter((a) => a.latest?.status === "new" || (a.update?.status === "available" && a.watch !== false && a.skip !== a.update.latest)).length;
  $("#apps-count").textContent = list.length ? (news ? `${news} new` : String(list.length)) : "";
}

function render() {
  const st = S.state;
  applyTheme(st.config.settings.theme);
  $("#banner").textContent = st.keyring_error ? `⚠ ${st.keyring_error}` : st.ui_notice || "";
  $("#banner").classList.toggle("hidden", !st.keyring_error && !st.ui_notice);
  renderStatus();
  renderAppsCount();
  renderMode();
  renderChat(true);
  if (S.panel) openPanel(S.panel);
}

// ------------------------------------------------------------------ chat

const nearBottom = (el) => el.scrollHeight - el.scrollTop - el.clientHeight < 120;

// a re-render would drop what the user has selected to copy: it waits until the selection goes
const selectingInChat = () => {
  const sel = window.getSelection();
  return sel && !sel.isCollapsed && sel.rangeCount && $("#chat").contains(sel.getRangeAt(0).commonAncestorContainer);
};
document.addEventListener("selectionchange", () => {
  if (S.chatHeld && !selectingInChat()) { const scroll = S.chatHeld === "scroll"; S.chatHeld = null; renderChat(scroll); }
});

function renderChat(scroll) {
  const box = $("#chat");
  if (S.state.ready && selectingInChat()) { S.chatHeld = scroll || S.chatHeld === "scroll" ? "scroll" : "held"; return; }
  const stick = scroll || nearBottom(box);
  const st = S.state;
  // a re-render must not lose what the user is typing into a card
  const focus = document.activeElement;
  const keep = focus?.closest?.("#chat") && focus.dataset.key ? { key: focus.dataset.key, value: focus.value, pos: focus.selectionStart } : null;
  const typed = {};
  for (const el of box.querySelectorAll("[data-key]")) typed[el.dataset.key] = el.value;
  if (!st.ready) { box.replaceChildren(st.keyring_wait ? keyringScreen() : setupScreen()); $("#composer").classList.add("hidden"); return; }
  $("#composer").classList.remove("hidden");
  const items = st.chat.map((e) => entryEl(e, false));
  if (S.live) items.push(entryEl(S.live, true));
  // its turn has ended, but what it started (a build) goes on: the user can talk with it meanwhile
  else if (S.activity) items.push(h("div", { class: "msg assistant" }, h("div", { class: "muted small" },
    "Still running in its sandbox. You can keep talking: it's told when this finishes."), activityEl(S.activity, {})));
  box.replaceChildren(...(st.podman ? [podmanBox(st.podman)] : []), ...(items.length ? items : [welcome()]));
  for (const el of box.querySelectorAll("[data-key]")) if (el.dataset.key in typed) el.value = typed[el.dataset.key];
  if (keep) {
    const el = box.querySelector(`[data-key="${keep.key}"]`);
    if (el) { el.value = keep.value; el.focus(); try { el.selectionStart = el.selectionEnd = keep.pos; } catch { /* not text */ } }
  }
  if (stick) box.scrollTop = box.scrollHeight;
}

// ------------------------------------------------------------------ the two kinds of chat, never mixed

const shortSource = (url) => (url || "").replace(/^https:\/\//, "").replace(/\.git$/, "");
// where an app's code comes from, as people know it: "GitHub", "GitLab"… and the project's path
function forgeOf(url) {
  let host = "";
  try { host = new URL(url).hostname.toLowerCase(); } catch { return ""; }
  if (host === "github.com") return "GitHub";
  if (host === "codeberg.org") return "Codeberg";
  if (host === "git.sr.ht") return "SourceHut";
  if (host === "bitbucket.org") return "Bitbucket";
  if (host.startsWith("gitlab.") || ["invent.kde.org", "salsa.debian.org", "gitlab.freedesktop.org", "gitlab.gnome.org"].includes(host)) return "GitLab";
  return host;
}
const sourceText = (url) => [forgeOf(url), shortSource(url)].filter(Boolean).join(" · ");
const chatApp = (c) => (S.state.apps || []).find((a) => a.id === c?.app) || null;
const chatAppName = (c) => chatApp(c)?.name || c?.app_name || "";

async function startChat(body, wish = "") {
  await api("POST", "/api/chats/new", body);
  closePanel();
  if (wish) { $("#input").value = wish; autosize(); }
  $("#input").focus();
}

// which app an app chat is about: one of theirs, or one they name
function pickApp() {
  const list = [...(S.state.apps || [])].reverse();
  const name = h("input", { type: "text", maxlength: "80", placeholder: "Its name, e.g. gThumb or mpv" });
  let m = null;
  const go = (body) => guarded(async () => { await startChat(body); m.close(); });
  const body = h("div", { class: "pick-app" },
    list.length ? h("div", { class: "small muted" }, "One of your apps:") : null,
    list.map((a) => h("button", { type: "button", class: "app-choice", onclick: () => go({ mode: "app", app: a.id }) },
      h("div", { class: "name" }, a.name),
      h("div", { class: "small muted" }, [a.installed?.version || a.base_ref, shortSource(a.upstream)].filter(Boolean).join(" · ")))),
    h("div", { class: "small muted" }, list.length ? "Or another app you use:" : "Which app do you use that you'd like changed?"),
    h("form", { class: "row", onsubmit: (e) => { e.preventDefault(); if (name.value.trim()) go({ mode: "app", app_name: name.value.trim() }); } },
      name, h("button", { type: "submit", class: "primary" }, "Start")));
  m = modal({ title: "Which app?", body, buttons: [{ label: "Cancel" }] });
  if (!list.length) setTimeout(() => name.focus(), 0);
}

function welcome() {
  const c = S.state.conversation || {};
  const ask = (t) => h("button", { type: "button", onclick: () => { $("#input").value = t; $("#input").focus(); autosize(); } }, t);
  const safe = h("div", { class: "small" }, "I can't see your files or change anything by myself. Whenever I need to look at something or change it, I'll ask you first. To show me a file or a picture, attach it with 📎.");
  if (c.mode === "computer" && c.app) {
    const name = chatAppName(c);
    return h("div", { class: "welcome" },
      h("div", {}, `What goes wrong with ${name} on this computer? Tell me what you see.`),
      h("div", { class: "small" }, `I'll look into it on your computer, asking you before every step, and then hand what I find to ${name}'s own chat, so its build gets fixed to work here too.`),
      h("div", { class: "tips" }, ask(`${name} doesn't start.`), ask(`${name} crashes when I `), ask(`${name} looks wrong: `)),
      safe);
  }
  if (c.mode === "computer") {
    return h("div", { class: "welcome" },
      h("div", {}, "Tell me what's wrong: an app that doesn't start or misbehaves, or anything else on your computer."),
      h("div", { class: "tips" },
        ask("An app doesn't start: "),
        ask("My Wi-Fi keeps dropping. Can you find out why?"),
        ask("How do I make the text on my screen bigger?")),
      safe);
  }
  if (c.mode === "app") {
    const a = chatApp(c), name = chatAppName(c);
    if (c.remake) {
      return h("div", { class: "welcome" },
        h("div", {}, `I'll make ${name} again from its official source, with each of your changes made afresh on it.`),
        h("div", { class: "small" }, "Tell me anything that helps: where a change of yours came from (a fork of your own, a commit), anything to add or leave out, or just say “go ahead”."),
        h("div", { class: "tips" }, ask("Go ahead, with all my changes."), ask("My fix is in my fork: …")), safe);
    }
    return h("div", { class: "welcome" },
      h("div", {}, `What should ${name} do better? Tell me the feature you wish it had, or what's wrong with it.`),
      a ? h("div", { class: "small" }, a.changes?.length
        ? `Your ${a.name} has your change${a.changes.length > 1 ? "s" : ""}: ${a.changes.map((x) => x.title).join(" · ")}. A new one goes on top, and it's all kept up to date with ${a.name}'s official releases.`
        : `A change goes on your ${a.name}, and it's kept up to date with ${a.name}'s official releases.`)
        : h("div", { class: "small" }, `If ${name} is open source, I can build you a version with the change, and keep it up to date with its official releases.`),
      h("div", { class: "tips" },
        ask(`I wish ${name} could…`),
        ask(`Something in ${name} doesn't work: …`)),
      safe);
  }
  return h("div", { class: "welcome choose" },
    h("div", {}, "What would you like help with?"),
    h("button", { type: "button", class: "kind", onclick: pickTrouble },
      h("div", { class: "big" }, "🩺 Get an app working on this computer"),
      h("div", { class: "small muted" }, "An app I built doesn't start or misbehaves here? I'll find out why, asking before every step, and get its build fixed. Other problems with your computer too.")),
    h("button", { type: "button", class: "kind", onclick: pickApp },
      h("div", { class: "big" }, "📦 Help me fix or add a feature to an app"),
      h("div", { class: "small muted" }, "Name an app you use and say how it should be better. I build you a version that does it, and keep it up to date.")),
    safe);
}

// what kind of chat this is, under the app's name, and what the box to write in asks for
function renderMode() {
  const c = S.state.conversation || {};
  const el = $("#mode");
  const text = c.mode === "computer" ? (c.app ? `🩺 Getting ${chatAppName(c)} working here` : "🩺 Your computer") : c.mode === "app" ? (c.remake ? `📦 ${chatAppName(c)}, made again cleanly` : `📦 Improving ${chatAppName(c)}`) : "";
  el.textContent = text;
  el.classList.toggle("hidden", !text);
  $("#input").placeholder = c.mode === "app" && c.remake ? "Anything to tell me before I start? Or “go ahead”."
    : c.mode === "app" ? `What should ${chatAppName(c)} do better?`
    : c.mode === "computer" ? (c.app ? `What goes wrong with ${chatAppName(c)}?` : "What's wrong?") : "Pick one above, or just ask…";
}

// in a chat about the computer: what needs a change to an app is for an app chat, on the user's click
function suggestCard(p) {
  return h("div", { class: "card suggest" },
    h("div", {}, `💡 That needs a change to ${p.app} itself. An app chat can build you a version of ${p.app} with it, and keep it up to date.`),
    h("div", { class: "small muted" }, `“${p.wish}”`),
    h("div", { class: "actions" }, h("button", { class: "small primary", onclick: () => guarded(() =>
      startChat(p.app_id ? { mode: "app", app: p.app_id } : { mode: "app", app_name: p.app }, p.wish)) }, `Start an app chat about ${p.app}`)));
}

// what a chat about getting an app working here found: the user reads it (and can change it), and
// with a click starts the app's own chat with it, where its build is fixed
function findingsCard(p) {
  const text = h("textarea", { class: "cmd", rows: 6, "data-key": `findings-${p.app_id || p.app}` }, p.findings);
  text.value = p.findings;
  return h("div", { class: "card findings" },
    h("div", {}, h("b", {}, `🩺 What I found about ${p.app}`)),
    h("div", { class: "small muted" }, `For ${p.app}'s own chat, where its build is fixed so it works here and still works where it did. You can change it first; it's sent only when you send it there.`),
    text,
    h("div", { class: "actions" }, h("button", { class: "small primary", onclick: () => guarded(() => startChat(
      p.app_id ? { mode: "app", app: p.app_id } : { mode: "app", app_name: p.app },
      `I looked into why ${p.app} doesn't work properly on this computer. What we found:\n\n${text.value.trim()}\n\nPlease fix the build so it works here, and still works where it did.`)) },
      `Fix ${p.app}'s build with this`)));
}

// which app isn't working here: one of theirs, or something else on the computer
function pickTrouble() {
  const list = [...(S.state.apps || [])].reverse().sort((a, b) => !!b.installed - !!a.installed);
  let m = null;
  const go = (body) => guarded(async () => { await startChat(body); m.close(); });
  const body = h("div", { class: "pick-app" },
    list.length ? h("div", { class: "small muted" }, "Which of your apps?") : null,
    list.map((a) => h("button", { type: "button", class: "app-choice", onclick: () => go({ mode: "computer", app: a.id }) },
      h("div", {}, a.name), h("div", { class: "small muted" }, a.installed ? `${a.installed.version}, installed` : "not installed yet"))),
    h("button", { type: "button", class: "app-choice", onclick: () => go({ mode: "computer" }) },
      h("div", {}, "Something else on my computer"), h("div", { class: "small muted" }, "Another app, a setting, Wi-Fi, sound…")));
  m = modal({ title: "What isn't working?", body, buttons: [{ label: "Cancel" }] });
}

function entryEl(e, live) {
  if (e.kind === "note") return h("div", { class: "msg note" }, e.text,
    e.retry === "workspace" && S.state.workspace?.state === "failed"
      ? h("div", {}, h("button", { class: "small", onclick: () => guarded(() => api("POST", "/api/workspace/start")) }, "Try again")) : null);
  if (e.kind === "user") {
    const msg = h("div", { class: `msg user${e.queued ? " queued" : ""}`, title: e.queued ? "Sent when the assistant is ready" : "" },
      e.text || null, filesEl(e.files));
    if (!e.shared) return msg;
    return h("div", { class: "user-wrap" }, msg, h("details", { class: "shared small muted" },
      h("summary", {}, "Sent with it: about this computer (Settings)"), h("pre", {}, e.shared)));
  }
  // what the user wrote while it worked splits the entry where they wrote it
  const out = [];
  let box = h("div", { class: "msg assistant" });
  const parts = e.parts || [];
  const said = parts.filter((p) => p.t === "text").map((p) => p.text).join("\n\n");
  if (e.woken) box.append(h("div", { class: "muted small" }, "Something it left running has finished:"));
  parts.forEach((p, i) => {
    const last = i === parts.length - 1;
    if (p.t === "user") {
      if (box.childNodes.length) out.push(box);
      out.push(h("div", { class: "msg user" }, p.text || null, filesEl(p.files)));
      box = h("div", { class: "msg assistant" });
    }
    else if (p.t === "text") box.append(h("div", { class: "md", html: md(p.text) }));
    // the model's thinking, shown as it goes (faint): Claude Code asks Opus to write it as progress
    // updates for the reader, and folded away it hid what Opus had to say
    else if (p.t === "thinking") box.append(h("div", { class: "reasoning md", title: "Its thinking", html: md(p.text) }));
    else if (p.t === "steps") box.append(stepsEl(p.items, live && last));
    else if (p.t === "request") { const r = S.state.requests[p.id]; if (r) box.append(requestCard(r)); }
    else if (p.t === "question") { const q = S.state.questions[p.id]; if (q) box.append(questionCard(q)); }
    else if (p.t === "screenshot") box.append(h("div", { class: "shot" }, authImg(`/api/screens/${encodeURIComponent(p.file)}`), p.caption ? h("div", { class: "small muted" }, p.caption) : null));
    else if (p.t === "delivery") { const d = (S.state.deliveries || []).find((x) => x.id === p.id); if (d) box.append(deliveryCard(d)); }
    else if (p.t === "suggest") box.append(suggestCard(p));
    else if (p.t === "findings") box.append(findingsCard(p));
  });
  if (live && S.activity) box.append(activityEl(S.activity, e));
  if (live && e.retry) {
    const why = e.retry.reason || (e.retry.status ? `error ${e.retry.status}` : "no answer");
    box.append(h("div", { class: "warnbox" }, h("span", { class: "spinner" }),
      ` Having trouble reaching the AI (try ${e.retry.attempt} of ${e.retry.max}): ${why}`));
  }
  if (live) {
    if (S.liveText) box.append(h("div", { class: "md" }, h("span", { html: md(S.liveText) }), h("span", { class: "caret" })));
    else if (parts[parts.length - 1]?.t === "user" && runningStep(e)) {
      // what the user wrote waits for the step it's on, not for it to think
      box.append(h("div", { class: "muted small" }, "It reads your message when its current step is done (a long one goes on in the background after a minute)."));
    }
    else if (S.thinking || !parts.length || parts[parts.length - 1].t === "user") {
      const t = S.thinkingFor || 0;
      box.append(h("div", { class: "thinking" }, h("span", { class: "spinner" }), t >= 20
        ? `Thinking it through: ${Math.floor(t / 60) ? `${Math.floor(t / 60)} min ` : ""}${t % 60}s so far${S.thinkingWords ? `, about ${S.thinkingWords.toLocaleString()} words` : ""}…`
        : "Thinking…"));
    }
  }
  if (!live && said) {
    box.append(h("div", { class: "msg-actions" }, h("button", { type: "button", class: "small ghost", title: "Copy this reply",
      onclick: () => guarded(async () => { await clipWrite(said); toast("Copied.", "ok", 2000); }) }, "Copy")));
  }
  if (e.error && e.error !== "stopped") box.append(h("div", { class: "err" }, `Something went wrong: ${e.error}`));
  if (e.error === "stopped") box.append(h("div", { class: "muted small" }, "Stopped."));
  if (box.childNodes.length || !out.length) out.push(box);
  if (out.length === 1) return out[0];
  const frag = document.createDocumentFragment();
  frag.append(...out);
  return frag;
}

// ---- what the sandbox is doing, while it works

const fmtFor = (sec) => {
  sec = Math.max(0, Math.round(sec));
  if (sec < 60) return `${sec} s`;
  if (sec < 3600) return `${Math.floor(sec / 60)} min ${sec % 60 ? `${sec % 60} s` : ""}`.trim();
  return `${Math.floor(sec / 3600)} h ${Math.floor((sec % 3600) / 60)} min`;
};
// what a busy program is doing, in the user's words
const PROGRAM_KIND = [
  [/^(cc1|cc1plus|cc1obj|clang|clang\+\+|gcc|g\+\+|c\+\+|cc|as|rustc|javac|go|tsc|valac|moc|uic|rcc|glib-compile-.*)$/, "compiling"],
  [/^(ld|ld\..+|collect2|mold|lld)$/, "linking"],
  [/^(make|gmake|ninja|meson|cmake|cargo|scons|gradle|mvn|bazel|autoconf|configure)$/, "building"],
  [/^(git|git-remote-http.*|index-pack)$/, "getting code"],
  [/^(apt|apt-get|dpkg|http|https|gpgv)$/, "installing packages"],
  [/^(curl|wget)$/, "downloading"],
  [/^(pip|pip3|python3?|npm|node|yarn|pnpm)$/, "running tools"],
  [/^(Xvfb|xvfb-run|xdotool|import|dbus-daemon|dbus-run-sessi)$/, "trying the app on a virtual screen"],
  [/^(appimagetool|mksquashfs|linuxdeploy)$/, "packaging"],
];
const CHECK_LABEL = { start: "starting a clean container", packages: "installing the build's packages", build: "building it" };

const runningStep = (entry) => (entry.parts || []).some((p) => p.t === "steps" && p.items.some((i) => i.status === "running" && !i.background));

function activityEl(a, entry) {
  const now = Date.now() / 1000;
  const box = h("div", { class: "activity small" });
  const running = (entry.parts || []).filter((p) => p.t === "steps").flatMap((p) => p.items).filter((i) => i.status === "running");
  const cur = running[running.length - 1];
  if (a.check) {
    box.append(h("div", { class: "line" }, h("span", { class: "spinner" }),
      h("span", {}, `The app is building your new version in a clean container, to check it (${CHECK_LABEL[a.check.label] || a.check.label}) · ${fmtFor(now - a.check.since)}`)));
    if (a.check.last?.length) box.append(h("div", { class: "last" }, a.check.last[a.check.last.length - 1]));
  } else if (cur) {
    box.append(h("div", { class: "line" }, h("span", {}, "Now: "), h("span", { class: "what" }, `${TOOL_LABEL[cur.tool] || cur.tool} ${cur.summary}`),
      h("span", {}, ` · for ${fmtFor(now - cur.at)}`)));
  }
  for (const t of a.tasks || []) {
    const mine = cur && !t.background;           // the step above: only its output
    if (!mine) box.append(h("div", { class: "line" }, h("span", {}, t.background ? "In the background: " : "Running: "),
      h("span", { class: "what" }, t.description), h("span", {}, ` · ${fmtFor(now - t.since)}`)));
    if (t.last?.length) box.append(h("div", { class: "last", title: t.last.join("\n") }, t.last[t.last.length - 1]));
  }
  const kinds = new Map();
  for (const [name, n] of a.procs || []) {
    const kind = (PROGRAM_KIND.find(([re]) => re.test(name)) || [null, name])[1];
    kinds.set(kind, [...(kinds.get(kind) || []), n > 1 ? `${name} ×${n}` : name]);
  }
  const busy = [...kinds].map(([kind, names]) => names.length === 1 && names[0] === kind ? kind : `${kind} (${names.join(", ")})`);
  const idle = a.cpu !== null && a.cpu < 3;
  const share = a.cpu_share ?? a.cpu;
  const figures = [a.cpu === null ? "" : idle ? "processor idle" : `processor ${share}%`, a.mem ? `memory ${fmtBytes(a.mem)}` : ""].filter(Boolean);
  if (busy.length || figures.length) {
    box.append(h("div", { class: "line muted", title: "In its sandbox. Processor: 100% is all the processor power the sandbox may use (Settings)." },
      busy.length && !idle ? `Busy ${busy.join(", ")}` : "In the sandbox", figures.length ? ` · ${figures.join(" · ")}` : ""));
  }
  if (a.quiet >= 120 && (cur || a.check || (a.tasks || []).length)) {
    box.append(h("div", { class: "warnbox" }, `Nothing has happened in the sandbox for ${fmtFor(a.quiet)}. It may be waiting for a download, or stuck. If it stays like this, you can stop it and ask what happened.`));
  }
  return box;
}

const TOOL_LABEL = { Bash: "ran", Read: "read", Write: "wrote", Edit: "edited", MultiEdit: "edited", Glob: "looked for", Grep: "searched",
  WebFetch: "read the page", WebSearch: "searched the web for", Task: "worked on", Agent: "worked on", TodoWrite: "planned",
  "mcp__host__install_packages": "installed", "mcp__host__web_search": "searched the web for" };

function stepsEl(items, live) {
  const running = items.filter((i) => i.status === "running");
  const failed = items.filter((i) => i.status === "error").length;
  const cur = running[running.length - 1] || (live ? items[items.length - 1] : null);
  return h("details", { class: "steps" },
    h("summary", {}, live && running.length ? h("span", { class: "spinner" }) : "🛠",
      h("span", {}, `${live ? "Working in its sandbox" : "Worked in its sandbox"} · ${items.length} step${items.length > 1 ? "s" : ""}${failed ? ` (${failed} didn't work)` : ""}`),
      cur && live ? h("span", { class: "now" }, `— ${TOOL_LABEL[cur.tool] || cur.tool} ${cur.summary}`) : null),
    h("ol", {}, items.map((i) => h("li", { class: i.status },
      h("span", { class: "tool" }, TOOL_LABEL[i.tool] || i.tool), " ", h("span", { class: "what" }, i.summary || ""),
      i.output ? h("details", {}, h("summary", { class: "small" }, "output"), h("pre", {}, i.output)) : null))));
}

// ---- a request to run something on this computer

const RISK = {
  read_only: { icon: "🔍", head: "Wants to look at something on your computer", cls: "" },
  modifying: { icon: "✏️", head: "Wants to change something on your computer", cls: "risk-modifying" },
  disruptive: { icon: "⚠️", head: "Wants to do something risky on your computer", cls: "risk-disruptive" },
};
const REVIEW = { ok: "✓ Second opinion: looks fine", care: "⚠ Second opinion: be careful", stop: "✗ Second opinion: don't run this" };

function reviewEl(review) {
  if (!review?.status) return null;
  if (review.status === "checking") return h("div", { class: "review" }, h("span", { class: "spinner" }), " Getting a second opinion…");
  if (review.status === "error") return h("div", { class: "review" }, `Second opinion not available: ${review.error}`);
  return h("div", { class: `review ${review.level}`, title: "Click to read it all",
    onclick: () => modal({ title: "Second opinion", body: h("div", {}, h("div", { class: "small muted" }, `${review.model}${review.tier === "e2ee" ? " · private" : ""}`), h("pre", {}, review.text)), buttons: [{ label: "Close" }] }) },
    h("b", {}, REVIEW[review.level] || `Second opinion: ${review.verdict || "?"}`), review.summary ? ` — ${review.summary}` : "",
    review.data ? h("div", { class: "small" }, `🔍 ${review.data}`) : null);
}

function requestCard(r) {
  const k = RISK[r.risk] || RISK.modifying;
  const settled = ["sent", "withheld", "declined", "cancelled", "failed"].includes(r.status);
  const card = h("div", { class: `card req ${k.cls}${settled ? " settled" : ""}` });
  const act = (action, body) => guarded(() => api("POST", `/api/requests/${r.id}/${action}`, body));
  card.append(h("div", { class: "head" }, `${k.icon} ${k.head}`, h("span", { class: "spacer" }),
    r.as_root ? h("span", { class: "chip warn", title: "Your computer will ask for your password" }, "🔑 admin") : null,
    r.sensitive?.length ? h("span", { class: "chip danger", title: r.sensitive.join("\n") }, "private data?") : null));
  if (r.purpose) card.append(h("div", { class: "purpose" }, r.purpose));
  if (r.status === "pending" && S.editing === r.id) {
    const ta = h("textarea", { class: "cmd", rows: 2, "data-key": `edit-${r.id}`, value: r.command });
    card.append(ta, h("div", { class: "actions" },
      h("button", { class: "small primary", onclick: async () => { await act("edit", { command: ta.value }); S.editing = null; renderChat(false); } }, "Save"),
      h("button", { class: "small", onclick: () => { S.editing = null; renderChat(false); } }, "Cancel")));
  } else {
    card.append(h("div", { class: "cmd" }, r.command));
  }
  if (r.edited) card.append(h("div", { class: "small muted" }, "You changed this command."));
  if (r.hidden?.length) card.append(h("div", { class: "warnbox" }, `Hidden characters were removed from this command (${r.hidden.join("; ")}). Coming from an AI, that's suspicious: read it carefully.`));
  if (r.rollback && r.risk !== "read_only") card.append(h("div", { class: "small muted" }, "To undo it later: ", h("code", {}, r.rollback)));
  const rv = reviewEl(r.review);
  if (rv) card.append(rv);

  if (r.status === "pending") {
    const reason = h("input", { type: "text", autocomplete: "off", placeholder: "Why not? (optional) Press Enter", class: "hidden", "data-key": `why-${r.id}` });
    reason.addEventListener("keydown", (e) => { if (e.key === "Enter") act("decline", { note: reason.value }); });
    card.append(h("div", { class: "actions" },
      h("button", { class: `small ${r.risk === "disruptive" ? "danger" : "primary"}`, onclick: () => runRequest(r) }, "Run it"),
      r.review?.status ? null : h("button", { class: "small", onclick: () => act("review") }, "Second opinion"),
      h("button", { class: "small", onclick: () => { S.editing = r.id; renderChat(false); } }, "Edit"),
      h("button", { class: "small ghost", onclick: () => {
        if (reason.classList.contains("hidden")) { reason.classList.remove("hidden"); reason.focus(); return; }
        act("decline", { note: reason.value });
      } }, "Don't run")), reason);
  } else if (r.status === "running") {
    card.append(h("div", { class: "row" }, h("span", { class: "spinner" }), "Running…", h("span", { class: "spacer" }),
      h("button", { class: "small", onclick: () => act("stop") }, "Stop")));
  } else if (r.status === "done") {
    const info = [r.still_running ? `didn't end when it was stopped after ${Math.round(r.seconds)}s`
      : r.timed_out ? `was stopped after ${Math.round(r.seconds)}s` : `finished${r.exit_code ? ` with an error (code ${r.exit_code})` : ""}`];
    if (r.redactions) info.push(`${r.redactions} secret${r.redactions > 1 ? "s" : ""} blanked out`);
    if (r.truncated) info.push("shortened");
    const out = h("textarea", { class: "out", spellcheck: "false", "data-key": `out-${r.id}`, value: r.preview });
    card.append(h("div", { class: "small muted" }, `It ${info.join(" · ")}. This is what the assistant would get: read it, and remove anything you'd rather not share.`));
    if (r.still_running) card.append(h("div", { class: "warnbox" }, `It may still be running${r.as_root ? " as administrator" : ""}. `
      + (r.as_root ? "To end it, restart the computer, or find it in your system monitor." : "To end it, find it in your system monitor.")));
    if (r.warnings?.length) card.append(h("div", { class: "warnbox" }, `The output contains text that looks aimed at an AI (${r.warnings.join("; ")}). The assistant is told to ignore such text, but check it.`));
    if (r.sensitive?.length) card.append(h("div", { class: "warnbox" }, `This may include private data: ${r.sensitive.join("; ")}.`));
    card.append(out, h("div", { class: "actions" },
      h("button", { class: "small primary", onclick: () => act("send", { text: out.value }) }, "Send it"),
      h("button", { class: "small ghost", onclick: () => act("withhold", {}) }, "Keep it private")));
  } else {
    const label = { sent: "✓ Sent to the assistant", withheld: "Ran it, kept the output private", declined: "Not run",
      cancelled: "Cancelled", failed: "Couldn't run" }[r.status];
    card.append(h("div", { class: "small muted" }, label, r.note && r.status !== "sent" ? ` — ${r.note}` : ""));
    if (r.status === "sent") card.append(h("details", { class: "small" }, h("summary", {}, "What it got"), h("pre", { class: "outview" }, r.sent_text || "(no output)")));
    if (r.status === "failed") card.append(h("pre", { class: "outview" }, r.output));
  }
  return card;
}

async function runRequest(r) {
  if (r.risk === "disruptive" || r.review?.level === "stop") {
    const ok = await confirmModal("Are you sure?", h("div", {},
      h("p", {}, r.review?.level === "stop" ? "The second opinion says not to run this." : "This could interrupt what you're doing, lose data or lock you out."),
      h("pre", { class: "cmd" }, r.command),
      r.rollback ? h("p", { class: "small" }, "To undo it: ", h("code", {}, r.rollback)) : h("p", { class: "small" }, "No way to undo it was given.")),
      "Run it anyway", "danger");
    if (!ok) return;
  }
  await guarded(() => api("POST", `/api/requests/${r.id}/run`));
}

// ---- a question

// ---- an offer to build: the app's own words on what it costs, and how big a change it might be

const MODEL_NAME = { "z-ai/glm-5.3": "GLM 5.3", "z-ai/glm-5.3-flash": "GLM 5.3 Flash", "private/glm-5-3": "private GLM 5.3", "anthropic/claude-opus-5.5": "Claude Opus 5.5" };
const SIZE_TEXT = {
  simple: ["A simple fix", "a few lines in one or two places."],
  significant: ["A significant modification", "several files, or a new part of the app."],
  major: ["A major rewrite", "deep changes to how the app works: the most costly, and the most likely not to work out."],
};
function offerCost(sized) {
  const m = S.state.config.settings.builder_model;
  const range = "a few dollars for a simple fix, $50 or more for a big change";
  const routed = (S.state.config.settings.model_routes || {})[m];
  const who = m === "z-ai/glm-5.3" && !routed
    ? `With a NanoGPT subscription, GLM 5.3 builds on your subscription; without one, it's paid per use: ${range}.`
    : `On ${MODEL_NAME[m] || m}${routed ? ` (${routeText(routed)})` : ""} it's paid per use: ${range}. Set a spending limit on your NanoGPT key.`;
  return `${sized ? "" : "Nobody can tell from the outside whether this needs a few lines changed or a big part of the app rewritten. "}${who} It may take under an hour or several hours, and some changes don't work out.`;
}
function offerDetails(q) {
  const o = q.offer, size = SIZE_TEXT[o.size], out = [];
  if (o.upstream) out.push(h("div", { class: "small" }, h("span", { class: "muted" }, "From its official source: "), sourceText(o.upstream)));
  if (size) out.push(h("div", { class: `size ${o.size}` }, h("b", {}, `${size[0]}: `), size[1], o.size_reason ? h("div", { class: "small" }, o.size_reason) : null));
  if (q.status === "pending") {
    out.push(h("div", { class: "warnbox" }, h("b", {}, "What it costs. "), offerCost(!!size)));
    if (!size) out.push(h("div", { class: "small muted" }, "Not sure? “First, tell me how big a change it is” has it read the app's code first, without building anything: that costs a little, much less than a build."));
  }
  return out;
}

function questionCard(q) {
  const card = h("div", { class: `card question${q.offer ? " offer" : ""}` });
  const answered = q.status !== "pending";
  const picks = q.questions.map(() => ({ value: "" }));
  const submit = () => guarded(() => api("POST", `/api/questions/${q.id}`, { answers: picks.map((p) => p.value) }));
  q.questions.forEach((item, i) => {
    card.append(h("div", { class: "q" }, item.question));
    if (q.offer && i === 0) card.append(...offerDetails(q));
    if (answered) { card.append(h("div", { class: "small" }, "→ ", (q.answers || [])[i] || "")); return; }
    const opts = h("div", { class: "opts" });
    const free = h("input", { type: "text", autocomplete: "off", placeholder: item.options?.length ? "Or type your own answer" : "Your answer", "data-key": `q-${q.id}-${i}` });
    free.addEventListener("input", () => { picks[i].value = free.value; for (const b of opts.children) b.classList.remove("on"); });
    free.addEventListener("keydown", (e) => { if (e.key === "Enter") submit(); });
    for (const o of item.options || []) {
      opts.append(h("button", { class: "small", type: "button", title: o, onclick: (ev) => {
        for (const b of opts.children) b.classList.toggle("on", b === ev.target);
        picks[i].value = o; free.value = "";
        if (q.questions.length === 1) submit();
      } }, o));
    }
    card.append(opts, free);
  });
  if (!answered && (q.questions.length > 1 || !(q.questions[0].options || []).length)) {
    card.append(h("div", { class: "actions" }, h("button", { class: "small primary", onclick: submit }, "Answer")));
  }
  return card;
}

// ---- a delivered app

const KIND_LABEL = { appimage: "app", source: "source code", addon: "add-on" };
const HOME_LABEL = { gearlever: "Gear Lever", shelly: "Shelly", menu: "your apps menu", files: "" };
const deliveryOf = (id) => (S.state.deliveries || []).find((x) => x.id === id);
const appOf = (d) => (S.state.apps || []).find((a) => a.id === d.app);

// how deep a delivered change goes, as the user is told it
const DEPTH_WARNING = {
  desktop: ["This changes part of your desktop itself.",
    "That's possible, but the more deeply something is woven into your system, the more problems a change can cause. Other parts of your desktop may still open the original, extras made for the installed one may not work in this copy, and every update needs a rebuild. Changing an ordinary app is much easier. Try it before you rely on it."],
  system: ["This changes something below your desktop.",
    "Parts like this are the most deeply woven into your system, and a change to them can cause problems that are hard to undo. Read what changed, and try it carefully."],
};

function reportEl(d) {
  if (!d.tested && !d.not_tested) return null;
  return h("details", { class: "report small", open: d.status === "new" }, h("summary", {}, "What was tested"),
    d.tested ? h("div", {}, h("b", {}, "In the sandbox: "), d.tested) : null,
    d.not_tested ? h("div", {}, h("b", {}, "Not tested: "), d.not_tested) : null);
}

function tryEl(d) {
  if (d.kind !== "appimage" || d.status !== "new") return null;
  const box = h("div", { class: "try" });
  if (d.try_steps?.length) box.append(h("div", { class: "small" }, h("b", {}, d.tried ? "While you try it:" : "When you try it, check:")),
    h("ul", { class: "small" }, d.try_steps.map((t) => h("li", {}, t))));
  if (d.tried) {
    const tell = (text) => guarded(async () => { await api("POST", "/api/send", { message: text }); });
    box.append(h("div", { class: "actions" },
      h("span", { class: "small muted" }, "How did it go?"),
      h("button", { class: "small", onclick: () => guarded(async () => {
        await api("POST", `/api/deliveries/${d.id}/works`); await tell(`I tried ${d.name} ${d.version}: it works.`); }) }, "It works"),
      h("button", { class: "small", onclick: () => {
        const input = $("#input"); input.value = `I tried ${d.name} ${d.version} and `; input.focus(); autosize();
      } }, "Something's wrong"),
      d.app ? h("button", { class: "small ghost", onclick: () => guarded(() => startChat({ mode: "computer", app: d.app })) }, "Look into it on this computer") : null));
  }
  return box;
}

function deliveryCard(d) {
  const act = (a) => guarded(() => api("POST", `/api/deliveries/${d.id}/${a}`));
  const replaced = d.status === "replaced";
  const head = { installed: "✓ Installed", rejected: "Set aside", replaced: `Replaced by ${deliveryOf(d.replaced_by)?.version || "a newer version"}` }[d.status]
    || (d.port ? `📦 ${d.base_ref} is ready, with your changes` : d.replaces ? "📦 A new version is ready" : "📦 Ready for you");
  const card = h("div", { class: `card delivery${d.status === "installed" ? " installed" : ""}${replaced ? " settled" : ""}` },
    h("div", { class: "head" }, head, h("span", { class: "spacer" }),
      d.identical_to ? h("span", { class: "chip ok", title: "Your changes carried over exactly: the same patch you had before" }, "same change") : null,
      h("span", { class: "chip" }, KIND_LABEL[d.kind] || d.kind)),
    h("div", { class: "name" }, `${d.name} ${d.version}`),
    d.summary ? h("div", { class: "md", html: md(d.summary) }) : null,
    DEPTH_WARNING[d.integration] && !replaced ? h("div", { class: "warnbox depth" }, h("b", {}, DEPTH_WARNING[d.integration][0]), " ", DEPTH_WARNING[d.integration][1]) : null,
    replaced ? null : reportEl(d),
    replaced ? null : tryEl(d),
    d.by === "app" ? h("div", { class: "small muted" }, "Built by this app from the official release, with your saved changes and build steps.") : null,
    d.replaces && d.status === "new" ? h("div", { class: "small muted" }, `Installing it takes the place of ${deliveryOf(d.replaces)?.version || d.replaces}.`) : null,
    d.left_out?.length && !replaced ? h("div", { class: "small muted" }, `As you chose, it leaves out ${d.left_out.map((t) => `“${t}”`).join(" and ")}.`) : null,
    d.remake && !replaced ? h("div", { class: "small" }, `Made again, cleanly, from the official ${d.base_ref}${d.upstream ? ` (${sourceText(d.upstream)})` : ""}. Before, it was built on ${d.remake.base_ref || "?"}${d.remake.upstream && d.remake.upstream !== d.upstream ? ` from ${shortSource(d.remake.upstream)}` : ""}.`) : null,
    d.merged?.length && !replaced ? h("div", { class: "small muted" }, `${d.merged.map((t) => `“${t}”`).join(" and ")} ${d.merged.length > 1 ? "are" : "is"} part of ${d.base_ref} itself now, so ${d.merged.length > 1 ? "they're" : "it's"} no longer one of your changes.`) : null,
    d.grew?.length && !replaced ? h("div", { class: "warnbox" }, `To fit ${d.base_ref}, ${d.grew.map((t) => `“${t}”`).join(" and ")} changed more than usual. Try it carefully before you rely on it.`) : null,
    d.screenshots?.length && !replaced ? h("div", { class: "shots" }, d.screenshots.map((s) => authImg(`/api/deliveries/${d.id}/shots/${encodeURIComponent(s)}`))) : null);
  const btns = h("div", { class: "actions" });
  if (d.status === "installed") {
    btns.append(h("button", { class: "small primary", onclick: () => act("open") }, d.kind === "appimage" ? "Open it" : "Open the folder"));
  } else if (!["rejected", "replaced"].includes(d.status)) {
    if (d.kind === "appimage") btns.append(h("button", { class: `small${d.tried ? "" : " primary"}`, title: "Runs it once, without installing it",
      onclick: () => act("try") }, d.tried ? "Try it again" : "Try it first"));
    btns.append(h("button", { class: `small${d.kind === "appimage" && !d.tried ? "" : " primary"}`, onclick: () => installDelivery(d) }, "Install"));
  }
  btns.append(h("button", { class: "small", onclick: () => guarded(() => showDelivery(d.id)) }, "What changed?"));
  card.append(btns);
  if (d.installed_to && !replaced) card.append(h("div", { class: "small muted" }, d.installed_via && HOME_LABEL[d.installed_via] ? `In ${HOME_LABEL[d.installed_via]}: ` : "In ", h("code", {}, d.installed_to)));
  if (d.backups?.length) card.append(h("div", { class: "small muted" }, "Your own file of the same name was kept: ", h("code", {}, d.backups.join(", "))));
  return card;
}

// ---- an app of the user's, over time

const STEP_LABEL = { waiting: "waiting for another build", start: "starting a clean container to build in", packages: "installing its build tools", fetch: "getting the new version",
  apply: "putting your changes in", build: "building it", deliver: "checking the result" };

function appAct(a, action, body) { return api("POST", `/api/apps/${a.id}/${action}`, body); }
const failedChanges = (a, port) => Object.entries(port.changes || {}).filter(([, r]) => r === "failed")
  .map(([id]) => (a.changes || []).find((c) => c.id === id)?.title || id);

function releaseEl(a) {
  const u = a.update || {};
  if (a.building) {
    return h("div", { class: "update" }, h("div", { class: "row" }, h("span", { class: "spinner" }),
      h("b", {}, `Building ${a.building.tag} with your changes`), ` (${STEP_LABEL[a.building.step] || a.building.step})…`),
      h("div", { class: "small muted" }, "Building uses a lot of your computer's power, so it may be slower until it's done. You can keep using it."));
  }
  if (S.checking?.has(a.id)) return h("div", { class: "small muted row" }, h("span", { class: "spinner" }), "Looking for a new version…");
  if (u.port?.status === "merged" && u.status === "available") {
    return h("div", { class: "small" }, `🎉 ${a.name} ${u.latest} has your change${(a.changes || []).length > 1 ? "s" : ""} itself: the project made ${(a.changes || []).length > 1 ? "them" : "it"} part of it. Its own version does what yours does.`);
  }
  if (u.status === "available" && a.skip !== u.latest) {
    const sum = u.summary || {};
    const security = (u.security_lines || []).length || sum.security;
    const port = u.port?.status === "failed" ? u.port : null;
    const box = h("div", { class: `update${security ? " security" : ""}` },
      h("div", {}, h("b", {}, `🆕 ${a.name} ${u.latest} is out.`), security ? h("span", { class: "chip danger", style: "margin-left:6px" }, "security fixes") : null),
      sum.status === "checking" ? h("div", { class: "small row" }, h("span", { class: "spinner" }), "Summarising what's new…")
        : sum.status === "done" ? h("div", { class: "small" }, sum.summary || sum.text,
          sum.security ? h("div", { class: "small" }, h("b", {}, "Security: "), sum.security) : null)
        : sum.status === "error" ? h("div", { class: "small muted" }, `No summary: ${sum.error}`) : null,
      !sum.security && security ? h("div", { class: "small" }, h("b", {}, "Mentions security: "), u.security_lines.slice(0, 3).join(" · ")) : null,
      !port && a.schedule?.waiting === "scheduled" ? h("div", { class: "small" }, `Your version is built at ${fmtHour(S.state.config.settings.build_time)}, when your computer is quiet. Or build it now.`) : null,
      !port && a.schedule?.waiting === "battery" ? h("div", { class: "small" }, "Waiting to build: your computer is on its battery. It's built at the quiet time once it's plugged in (or now, if you like).") : null,
      port ? h("div", { class: "warnbox" }, failedChanges(a, port).length
        ? `${failedChanges(a, port).map((t) => `“${t}”`).join(" and ")} didn't fit the new version as ${failedChanges(a, port).length > 1 ? "they are" : "it is"}. The assistant can make ${failedChanges(a, port).length > 1 ? "them" : "it"} fit; the rest of your changes carried over by themselves.`
        : `Your changes didn't carry over by themselves (${STEP_LABEL[port.step] || port.step} failed). The assistant can finish it.`) : null,
      h("div", { class: "actions" },
        port && a.chat?.tag === u.latest ? chatButton(a, "primary")
          : port ? h("button", { class: "small primary", onclick: () => guarded(async () => { await appAct(a, "assistant"); closePanel(); }) }, "Let the assistant do it")
          : a.kind === "appimage" ? h("button", { class: "small primary", onclick: () => rebuildApp(a) }, a.schedule?.waiting ? "Build it now" : `Build ${u.latest} with my changes`)
          : h("button", { class: "small primary", onclick: () => guarded(async () => { await appAct(a, "assistant"); closePanel(); }) }, `Update to ${u.latest}`),
        h("button", { class: "small", onclick: () => guarded(() => showChangelog(a)) }, "What's new?"),
        !sum.status || sum.status === "error" ? h("button", { class: "small", onclick: () => guarded(() => appAct(a, "summarize")) }, "Summarise it") : null,
        h("button", { class: "small ghost", onclick: () => guarded(() => appAct(a, "skip")) }, "Skip this version")));
    return box;
  }
  if (u.status === "current") return h("div", { class: "small muted" }, `Up to date: ${a.base_ref} is the newest release (checked ${fmtDay(u.checked)}).`);
  if (u.status === "error") return h("div", { class: "small muted" }, `Couldn't check for a new version: ${u.error}`);
  if (u.status === "available" && a.skip === u.latest) return h("div", { class: "small muted" }, `You skipped ${u.latest}. You'll hear about the next one.`);
  return null;
}

// where the app's code comes from: the project's own repository, which its updates follow
function sourceEl(a) {
  if (!a.upstream) return h("div", { class: "small muted" }, "Its own code, made for you: there's no project to follow for updates.");
  const page = a.upstream.replace(/\.git$/, "");
  return h("div", { class: "small source" }, h("span", { class: "muted" }, "Official source: "),
    page.startsWith("https://") ? h("a", { href: page, target: "_blank", rel: "noopener noreferrer", title: page }, `${sourceText(a.upstream)} ↗`) : sourceText(a.upstream),
    a.base_ref ? h("span", { class: "muted" }, ` · release ${a.base_ref}`) : null);
}

// ---- one app, shared with someone else (share.py): a .vibe file of its source, changes and build script

// first, what the file will hold: each change's title and notes, which the user can correct, and
// anything in them that came from this computer (the web search check's)
async function exportApp(a) {
  const p = await appAct(a, "share-preview");
  const fields = p.changes.map((c) => ({ c, title: h("input", { type: "text", value: c.title, maxlength: 120 }),
    notes: h("textarea", { class: "notes", rows: 6, spellcheck: "true", value: c.notes }) }));
  const flagged = (list) => list?.length ? h("div", { class: "warnbox small" },
    `Came from your computer, so check it before you share: ${list.map((x) => `“${x}”`).join(", ")}.`) : null;
  modal({ title: `Share ${a.name}?`, body: h("div", {},
    h("p", { class: "small" }, `The file holds where ${a.name} comes from (${sourceText(p.upstream)}, ${p.base_ref}), how it's built, `
      + "and each of your changes: its code, and its title and notes as below. Not your chats, your key, your builds or "
      + "anything else about this computer. Whoever you give it to sees all of it, so correct anything here first."),
    ...fields.map(({ c, title, notes }) => h("div", { class: "field share-change" },
      h("span", {}, "Change"), title, notes, flagged(c.flags))),
    p.build_flags?.length ? h("div", {}, h("div", { class: "small" }, "How it's built:"), flagged(p.build_flags)) : null),
    buttons: [{ label: "Cancel" }, { label: "Save the file", kind: "primary", onClick: async () => {
      const notes = {};
      for (const { c, title, notes: n } of fields) {
        if (title.value.trim() !== c.title || n.value.trim() !== c.notes) {
          if (!n.value.trim()) throw new Error(`“${title.value.trim() || c.title}” needs notes: what it does, for whoever you give it to.`);
          notes[c.id] = { title: title.value.trim(), notes: n.value.trim() };
        }
      }
      exported(a, await appAct(a, "export", Object.keys(notes).length ? { notes } : undefined));
    } }] }).box.classList.add("wide");
}

function exported(a, out) {
  modal({ title: `${a.name} is ready to share`, buttons: [{ label: "Close" }], body: h("div", {},
    h("p", {}, "Saved as ", h("b", { class: "mono" }, out.name), ` in ${out.folder} (${fmtBytes(out.size)}).`),
    h("p", { class: "small muted" }, `It holds where ${a.name} comes from, the release it's built on, your changes with their notes, and how it's built. Not your chats, your key, your builds or anything about this computer. Whoever you give it to imports it in My apps, and their computer builds it from the official source.`),
    h("div", { class: "actions" }, h("button", { class: "small", onclick: () => guarded(() => api("POST", "/api/open-folder", { export: out.path })) }, "Show it in its folder"))) });
}

// a copy of the app itself, to run on another computer or keep (no updates come to that copy)
async function exportAppImage(a) {
  const out = await appAct(a, "export-appimage");
  modal({ title: `${a.name} ${out.version} is saved`, buttons: [{ label: "Close" }], body: h("div", {},
    h("p", {}, "Saved as ", h("b", { class: "mono" }, out.name), ` in ${out.folder} (${fmtBytes(out.size)}).`),
    h("p", { class: "small" }, "It runs by itself on Linux computers as new as Ubuntu 24.04 or Mint 22 (most current distributions): copy it there, make it executable (right-click → Properties → Allow executing, or chmod +x), and open it. Nothing needs installing."),
    h("p", { class: "small muted" }, `That copy won't be kept up to date: here, My apps keeps ${a.name} updated. For someone who uses DA Vibe Manager, Share… is better: their copy is built from the official source and kept up to date too.`),
    h("details", { class: "small muted" }, h("summary", {}, "Its checksum"), h("code", { class: "mono hash" }, `sha256 ${out.sha256}`)),
    h("div", { class: "actions" }, h("button", { class: "small", onclick: () => guarded(() => api("POST", "/api/open-folder", { export: out.path })) }, "Show it in its folder"))) });
}

const patchEl = (text) => h("pre", { class: "patch small" }, (text || "").split("\n").map((l) => h("span", {
  class: l.startsWith("+") && !l.startsWith("+++") ? "add" : l.startsWith("-") && !l.startsWith("---") ? "del" : l.startsWith("@@") ? "hunk" : "" }, `${l}\n`)));
const REVIEW_LOOK = { ok: ["ok", "Looks safe"], care: ["warn", "Be careful"], stop: ["danger", "Don't install it"] };

// a reviewer's reading of a shared app's changes (not a command's second opinion: reviewEl)
function sharedReviewEl(r, compact) {
  if (!r || r.status === "checking") return h("div", { class: "small row" }, h("span", { class: "spinner" }), "A reviewer is reading its changes…");
  if (r.status === "error") return h("div", { class: "warnbox small" }, `Its changes couldn't be reviewed: ${r.error}. Read them yourself before you build it.`);
  const [cls, label] = REVIEW_LOOK[r.level] || ["", r.verdict || "Read by a reviewer"];
  return h("div", { class: `review ${cls}` }, h("div", {}, h("span", { class: `chip ${cls}` }, label), " ", h("span", { class: "small" }, r.summary)),
    r.concerns ? h("div", { class: "small" }, h("b", {}, "Worth knowing: "), r.concerns) : null,
    r.parts > 1 ? h("div", { class: "small muted" }, `Its changes were too long to read together, so each was read on its own (${r.parts} readings).`) : null,
    r.partial ? h("div", { class: "small muted" }, "A change was too long to read in full.") : null,
    r.binaries?.length ? h("div", { class: "small" }, h("b", {}, `${r.binaries.length} binary file${r.binaries.length > 1 ? "s" : ""} the reviewer can't read: `),
      r.binaries.map((b) => `${b.file.split("/").pop()} (${b.bytes != null ? fmtBytes(b.bytes) : "?"})`).join(", "),
      ". Check they're what the change needs (pictures, sounds, test data), not programs.") : null,
    !compact && r.text ? h("details", { class: "small" }, h("summary", {}, "What the reviewer said"), h("div", { class: "md", html: md(r.text) })) : null);
}

// the systems this version of the app is known to work on, and a way to say it works here
function worksEl(a) {
  const inst = a.installed;
  if (!a.works_on?.length && !inst) return null;
  return h("div", { class: "small row" },
    a.works_on?.length ? h("span", {}, h("span", { class: "muted" }, "Works on: "), a.works_on.join(" · ")) : h("span", { class: "muted" }, "Not confirmed to work anywhere yet."),
    inst && !a.works_here && a.kind === "appimage" ? h("button", { class: "small ghost", onclick: () => guarded(async () => {
      await api("POST", `/api/deliveries/${inst.build}/works`); toast(`Noted: ${a.name} works on this computer.`, "ok", 2500); }) }, "It works here") : null);
}

// a shared app made to work here: the copies elsewhere don't have that, so offer to share it back
function reshareEl(a) {
  const r = a.reshare;
  if (!r) return null;
  return h("div", { class: "update reshare" },
    h("div", {}, h("b", {}, `📤 Share this version of ${a.name}?`), ` It works on ${r.system} now.`),
    h("div", { class: "small" }, r.received
      ? `The person who gave you ${a.name} still has the version from before. If they (or anyone they share it with) use ${r.system}, it has the same problem you had. This version has your fix and still has everything theirs did.`
      : `Whoever you gave ${a.name} to has the version from before, without what changed since.`),
    h("div", { class: "small muted" }, `Share… saves a new .vibe file. When they import it, DA Vibe Manager sees it's a newer version of their ${a.name} and offers to update it, keeping any changes of their own.`),
    h("div", { class: "actions" }, h("button", { class: "small primary", onclick: () => guarded(() => exportApp(a)) }, "Share…"),
      h("button", { class: "small ghost", onclick: () => guarded(() => appAct(a, "reshare-later")) }, "Not now")));
}

// an app from someone else, or changes of theirs added to one of the user's: built when they say so
function importedEl(a) {
  const imp = a.imported;
  if (!imp || imp.built !== false || a.building) return null;
  const titles = (a.changes || []).filter((c) => (imp.changes || []).includes(c.id)).map((c) => c.title);
  const failed = a.update?.port?.status === "failed" && a.update.port.tag === a.base_ref;
  return h("div", { class: "update" },
    h("div", {}, h("b", {}, imp.update ? `Updated to the shared version${titles.length ? `: ${titles.join(" · ")}` : ""}.`
      : imp.into ? `Added from a shared app: ${titles.join(" · ")}.` : "Shared with you."),
      ` Not built yet: it's built from the official ${a.base_ref} with ${imp.into ? "all your changes" : "its changes"}.`),
    sharedReviewEl(imp.review, true),
    failed ? h("div", { class: "small" }, `${a.update.port.step === "apply" ? "Not all of them applied by themselves" : "It didn't build by itself"}, so the assistant was asked to finish it in a chat. Its build shows up here when it's done.`) : null,
    h("div", { class: "actions" },
      failed && a.chat ? chatButton(a, "primary") : null,
      h("button", { class: `small ${failed && a.chat ? "ghost" : "primary"}`, onclick: () => guarded(async () => {
        if (imp.review?.level === "stop" && !(await confirmModal("Build it anyway?", "The reviewer said not to install these changes. Building it is safe (it happens in the sandbox), but read what it said before you install it.", "Build it"))) return;
        if (failed && !(await confirmModal("Try building it again?", "Last time it couldn't be made by itself, so the same will probably happen again, and a new chat with the assistant starts (which costs money). To carry on with the one already working on it, use “Go to its chat”.", "Try again"))) return;
        await appAct(a, "build"); }) }, failed ? "Try again" : "Build it")));
}

// the chat the assistant was asked to build an app in (AppManager.ask_assistant)
function chatButton(a, kind = "") {
  return h("button", { class: `small ${kind}`, onclick: () => guarded(async () => {
    await api("POST", "/api/chats/open", { id: a.chat.id }); closePanel(); }) }, "Go to its chat");
}

async function removeApp(a) {
  const inst = a.installed;
  const ok = await confirmModal(`Remove ${a.name}?`, h("div", {},
    h("p", {}, inst ? `${a.name} ${inst.version || ""} is uninstalled${HOME_LABEL[inst.via] ? ` from ${HOME_LABEL[inst.via]}` : ""}, and it goes from My apps with its builds and changes.`
      : `${a.name} goes from My apps, with its builds and changes.`),
    h("p", { class: "small" }, a.kind === "addon" && inst ? "Its files are taken out of the app's folder, and any of your own it set aside are put back." : a.kind === "source" && inst ? `The copy of its source code (${inst.path || "in your install folder"}) stays.` : ""),
    h("p", { class: "small muted" }, a.unshareable ? "Its chats stay in Chats." : "Its chats stay in Chats. To keep its changes, Share… it first: the .vibe file can be imported again.")), "Remove", "danger");
  if (!ok) return;
  let out;
  try {
    out = await appAct(a, "remove");
  } catch (e) {
    if (!inst || !/couldn't be uninstalled/.test(e.message)) throw e;
    if (!(await confirmModal("It couldn't be uninstalled", h("div", {}, h("p", {}, e.message),
      h("p", { class: "small" }, `Remove ${a.name} from My apps anyway? It stays installed, and you can remove it yourself${HOME_LABEL[inst.via] ? ` in ${HOME_LABEL[inst.via]}` : ""}.`)), "Remove it anyway", "danger"))) return;
    out = await appAct(a, "remove", { keep_installed: true });
  }
  toast(out?.left ? `${a.name} is removed. Left on your computer: ${out.left}` : `${a.name} is removed.`, out?.left ? "info" : "ok");
}

function importApp() {
  const file = h("input", { type: "file", accept: ".vibe" });
  const m = modal({ title: "Import an app", body: h("div", {},
    h("p", { class: "small" }, "Choose the .vibe file someone gave you. It's read first: nothing is built or installed until you say so."), file),
    buttons: [{ label: "Cancel" }, { label: "Next", kind: "primary", onClick: async () => {
      if (!file.files[0]) throw new Error("Choose the file first.");
      const res = await fetch("/api/share/upload", { method: "POST", headers: { "X-Token": TOKEN }, body: file.files[0] });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || data.detail || "The file couldn't be read.");
      importView(data);
    } }] });
  return m;
}

// how a shared file's version stands to the user's own copy of that app (share.relation), in words
function versionWords(c) {
  const theirs = c.changes.filter((x) => x.how === "theirs_newer").map((x) => x.title);
  const added = c.changes.filter((x) => x.how === "new").map((x) => x.title);
  const both = c.changes.filter((x) => x.how === "both").map((x) => x.title);
  const mine = c.changes.filter((x) => x.how === "mine_only").map((x) => x.title);
  const what = [...theirs.map((t) => `“${t}” changed`), ...added.map((t) => `“${t}” is new`),
    ...(["theirs_newer", "both"].includes(c.build) ? ["how it's built changed"] : [])];
  return { what: what.join(", "), both, mine };
}

function importView(v) {
  const a = v.app;
  const name = h("input", { type: "text", value: v.name });
  // what a file says of its version is only its word: anyone with an earlier copy could make one
  // that says it's newer, so updating is never chosen for the user
  let pick = {};
  const reviewBox = h("div", {}, sharedReviewEl(v.review));
  const radio = (checked, onpick, title, desc, extra) => h("label", { class: "radio" },
    h("input", { type: "radio", name: "into", checked, onchange: onpick }),
    h("div", {}, h("div", {}, title), desc ? h("div", { class: "small muted" }, desc) : null, extra || null));
  const copyNotes = v.copies.filter((c) => ["same", "older"].includes(c.verdict)).map((c) => h("div", { class: "warnbox small" },
    c.verdict === "same" ? `You have this version already: your ${c.name}. There's nothing to update.`
      : `Your ${c.name} is newer than this file: keep yours. If whoever sent it needs your version, use Share… on your ${c.name} and send them that.`));
  const choices = h("div", {},
    ...v.copies.filter((c) => ["newer", "both"].includes(c.verdict)).map((c) => {
      const w = versionWords(c);
      return radio(false, () => { pick = { update: c.id }; }, `Update your ${c.name} to this version`,
        (c.build === "theirs_newer" || c.build === "both" ? "It also changes how your app is built: read “How it's built” above first. " : "")
        + (c.verdict === "newer"
          ? `The file says it's a newer version of the ${c.name} you have, from the same shared app (only take its word if you know who sent it): ${w.what}.${w.mine.length ? ` Your own change${w.mine.length > 1 ? "s" : ""} (${w.mine.join(", ")}) stay.` : ""} It's built again on your release, and the ${c.name} you have stays installed until you install the new build.`
          : `You've both changed it since it was shared: ${w.what || "theirs differs"}. Updating takes theirs for ${w.both.length ? w.both.map((t) => `“${t}”`).join(", ") : "what they changed"}${w.mine.length ? `, and keeps yours for ${w.mine.join(", ")}` : ""}. Keeping it as an app of its own instead lets you try theirs first.`));
    }),
    radio(true, () => { pick = {}; }, "As an app of its own", "Next to any you have, with its own name: try it before it touches yours.", h("div", { class: "row small" }, "Its name:", name)),
    ...v.yours.map((x) => radio(false, () => { pick = { into: x.id }; }, `Add its changes to your ${x.name}`,
      `Yours has: ${x.changes.join(" · ") || "no changes yet"}. Theirs go on top; if they touch the same code as yours, the assistant may be needed to fit them together.`)));
  const body = h("div", {},
    h("p", {}, h("b", {}, a.name), " from ", sourceText(a.upstream), `, built on ${a.base_ref}.`),
    h("div", { class: "small" }, v.works_on.length ? `Known to work on: ${v.works_on.join(" · ")}.` : "Not confirmed to work anywhere yet.",
      v.works_on.includes(v.this_system) ? "" : ` Not tried on ${v.this_system} yet: if it doesn't work here, “It doesn't work on this computer” in My apps finds out why.`),
    h("div", { class: "small muted" }, "Check that this is the project's official source, not a copy of it: it's what the app is built from and updated from."),
    h("h3", {}, `Its change${a.changes.length > 1 ? "s" : ""}`),
    ...a.changes.map((c) => h("details", { class: "change" }, h("summary", {}, c.title, h("span", { class: "small muted" }, ` · ${c.lines} lines`)),
      c.notes ? h("div", { class: "md small", html: md(c.notes) }) : h("div", { class: "small muted" }, "It has no notes."), patchEl(c.patch))),
    h("details", { class: "small" }, h("summary", {}, "How it's built (in the sandbox)"), h("pre", { class: "outview small" }, v.build_script)),
    h("h3", {}, "A second opinion"), reviewBox,
    h("h3", {}, "Import it"), ...copyNotes, choices);
  const m = modal({ title: `Import ${a.name}?`, body, buttons: [{ label: "Cancel" }, { label: "Import", kind: "primary", onClick: async () => {
    const out = await api("POST", `/api/share/${v.token}/import`, { ...pick, name: name.value.trim() });
    toast(pick.update ? `Your ${out.name} has the new version's changes. Build it in My apps when you're ready.`
      : `${out.name} is in My apps. Build it there when you're ready.`, "ok");
    openPanel("apps");
  } }] });
  m.box.classList.add("wide");
  const poll = setInterval(async () => {
    if (!document.body.contains(m.box)) { clearInterval(poll); return; }
    try {
      const now = await api("GET", `/api/share/${v.token}`);
      if (now.review.status !== "checking") { clearInterval(poll); reviewBox.replaceChildren(sharedReviewEl(now.review)); }
    } catch { clearInterval(poll); }
  }, 2000);
}

async function showChange(a, c) {
  const x = await api("GET", `/api/apps/${a.id}/changes/${encodeURIComponent(c.id)}`);
  modal({ title: c.title, buttons: [{ label: "Close" }], body: h("div", {},
    h("p", { class: "small muted" }, `Your change to ${a.name}${x.base_ref ? `, against its official ${x.base_ref}` : ""}${c.added ? `, first made ${fmtDay(c.added)}` : ""}. It's carried over to each new version.`),
    x.feature ? h("details", { open: true }, h("summary", { class: "small" }, "What it is"), h("div", { class: "md", html: md(x.feature) })) : null,
    x.patch ? h("details", {}, h("summary", { class: "small" }, "The change to the code"), h("pre", { class: "outview small" }, x.patch)) : null) });
}

const LOOK_LABEL = { day: "every day", week: "every week", month: "every month", manual: "only when you ask" };
const fmtHour = (hhmm) => { const [hh, mm] = (hhmm || "03:00").split(":").map(Number); return new Date(2000, 0, 1, hh, mm).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" }); };
const buildLabel = (when) => ({ scheduled: `at ${fmtHour(S.state.config.settings.build_time)}`, auto: "straight away", ask: "when you say so" }[when] || when);

// this app's own choices: how often to look for new versions, and when to build them
function scheduleEl(a) {
  if (!a.upstream || !a.base_ref) return null;
  const s = a.schedule || {}, own = s.own || {}, set = S.state.config.settings;
  const sel = (key, options) => h("select", { onchange: (e) => guarded(() => appAct(a, "schedule", { [key]: e.target.value })) },
    options.map(([v, label]) => h("option", { value: v, selected: (own[key] || "") === v }, label)));
  return h("details", { class: "small schedule" },
    h("summary", {}, `Updates: looked for ${LOOK_LABEL[s.check_every] || s.check_every}, built ${buildLabel(s.build_when)}`),
    h("div", { class: "field" }, h("span", {}, "Look for new versions"),
      sel("check_every", [["", `Like my other apps (${LOOK_LABEL[set.check_every]})`], ["day", "Every day"], ["week", "Every week"],
        ["month", "Every month"], ["manual", "Only when I ask"]])),
    h("div", { class: "field" }, h("span", {}, "Build a new version with my changes"),
      sel("build_when", [["", `Like my other apps (${buildLabel(set.rebuild)})`], ["scheduled", `At ${fmtHour(set.build_time)}, when my computer is quiet`],
        ["auto", "Straight away"], ["ask", "When I say so"]])),
    h("div", { class: "small muted" }, "Building uses a lot of your computer's power for a while. The time is in Settings."));
}

// an app whose changes have become hard to carry over (built on a fork, or with others' code history in
// it): made again from the official project, each change made afresh on it
async function startAgain(a) {
  const ok = await confirmModal(`Start ${a.name} again, cleanly?`, h("div", {},
    h("p", {}, `The assistant makes ${a.name} again from the project's official source, with each of your changes (${(a.changes || []).map((c) => c.title).join(", ") || "none yet"}) made afresh on it, plus anything you'd like to add.`),
    h("p", { class: "small" }, "Worth it when updates no longer carry your changes over by themselves: for example when it was built on a fork, or pulled in code from other apps. Once it's clean, new versions usually build without the assistant."),
    h("p", { class: "small muted" }, `Your ${a.installed?.version || "current version"} stays as it is until you install the new one, which then takes its place. Building it again costs about what building it did.`)), "Start again");
  if (ok) await guarded(() => startChat({ mode: "app", app: a.id, remake: true }));
}

async function rebuildApp(a) {
  const ok = await confirmModal(`Build ${a.name} ${a.update.latest}?`, h("div", {},
    h("p", {}, `This app takes ${a.update.latest} from the official source, puts your changes in (${a.changes.map((c) => c.title).join(", ")}), and builds it.`),
    h("p", {}, "Building uses a lot of your computer's power for a while (minutes for a small app, longer for a big one), so it may be slower until it's done. If your changes don't fit the new version as they are, the assistant takes over, which is light on your computer."),
    h("p", { class: "small muted" }, `Your ${a.installed?.version || "current version"} stays until you install the new one.`)), "Build it");
  if (!ok) return;
  await guarded(() => appAct(a, "rebuild"));
}

async function checkApp(a) {
  S.checking = S.checking || new Set();
  S.checking.add(a.id); if (S.panel === "apps") openPanel("apps");
  try {
    const u = await appAct(a, "check");
    if (u.status === "none") toast(u.why, "info");
    else if (u.status === "current") toast(`${a.name} ${a.base_ref} is still the newest release.`, "ok");
  } catch (e) { toast(e.message, "error"); }
  finally { S.checking.delete(a.id); if (S.panel === "apps") openPanel("apps"); }
}

async function showChangelog(a) {
  const log = await api("GET", `/api/apps/${a.id}/changelog`);
  const u = a.update || {};
  const body = h("div", {},
    h("p", { class: "small muted" }, `What changed from ${log.since} to ${log.tag}${log.commit_count ? ` (${log.commit_count} changes by its developers)` : ""}. This comes from the project itself.`),
    log.page ? h("p", { class: "small" }, h("a", { href: log.page, target: "_blank", rel: "noopener noreferrer" }, "The official release page ↗")) : null,
    u.security_lines?.length ? h("div", { class: "warnbox" }, h("b", {}, "Lines about security: "), h("ul", {}, u.security_lines.map((l) => h("li", {}, l)))) : null,
    log.notes ? h("div", {}, h("h3", {}, "Release notes"), h("div", { class: "md", html: md(log.notes) })) : null,
    ...Object.entries(log.news || {}).map(([name, text]) => h("div", {}, h("h3", {}, `New in ${name}`), h("pre", { class: "outview small" }, text))),
    log.commits?.length ? h("details", {}, h("summary", { class: "small" }, `Every change (${log.commits.length})`), h("pre", { class: "outview small" }, log.commits.join("\n"))) : null,
    !log.notes && !Object.keys(log.news || {}).length && !log.commits?.length ? h("p", {}, "The project didn't say what changed.") : null);
  modal({ title: `${a.name} ${log.tag}: what's new`, body, buttons: [{ label: "Close" }] });
}

function appCard(a) {
  const inst = a.installed || null;
  const latest = a.latest;
  const pending = latest && latest.status === "new" ? latest : null;
  const card = h("div", { class: "card app" },
    h("div", { class: "head" }, inst ? `✓ You have ${inst.version}${HOME_LABEL[inst.via] ? `, in ${HOME_LABEL[inst.via]}` : ""}` : "Not installed yet",
      h("span", { class: "spacer" }), h("span", { class: "chip" }, KIND_LABEL[a.kind] || a.kind)),
    h("div", { class: "name" }, a.name),
    sourceEl(a),
    a.changes?.length ? h("div", { class: "changes" },
      h("div", { class: "small muted" }, `Your change${a.changes.length > 1 ? "s" : ""}, on top of it:`),
      a.changes.map((c) => h("div", { class: "small change" }, h("span", {}, c.title),
        c.added ? h("span", { class: "muted" }, ` · ${fmtDay(c.added)}`) : null,
        h("button", { type: "button", class: "small ghost", onclick: () => guarded(() => showChange(a, c)) }, "What changed?")))) : null,
    worksEl(a),
    reshareEl(a),
    importedEl(a),
    releaseEl(a),
    scheduleEl(a));
  const btns = h("div", { class: "actions" });
  btns.append(h("button", { class: "small", onclick: () => guarded(() => startChat({ mode: "app", app: a.id })) }, "Improve this app"));
  if (a.upstream || a.changes?.length) btns.append(h("button", { class: "small ghost", onclick: () => startAgain(a) }, "Start again, cleanly"));
  if (inst) btns.append(h("button", { class: "small primary", onclick: () => guarded(() => api("POST", `/api/deliveries/${inst.build}/open`)) }, a.kind === "appimage" ? "Open it" : "Open the folder"));
  if (inst || a.builds?.length) btns.append(h("button", { class: "small", onclick: () => guarded(() => startChat({ mode: "computer", app: a.id })) }, "It doesn't work on this computer"));
  if (a.previous && a.previous.build !== inst?.build && deliveryOf(a.previous.build)) {
    btns.append(h("button", { class: "small", onclick: () => guarded(async () => {
      if (!(await confirmModal(`Go back to ${a.previous.version}?`, `${a.name} ${a.previous.version} is put back where ${inst?.version || "the newer one"} is now.`, "Go back"))) return;
      await appAct(a, "rollback"); toast(`Back to ${a.previous.version}.`, "ok"); }) }, `Go back to ${a.previous.version}`));
  }
  if (a.upstream && a.base_ref && !a.building && !S.checking?.has(a.id)) btns.append(h("button", { class: "small ghost", onclick: () => checkApp(a) }, "Check for a new version"));
  if (!a.unshareable) btns.append(h("button", { class: "small ghost", onclick: () => guarded(() => exportApp(a)) }, "Share…"));
  if (a.export_build) btns.append(h("button", { class: "small ghost", title: "Save a copy of the app to run on another computer",
    onclick: () => guarded(() => exportAppImage(a)) }, "Export AppImage"));
  if (!a.building) btns.append(h("button", { class: "small ghost danger", onclick: () => guarded(() => removeApp(a)) }, "Remove…"));
  card.append(btns);
  const builds = (a.builds || []).map(deliveryOf).filter(Boolean);
  const older = builds.filter((d) => d.id !== pending?.id && d.id !== inst?.build);
  return h("div", { class: "app-line" }, card, pending ? deliveryCard(pending) : null,
    older.length ? h("details", { class: "small muted older" }, h("summary", {}, `Earlier builds (${older.length})`), [...older].reverse().map(deliveryCard)) : null);
}

async function installDelivery(d) {
  const before = (S.state.deliveries || []).find((x) => x.id !== d.id && x.app && x.app === d.app && x.status === "installed");
  const home = S.state.app_homes || {};
  const choice = S.state.config.settings.app_home || "auto";
  const lives = choice !== "auto" ? choice : home.shelly ? "shelly" : home.gearlever ? "gearlever" : "menu";
  const where = {
    appimage: (lives === "menu" ? `It's copied to ${S.state.config.settings.install_dir}, with an entry in your apps menu.`
      : `It's added to ${HOME_LABEL[lives]}, with your other apps.`) + ` Your own ${d.name.replace(/ \((DVM|DLA)\)$/, "")} from your distribution stays as it is, and nothing starts until you open it.`,
    source: `The source code is copied to ${S.state.config.settings.install_dir}/src.`,
    addon: `${(d.files || []).length > 1 ? "Its files are" : "It's"} copied into ${d.install_to}, where the app finds ${(d.files || []).length > 1 ? "them" : "it"} the next time it starts. If you already have a file of the same name there, it's kept, renamed.`,
  }[d.kind];
  const ok = await confirmModal(before ? `Install the update of ${d.name}?` : `Install ${d.name}?`, h("div", {},
    h("p", {}, where),
    d.kind === "addon" && d.files?.length ? h("pre", { class: "outview small" }, d.files.map((f) => `${d.install_to}/${f}`).join("\n")) : null,
    before ? h("p", { class: "small" }, `It takes the place of ${before.version}${d.kind === "appimage" ? " (you can go back to it from My apps)" : ""}.`) : null),
    "Install", "primary");
  if (!ok) return;
  const out = await guarded(() => api("POST", `/api/deliveries/${d.id}/install`));
  if (out) toast(`Installed. Click "Open it" to start it.`, "ok");
}

async function showDelivery(did) {
  const d = await api("GET", `/api/deliveries/${did}`);
  const pane = h("div", {});
  const views = {
    feature: () => h("div", { class: "md", html: md(d.feature) }),
    files: () => h("div", {}, h("pre", { class: "small" }, d.diffstat), h("pre", { class: "small muted" }, d.commits),
      h("p", { class: "small muted" }, d.base_ref ? `Based on ${d.upstream || "the official source"} at ${d.base_ref}.` : "Made from scratch: the change is all of it."),
      d.sha256 ? h("p", { class: "small mono" }, `sha256 ${d.sha256} · ${fmtBytes(d.size)}`) : null,
      d.tested ? h("p", { class: "small" }, `Tested: ${d.tested}`) : null),
    patch: () => h("pre", { class: "patch" }, d.patch.split("\n").map((l) => h("span", {
      class: l.startsWith("+") && !l.startsWith("+++") ? "add" : l.startsWith("-") && !l.startsWith("---") ? "del" : l.startsWith("@@") ? "hunk" : "" }, `${l}\n`))),
  };
  const tabs = h("div", { class: "tabs" });
  const show = (k) => { for (const b of tabs.children) b.classList.toggle("on", b.dataset.k === k); pane.replaceChildren(views[k]()); };
  for (const [k, label] of [["feature", "What was asked"], ["files", "Files"], ["patch", "The change"]]) {
    tabs.append(h("button", { class: "small", "data-k": k, onclick: () => show(k) }, label));
  }
  const m = modal({ title: `${d.name} ${d.version}`, body: pane, buttons: [{ label: "Close" }] });
  m.box.insertBefore(tabs, m.box.querySelector(".content"));
  show("feature");
}

// ------------------------------------------------------------------ setup

// building an app is many model calls: on a model paid per use it is real money on the user's key
const COST_NOTE = "Answering questions costs little, but building an app takes the AI many steps: on a model paid per use, like Claude Opus, a simple fix can cost a few dollars and a big change $50 or more, and nobody can tell which it is until the AI has read the app's code: before a build, you can ask it to find out how big a change it is first. Set a spending limit on your API key at nano-gpt.com, so it can never go beyond what you're happy to spend.";

// the key is in the keyring, which isn't open yet (just after login): wait for it, don't ask again
function keyringScreen() {
  return h("div", { class: "setup" },
    h("h2", {}, "Waiting for your keyring"),
    h("p", {}, "Your API key is kept in your desktop's keyring (GNOME Keyring or KWallet), which isn't open yet. It usually opens a moment after you log in; if your desktop asks for the keyring's password, enter it. DA Vibe Manager carries on by itself as soon as it can read the key."),
    h("p", { class: "small muted" }, S.state.keyring_wait),
    h("div", { class: "actions" }, h("button", { class: "primary", onclick: () => guarded(() => api("POST", "/api/keyring/retry")) }, "Try again")));
}

// a computer without Podman: what it is, and the app's own command to install it, run on the user's click
function podmanBox(p) {
  const ins = p.install || {};
  const what = (p.missing || []).includes("podman") ? "Podman" : "passt, which Podman needs to build the sandbox";
  const check = h("button", { class: "small", onclick: () => guarded(() => api("POST", "/api/workspace/start")) }, "I've installed it: check again");
  const docs = h("a", { href: "https://podman.io/docs/installation", target: "_blank", rel: "noopener noreferrer" }, "Podman's install guide");
  let how;
  if (ins.state === "installing") {
    how = [h("div", {}, h("span", { class: "spinner" }), " Installing… This can take a few minutes."),
      h("div", { class: "small muted" }, "If your computer asks for your password, that's this install.")];
  } else if (p.can_install) {
    how = [h("div", { class: "small muted" }, "This runs, as administrator:"), h("pre", { class: "small mono cmd" }, p.command),
      h("div", { class: "actions" }, h("button", { class: "primary", onclick: () => guarded(() => api("POST", "/api/podman/install")) }, `Install ${(p.missing || []).includes("podman") ? "Podman" : "passt"}`), check),
      h("div", { class: "small muted" }, "Your computer asks for your password; this app never sees it. Or run it yourself in a terminal: ",
        h("code", { class: "mono" }, p.terminal))];
  } else {
    how = [p.terminal ? h("div", {}, "Run this in a terminal:", h("pre", { class: "small mono cmd" }, p.terminal))
      : h("div", {}, "Install Podman with your system's software manager, or see ", docs, "."), h("div", { class: "actions" }, check)];
  }
  return h("div", { class: "card podman" },
    h("div", {}, h("b", {}, `First, one thing to install: ${what}.`)),
    h("div", { class: "small" }, `Podman is the sealed sandbox the assistant works in, kept apart from your computer. It comes from ${p.distro || "your system"} itself, so it gets your system's security updates.`),
    ...how,
    ins.state === "failed" ? h("div", { class: "err small" }, ins.error,
      ins.output ? h("details", {}, h("summary", {}, "What it printed"), h("pre", { class: "small mono" }, ins.output)) : null) : null);
}

function setupScreen() {
  const key = h("input", { type: "password", placeholder: "Your NanoGPT API key", autocomplete: "off" });
  const go = h("button", { class: "primary", onclick: () => guarded(async () => {
    go.disabled = true;
    try { await api("POST", "/api/setup", { api_key: key.value }); toast("All set. The assistant is getting its sandbox ready.", "ok"); }
    finally { go.disabled = false; }
  }) }, "Get started");
  key.addEventListener("keydown", (e) => { if (e.key === "Enter") go.click(); });
  return h("div", { class: "setup" }, h("img", { src: "/static/icon.svg" }), h("h1", {}, "Hi! I'm your Linux helper."),
    S.state.podman ? podmanBox(S.state.podman) : null,
    h("p", {}, "Ask me how to do things on your computer, or what's wrong when something isn't working. If an app can't do what you want, I can often build you a version that can."),
    h("ul", { class: "points" },
      h("li", {}, "I work in a sealed sandbox. I can't see your files or touch your computer. I only see a file if you attach it."),
      h("li", {}, "When I need to look at or change something, I show you exactly what and why. Nothing runs until you say so."),
      h("li", {}, "You decide what I get to see of the results.")),
    h("p", { class: "small" }, "I run on NanoGPT. Paste your API key (it stays in your keyring, never in my sandbox). ",
      h("a", { href: "https://nano-gpt.com/api", target: "_blank", rel: "noopener noreferrer" }, "Get a key")),
    h("div", { class: "warnbox" }, h("b", {}, "Mind the cost. "), COST_NOTE),
    key, go,
    h("p", { class: "small" }, "Moving from another computer? ", h("a", { href: "#", onclick: (e) => { e.preventDefault(); restoreBackup(); } }, "Restore a backup"),
      " to bring your apps, chats, settings and key."));
}

// ------------------------------------------------------------------ panels

function openPanel(name) {
  S.panel = name;
  $("#panel").classList.remove("hidden");
  const body = $("#panel-body");
  $("#panel-title").textContent = { chats: "Chats", apps: "My apps", settings: "Settings", activity: "Sandbox activity" }[name];
  const scroll = body.scrollTop;
  body.replaceChildren(...{ chats: chatsPanel, apps: appsPanel, settings: settingsPanel, activity: activityPanel }[name]());
  body.scrollTop = scroll;
}

function closePanel() { S.panel = null; $("#panel").classList.add("hidden"); }

function chatsPanel() {
  const list = h("div", { class: "section" }, h("div", { class: "muted" }, "Loading…"));
  api("GET", "/api/chats").then(({ chats }) => {
    list.replaceChildren(...chats.map((c) => h("div", { class: "list-item" },
      h("div", { class: "grow" }, h("div", {}, c.title),
        h("div", { class: "small muted" }, [c.mode === "app" ? `📦 ${chatAppName(c)}${c.remake ? ", made again" : ""}` : c.mode === "computer" ? (c.app ? `🩺 ${chatAppName(c)} here` : "🩺 Your computer") : "",
          c.started.replace("T", " ").slice(0, 16), `${c.messages} messages`].filter(Boolean).join(" · "))),
      S.state.conversation?.id === c.id ? h("span", { class: "small muted" }, "open") : h("button", { class: "small", onclick: () => guarded(async () => {
        await api("POST", "/api/chats/open", { id: c.id }); closePanel(); }) }, "Open"),
      S.state.conversation?.id === c.id ? null : h("button", { class: "small ghost", title: "Delete", onclick: () => guarded(async () => {
        if (!(await confirmModal("Delete this chat?", c.title, "Delete", "danger"))) return;
        await api("POST", "/api/chats/delete", { ids: [c.id] }); openPanel("chats"); }) }, "🗑"))));
  }).catch((e) => list.replaceChildren(h("div", { class: "err" }, e.message)));
  return [h("button", { class: "primary", onclick: () => guarded(async () => { await api("POST", "/api/chats/new"); closePanel(); }) }, "＋ New chat"), list];
}

function appsPanel() {
  const list = S.state.apps || [];
  const imp = h("div", { class: "row small" }, h("span", { class: "muted" }, "Someone shared an app with you?"),
    h("button", { class: "small", onclick: importApp }, "Import an app…"));
  if (!list.length) return [h("div", { class: "welcome" }, "Apps I build for you show up here, and I keep them up to date. Tell me what you wish an app could do, and if it's open source I can make you a version that does it.",
    h("div", {}, h("button", { class: "primary", onclick: pickApp }, "📦 Help me fix or add a feature to an app"))), imp];
  return [imp, ...[...list].reverse().map(appCard)];
}

function activityPanel() {
  const w = S.state.workspace || {};
  const evs = S.state.network || [];
  const hosts = {};
  for (const e of evs) if (e.kind === "connect" && e.status === 200) hosts[e.host] = (hosts[e.host] || 0) + 1;
  return [
    h("div", { class: "section" }, h("h3", {}, "The sandbox"),
      h("div", { class: "small" }, { running: "Running.", building: "Being prepared…", starting: "Starting…", failed: "It couldn't start:", stopped: "Stopped.",
        needs_podman: "Waiting for Podman to be installed (see the chat)." }[w.state] || w.state),
      w.state === "failed" ? h("pre", { class: "small err" }, w.error) : null,
      w.step && w.state !== "running" ? h("div", { class: "small mono muted" }, w.step) : null,
      h("p", { class: "small muted" }, "The assistant lives in a sealed container: no access to your files, your network or this computer. It can reach public websites over HTTPS only, through this app, which lists every connection below."),
      w.state !== "running" ? h("button", { class: "small", onclick: () => guarded(() => api("POST", "/api/workspace/start")) }, "Start it") : null),
    searchesEl(evs),
    h("div", { class: "section" }, h("h3", {}, "Sites it reached"), h("div", { class: "small" }, Object.entries(hosts).sort((a, b) => b[1] - a[1]).map(([k, n]) => `${k} (${n})`).join(", ") || "None yet.")),
    h("div", { class: "section" }, h("h3", {}, "Every connection"), evs.length ? h("table", { class: "netlog" }, h("tbody", {}, [...evs].reverse().slice(0, 200).map((e) => {
      const bad = e.refused || (e.status && e.status >= 400);
      const what = e.kind === "model" ? `🤖 ${e.model || e.path}` : e.kind === "http" ? `http ${e.target}`
        : e.kind === "search" ? `🔎 ${e.provider ? `${e.provider}: ` : ""}${e.query}` : `${e.host}:${e.port}`;
      return h("tr", { class: bad ? "bad" : "" }, h("td", { class: "muted" }, fmtTime(e.ts)), h("td", {}, what),
        h("td", {}, bad ? `✗ ${e.refused || e.error || e.status}` : e.kind === "search" ? `✓ ${e.results} result${e.results === 1 ? "" : "s"}`
          : `✓${e.bytes_in != null ? ` ${fmtBytes(e.bytes_in)}` : ""}`));
    }))) : h("div", { class: "small muted" }, "None yet.")),
  ];
}

function searchesEl(evs) {
  const done = evs.filter((e) => e.kind === "search");
  if (!done.length) return null;
  const refused = done.filter((e) => e.refused).length;
  const cost = done.reduce((n, e) => n + (e.cost || 0), 0);
  return h("div", { class: "section" }, h("h3", {}, "Web searches"),
    h("div", { class: "small" }, `${done.length - refused} search${done.length - refused === 1 ? "" : "es"}${cost ? ` (about $${cost.toFixed(3)})` : ""}.`,
      refused ? ` ${refused} refused because ${refused === 1 ? "it" : "they"} held something from your computer.` : ""),
    h("p", { class: "small muted" }, "Searches go through NanoGPT to the search provider. Only what's in the sandbox may be in them: the app refuses any search with something from your computer in it."));
}

function pickModel(title, provider, onPick) {
  const listEl = h("div", {}, h("div", { class: "muted" }, "Loading…"));
  const search = h("input", { type: "text", placeholder: "Filter… (opus, private, glm)", style: "width:100%;margin-bottom:6px" });
  let models = [];
  let m;
  const draw = () => {
    const q = search.value.trim().toLowerCase();
    listEl.replaceChildren(...models.filter((x) => !q || x.id.toLowerCase().includes(q)).slice(0, 300).map((x) =>
      h("div", { class: "list-item", style: "cursor:pointer", onclick: () => guarded(async () => { await onPick(x.id); m.close(); }) },
        h("div", { class: "grow mono" }, x.id), x.tier === "e2ee" ? h("span", { class: "chip private" }, "private") : x.tier === "tee" ? h("span", { class: "chip" }, "TEE") : null)));
  };
  search.addEventListener("input", draw);
  m = modal({ title, body: h("div", {}, search, listEl), buttons: [{ label: "Close" }] });
  api("GET", `/api/models?provider=${encodeURIComponent(provider)}`).then((r) => { models = r.models; draw(); })
    .catch((e) => listEl.replaceChildren(h("div", { class: "err" }, e.message)));
}

// ---- which of NanoGPT's hosts runs a model (llm/routes.py): any choice but NanoGPT's own is paid per use

const ROUTE_LABEL = { subscription: "NanoGPT's own choice", speed: "Fastest overall", latency: "Fastest to start answering",
  throughput: "Fastest writing", price: "Cheapest", host: "A host I choose" };
const ROUTE_TIP = {
  subscription: "NanoGPT picks the host: included in a NanoGPT subscription, but it can be slow.",
  speed: "The host that finishes an answer soonest, as NanoGPT measures it (what NanoGPT calls :fast).",
  latency: "The host that starts answering soonest.",
  throughput: "The host that writes the most a second.",
  price: "The cheapest host.",
  host: "One you know is reliable. If it's down, NanoGPT uses another rather than stop the assistant in the middle of its work.",
};
// a model NanoGPT sends as it is: not sealed (private), attested (TEE) or Claude, which only Anthropic runs
const routable = (model) => !!model && !/^(private\/|anthropic\/|claude)/i.test(model) && !/(^|\/)tee\/|^phala\/|[-:]tee$/i.test(model);
function routeText(r) {
  if (!r) return ROUTE_LABEL.subscription;
  return `${r.priority === "host" ? r.host_name || r.host : ROUTE_LABEL[r.priority]} · ${r.fp8 === false ? "any precision" : "FP8 or better"}`;
}
function routeRow(model) {
  const r = (S.state.config.settings.model_routes || {})[model];
  return h("div", { class: "row small" }, `Host for ${MODEL_NAME[model] || model}:`, h("span", {}, routeText(r)), r ? h("span", { class: "chip warn" }, "paid per use") : null,
    h("button", { class: "small", onclick: () => routeDialog(model) }, "Change…"));
}
const hostSecs = (ms) => (ms == null ? "?" : `${(ms / 1000).toFixed(ms < 10000 ? 1 : 0)} s`);
const hostPrice = (x) => (x == null ? "?" : `$${x.toFixed(2)}`);
function routeDialog(model) {
  const body = h("div", {}, h("div", { class: "muted" }, "Asking NanoGPT which hosts run it…"));
  const m = modal({ title: `Which host runs ${MODEL_NAME[model] || model}`, body, buttons: [{ label: "Cancel" }] });
  m.box.classList.add("wide");
  api("GET", `/api/models/hosts?model=${encodeURIComponent(model)}`).then((d) => {
    if (!d.supported) {
      body.replaceChildren(h("div", {}, `NanoGPT runs ${model} itself: there's no host to choose.`));
      return;
    }
    const cur = d.route || { priority: "subscription", fp8: true };
    let pick = cur.priority, host = cur.host || "";
    const fp8 = h("input", { type: "checkbox", checked: cur.fp8 !== false, onchange: () => draw() });
    const radios = {};
    const hostRows = h("tbody", {});
    const table = h("table", { class: "hosts" },
      h("thead", {}, h("tr", {}, ["", "Host", "Precision", "Keeps your prompts?", "Where", "First word", "Tokens/s", "In $/M", "Out $/M", "Caches"].map((c) => h("th", {}, c)))),
      hostRows);
    const hostBox = h("div", { class: "hostbox" }, table);
    const auto = d.auto || {};
    const draw = () => {
      for (const [k, el] of Object.entries(radios)) el.checked = k === pick;
      hostBox.classList.toggle("hidden", pick !== "host");
      fp8.disabled = pick === "subscription";
      if (fp8.checked && host && !d.hosts.find((x) => x.id === host)?.fp8) host = "";
      const hosts = [...d.hosts].sort((a, b) => (b.available - a.available) || ((b.tokens_per_second || 0) - (a.tokens_per_second || 0)));
      hostRows.replaceChildren(...hosts.filter((x) => (x.available && (x.fp8 || !fp8.checked)) || x.id === host).map((x) => {
        const choose = () => { host = x.id; draw(); };
        return h("tr", { class: `${x.id === host ? "chosen" : ""}${x.available ? "" : " off"}`, onclick: x.available ? choose : null },
          h("td", {}, h("input", { type: "radio", name: "routehost", checked: x.id === host, disabled: !x.available })),
          h("td", {}, x.name), h("td", {}, x.precision || "not said"), h("td", { class: x.keeps_nothing ? "" : "warn" }, x.privacy),
          h("td", {}, x.region || "not said"), h("td", {}, hostSecs(x.first_token_ms)), h("td", {}, x.tokens_per_second ?? "?"),
          h("td", {}, hostPrice(x.input)), h("td", {}, hostPrice(x.output)), h("td", {}, x.caches ? "yes" : "no"));
      }));
    };
    const option = (k) => h("label", { class: "radio" },
      radios[k] = h("input", { type: "radio", name: "routeprio", onchange: () => { pick = k; draw(); } }),
      h("div", {}, h("div", {}, ROUTE_LABEL[k], k === "subscription" ? "" : h("span", { class: "chip warn", style: "margin-left:6px" }, "paid per use")),
        h("div", { class: "small muted" }, ROUTE_TIP[k],
          k === "subscription" && auto.tokens_per_second ? ` Now: ${hostSecs(auto.first_token_ms)} to the first word, ${auto.tokens_per_second} tokens a second.` : "")));
    body.replaceChildren(
      h("div", { class: "small muted" }, `NanoGPT runs ${model} on ${d.hosts.filter((x) => x.available).length} hosts. The figures are NanoGPT's own, measured now; a model that thinks first takes longer to its first word.`),
      ...["subscription", "speed", "latency", "throughput", "price", "host"].map(option),
      h("label", { class: "radio" }, fp8, h("div", {}, h("div", {}, "Only hosts that run it at FP8 or better"),
        h("div", { class: "small muted" }, "Hosts at lower precision (FP4) are quicker but make more mistakes. Hosts that don't say their precision are left out too."))),
      hostBox,
      h("div", { class: "warnbox" }, h("b", {}, "Paid per use. "),
        "Any choice but NanoGPT's own is billed at the host's price, plus NanoGPT's small fee, even with a NanoGPT subscription. Set a spending limit on your key at nano-gpt.com."));
    draw();
    const bar = m.box.querySelector(".buttons");
    bar.append(h("button", { class: "primary", type: "button", onclick: () => guarded(async () => {
      if (pick === "host" && !host) throw new Error("Choose the host.");
      const r = await api("POST", "/api/models/route", { model, route: { priority: pick, fp8: fp8.checked, host } });
      toast(r.route ? `${MODEL_NAME[model] || model} now runs on: ${routeText(r.route)}. Paid per use.` : `NanoGPT chooses the host for ${MODEL_NAME[model] || model} again.`, "ok");
      m.close();
    }) }, "Save"));
  }).catch((e) => body.replaceChildren(h("div", { class: "err" }, e.message)));
}

const SEARCH_PROVIDERS = ["perplexity", "kagi", "valyu", "tavily", "linkup", "brave", "sofya", "firecrawl", "exa"];
const SEARCH_LABEL = { perplexity: "Perplexity (detailed, with sources)", kagi: "Kagi (accurate links)" };

function searchSelect(key, current) {
  return h("select", { onchange: (e) => guarded(async () => { await api("POST", "/api/settings", { [key]: e.target.value }); toast("Saved.", "ok", 2000); }) },
    SEARCH_PROVIDERS.map((v) => h("option", { value: v, selected: current === v }, SEARCH_LABEL[v] || v[0].toUpperCase() + v.slice(1))));
}

function appsSettings(s, save) {
  const homes = S.state.app_homes || {};
  const select = (key, options) => h("select", { onchange: (e) => save({ [key]: e.target.value }) },
    options.map(([v, label]) => h("option", { value: v, selected: (s[key] || options[0][0]) === v }, label)));
  const auto = homes.shelly ? "Shelly" : homes.gearlever ? "Gear Lever" : "your apps menu";
  return h("div", { class: "section" }, h("h3", {}, "Your apps"),
    h("div", { class: "field" }, h("span", {}, "Look for new versions of my apps"),
      select("check_every", [["day", "Every day"], ["week", "Every week"], ["month", "Every month"], ["manual", "Only when I ask"]]),
      h("span", { class: "small muted" }, "While the sandbox runs, it asks each app's official source for new releases. Each app can choose its own, in My apps.")),
    h("div", { class: "field" }, h("span", {}, "When there's a new version, summarise what's new"),
      select("changelog_summary", [["auto", "Straight away (a second opinion reads the change log)"], ["manual", "Only when I ask"]])),
    h("div", { class: "field" }, h("span", {}, "Build the new version with my changes"),
      select("rebuild", [["scheduled", "At a quiet time"], ["ask", "When I say so"], ["auto", "Straight away"]]),
      h("span", { class: "small muted" }, "Building uses a lot of your computer's power for a while, so it may be slower until it's done. When the assistant has to step in, that part is light on your computer.")),
    h("div", { class: "field" }, h("span", {}, "The quiet time to build at"),
      h("div", { class: "row" }, h("input", { type: "time", value: s.build_time || "03:00", onchange: (e) => e.target.value && save({ build_time: e.target.value }) })),
      h("span", { class: "small muted" }, "If your computer is off or asleep then, it's built at that time the next day, not when you start it.")),
    h("label", { class: "radio" }, h("input", { type: "checkbox", checked: !!s.build_on_battery, onchange: (e) => save({ build_on_battery: e.target.checked }) }),
      h("div", {}, h("div", {}, "Build on battery too"), h("div", { class: "small muted" }, "Off: a laptop on its battery waits until it's plugged in."))),
    h("div", { class: "field" }, h("span", {}, "Where installed apps live"),
      select("app_home", [["auto", `Automatic (${auto})`], ["gearlever", `Gear Lever${homes.gearlever ? "" : " (not installed)"}`],
        ["shelly", `Shelly${homes.shelly ? "" : " (not installed)"}`], ["menu", "Your apps menu (this app adds them)"]]),
      !homes.gearlever && !homes.shelly ? h("span", { class: "small muted" }, homes.flatpak
        ? "Tip: Gear Lever (from Flathub, in your Software Manager) keeps all your AppImages in one place. Once it's installed, apps built here go there."
        : "Apps built here are added to your apps menu.") : null));
}

// ------------------------------------------------------------------ backups

const fmtWhen = (ts) => new Date(ts * 1000).toLocaleString([], { day: "numeric", month: "short", hour: "numeric", minute: "2-digit" });

function passwordFields(confirm) {
  const pw = h("input", { type: "password", autocomplete: "new-password", placeholder: "At least 10 characters: a few words you'll remember" });
  const again = confirm ? h("input", { type: "password", autocomplete: "new-password", placeholder: "The same again" }) : null;
  const value = () => {
    if (pw.value.length < 10) throw new Error("The password needs at least 10 characters.");
    if (again && again.value !== pw.value) throw new Error("The two passwords aren't the same.");
    return pw.value;
  };
  return { el: h("div", { class: "pw" }, pw, again), value, focus: () => pw.focus() };
}

// a backup now: with the saved password, or one chosen here (and, if they like, saved for automatic ones)
async function backupNow() {
  const b = S.state.backups || {};
  const run = async (body) => {
    const out = await api("POST", "/api/backups", body);
    toast(`Backed up: ${fmtBytes(out.size)}, in ${b.folder}.`, "ok", 8000);
  };
  if (b.has_password) return guarded(() => run({}));
  const fields = passwordFields(true);
  const keep = h("input", { type: "checkbox", checked: true });
  modal({ title: "Choose a password for your backups", body: h("div", {},
    h("p", { class: "small" }, "Your backup holds your apps, your chats and your API key, so it's locked with a password. You need it to restore the backup, on this computer or another one."),
    h("div", { class: "warnbox" }, h("b", {}, "Keep it somewhere safe. "), "Nobody can open a backup without its password, not even us."),
    fields.el,
    h("label", { class: "radio" }, keep, h("div", {}, h("div", {}, "Remember it in my keyring"), h("div", { class: "small muted" }, "Needed for automatic backups.")))),
    buttons: [{ label: "Cancel" }, { label: "Back up now", kind: "primary", onClick: async () => { await run({ password: fields.value(), save_password: keep.checked }); } }] });
  setTimeout(fields.focus, 0);
}

function changePassword() {
  const fields = passwordFields(true);
  modal({ title: "A new password for your backups", body: h("div", {},
    h("p", { class: "small" }, "New backups use it. Backups you made before still open with the password they were made with."), fields.el),
    buttons: [{ label: "Cancel" }, { label: "Save it", kind: "primary", onClick: async () => { await api("POST", "/api/backups/password", { password: fields.value() }); toast("Saved in your keyring.", "ok", 3000); } }] });
  setTimeout(fields.focus, 0);
}

// restoring: a backup from the folder, or a file from elsewhere (another computer's); checked with its
// password first, then put in place of what's here once the user says so
function restoreBackup() {
  const found = (S.state.backups || {}).found || [];
  let chosen = found.length ? { name: found[0].name } : null;
  const file = h("input", { type: "file", accept: ".dvmbackup" });
  const label = h("span", { class: "small muted" }, "");
  const list = h("div", { class: "pick-app" },
    found.length ? h("div", { class: "small muted" }, "From your backup folder:") : null,
    found.slice(0, 8).map((f, i) => h("label", { class: "radio" }, h("input", { type: "radio", name: "bk", checked: i === 0, onchange: () => { chosen = { name: f.name }; } }),
      h("div", {}, h("div", {}, `${fmtWhen(f.at)}${f.auto ? " (automatic)" : ""}`), h("div", { class: "small muted" }, fmtBytes(f.size))))),
    h("div", { class: "small muted" }, found.length ? "Or a backup file from elsewhere (another computer, a USB drive):" : "Choose the backup file (from another computer, a USB drive…):"),
    h("div", { class: "row" }, file, label));
  file.addEventListener("change", () => { if (file.files[0]) { chosen = { upload: file.files[0] }; label.textContent = fmtBytes(file.files[0].size); for (const r of list.querySelectorAll("input[type=radio]")) r.checked = false; } });
  const pw = h("input", { type: "password", autocomplete: "current-password", placeholder: "The backup's password" });
  const which = async () => {
    if (!chosen) throw new Error("Choose a backup first.");
    if (chosen.name) return { name: chosen.name };
    if (!chosen.token) {
      label.textContent = "Reading it…";
      const res = await fetch("/api/restore/upload", { method: "POST", headers: { "X-Token": TOKEN }, body: chosen.upload });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || data.error || "The file couldn't be read.");
      chosen.token = data.file; label.textContent = fmtBytes(chosen.upload.size);
    }
    return { file: chosen.token };
  };
  modal({ title: "Restore a backup", body: h("div", {}, list, h("div", { class: "field" }, h("span", {}, "Its password"), pw)),
    buttons: [{ label: "Cancel" }, { label: "Next", kind: "primary", onClick: async () => {
      const body = { ...(await which()), password: pw.value };
      const m = await api("POST", "/api/restore/peek", body);
      confirmRestore(body, m);
    } }] });
}

function confirmRestore(body, m) {
  const here = (S.state.apps || []).length;
  modal({ title: "Restore this backup?", body: h("div", {},
    h("p", {}, `Made ${fmtWhen(m.created)}, with ${m.apps.length} app${m.apps.length === 1 ? "" : "s"} and ${m.chats} chat${m.chats === 1 ? "" : "s"}${m.keys?.length ? ", and your API key" : ""}.`),
    m.apps.length ? h("ul", { class: "small" }, m.apps.map((a) => h("li", {}, a.name, a.changes?.length ? h("span", { class: "muted" }, `: ${a.changes.join(", ")}`) : null))) : null,
    h("div", { class: "warnbox" }, here || (S.state.chat || []).length
      ? "It takes the place of the apps and chats here now. Those aren't deleted: they're moved to a folder of their own, next to the app's data, in case you need them."
      : "It brings back your apps, your chats and your settings. This computer keeps its own: where apps are installed, and the sandbox's size."),
    h("p", { class: "small muted" }, "Afterwards your apps are ready to install, without building them again.")),
    buttons: [{ label: "Cancel" }, { label: "Restore it", kind: "primary", onClick: async () => restored(await api("POST", "/api/restore", body)) }] });
}

function restored(out) {
  const ready = () => (S.state.apps || []).map((a) => (S.state.deliveries || []).find((d) => d.app === a.id && d.status === "new" && d.kind === "appimage")).filter(Boolean);
  modal({ title: "Your apps are back", body: h("div", {},
    h("p", {}, `${out.apps.length} app${out.apps.length === 1 ? "" : "s"} and ${out.chats} chat${out.chats === 1 ? "" : "s"} were restored. Your apps are ready to install: they don't need building again.`),
    out.aside ? h("p", { class: "small muted" }, `What was here before is kept in ${out.aside}.`) : null,
    out.sessions ? null : h("p", { class: "small muted" }, "Your old chats are all there to read. The assistant's own memory of them wasn't in the backup (the sandbox wasn't running then), so if you carry one on, it starts afresh.")),
    buttons: [{ label: "Later" }, { label: "Install them all", kind: "primary", onClick: async () => {
      let n = 0;
      for (const d of ready()) { await api("POST", `/api/deliveries/${d.id}/install`); n++; }
      toast(n ? `Installed ${n} app${n === 1 ? "" : "s"}.` : "There was nothing to install.", "ok", 6000);
    } }] });
}

function backupSettings(s, save) {
  const b = S.state.backups || {};
  const folder = h("input", { type: "text", value: s.backup_dir || "" });
  const last = b.last ? `Last backup: ${fmtWhen(b.last.at)} (${fmtBytes(b.last.size)}${b.last.auto ? ", automatic" : ""}).` : "No backup yet.";
  return h("div", { class: "section" }, h("h3", {}, "Backups"),
    h("div", { class: "small muted" }, "Your apps exist only here and in the sandbox. A backup holds everything needed to restore them on this computer or another one: your apps and their changes, the installed version of each, your chats, settings and API key, locked with your password."),
    b.running ? h("div", { class: "small row" }, h("span", { class: "spinner" }), b.running.what === "restore" ? "Restoring…" : "Backing up…")
      : h("div", { class: "small" }, last),
    b.error ? h("div", { class: "warnbox small" }, `The last ${b.error.auto ? "automatic " : ""}backup failed: ${b.error.text}`) : null,
    h("div", { class: "actions" },
      h("button", { class: "small primary", disabled: !!b.running, onclick: backupNow }, "Back up now"),
      h("button", { class: "small", disabled: !!b.running, onclick: restoreBackup }, "Restore…"),
      h("button", { class: "small ghost", onclick: () => guarded(() => api("POST", "/api/backups/open-folder")) }, "Open the folder")),
    h("div", { class: "field" }, h("span", {}, "Back up automatically"),
      h("select", { onchange: (e) => save({ backup_auto: e.target.value }) },
        [["off", "Never"], ["day", "Every day"], ["week", "Every week"], ["change", "After each new app or change"]].map(([v, l]) => h("option", { value: v, selected: s.backup_auto === v }, l))),
      s.backup_auto !== "off" && !b.has_password ? h("span", { class: "small warn" }, "Choose a password first (Back up now): automatic backups need it in your keyring.") : null,
      h("span", { class: "small muted" }, `The newest ${s.backup_keep || 5} automatic backups are kept.`)),
    h("div", { class: "field" }, h("span", {}, "Back up to"),
      h("div", { class: "row" }, folder, h("button", { class: "small", onclick: () => save({ backup_dir: folder.value.trim() }) }, "Save")),
      h("span", { class: "small muted" }, "A USB drive, or a folder your cloud storage keeps (Dropbox, Nextcloud…), keeps them safe if this computer fails.")),
    b.has_password ? h("div", { class: "small" }, "Your backup password is in your keyring. ",
      h("button", { class: "small ghost", onclick: changePassword }, "Change it"),
      h("button", { class: "small ghost", onclick: () => guarded(async () => {
        if (!(await confirmModal("Forget the backup password?", "Automatic backups stop until you choose one again. Backups you have still open with it.", "Forget it"))) return;
        await api("POST", "/api/backups/password", { password: "" }); }) }, "Forget it")) : null);
}

// what the assistant is told about this computer in every chat, each part with exactly what it says
function aboutSettings(s, save) {
  const on = new Set(s.share_about || []);
  const part = (key, label, desc) => {
    const shows = h("pre", { class: "about-preview small" }, "…");
    api("GET", `/api/about-computer?parts=${key}`).then((r) => { shows.textContent = r.text || "(nothing found)"; })
      .catch((e) => { shows.textContent = e.message; });
    return h("label", { class: "radio" },
      h("input", { type: "checkbox", checked: on.has(key), onchange: (e) => {
        if (e.target.checked) on.add(key); else on.delete(key);
        save({ share_about: [...on] }, e.target.checked ? "It gets this in your next message." : "It won't get this in new chats.");
      } }),
      h("div", {}, h("div", {}, label), h("div", { class: "small muted" }, desc), shows));
  };
  return h("div", { class: "section" }, h("h3", {}, "What the assistant always knows"),
    h("div", { class: "small muted" }, "So it needn't ask in every chat. This app reads it from your computer and sends it with your first message in each chat; nothing else of yours goes with it, and it's never used in a web search."),
    part("system", "Your system", "Which Linux and version, your desktop, and the app formats you can use."),
    part("hardware", "Your hardware", "Processor, memory and graphics."));
}

function settingsPanel() {
  const st = S.state, s = st.config.settings;
  const save = (body, msg = "Saved.") => guarded(async () => { await api("POST", "/api/settings", body); toast(msg, "ok", 2000); });
  const radio = (name, value, current, label, desc, onpick) => h("label", { class: "radio" },
    h("input", { type: "radio", name, value, checked: current === value, onchange: onpick }), h("div", {}, h("div", {}, label), desc ? h("div", { class: "small muted" }, desc) : null));
  const nano = st.config.providers.find((p) => p.base_url && p.builder_url) || st.config.providers[0];
  const key = h("input", { type: "password", placeholder: nano?.has_key ? "Key stored. Paste a new one to replace it" : "Your NanoGPT API key", autocomplete: "off" });
  const model = h("input", { type: "text", class: "mono", value: s.builder_model });
  const small = h("input", { type: "text", class: "mono", value: s.builder_small_model, placeholder: "empty = the same model" });
  const vision = h("input", { type: "text", class: "mono", value: s.builder_vision_model, placeholder: "for models that can't see images" });
  const preset = { "z-ai/glm-5.3": "glm", "private/glm-5-3": "private", "anthropic/claude-opus-5.5": "claude" }[s.builder_model] || "custom";
  const pickInto = (input, title) => nano?.base_url ? h("button", { class: "small", onclick: () => pickModel(title, nano.name, async (id) => { input.value = id; }) }, "Choose…") : null;
  const customBox = h("div", { class: preset === "custom" ? "" : "hidden" },
    h("div", { class: "field" }, h("span", {}, "Model"), h("div", { class: "row" }, model, pickInto(model, "The assistant's model"))),
    h("div", { class: "field" }, h("span", {}, "For quick background tasks"), h("div", { class: "row" }, small, pickInto(small, "Quick tasks"))),
    h("div", { class: "field" }, h("span", {}, "Describes images to private models"), h("div", { class: "row" }, vision, pickInto(vision, "Vision helper"))),
    h("button", { class: "small", onclick: () => save({ builder_model: model.value.trim(), builder_small_model: small.value.trim(), builder_vision_model: vision.value.trim() }) }, "Save"));
  const reviewer = s.review_model ? s.review_model.split("|")[1] : "";
  const timeout = h("input", { type: "number", min: 5, max: 1800, value: s.command_timeout, style: "width:90px" });
  const mem = h("input", { type: "text", value: s.container_memory, style: "width:80px" });
  const cpus = h("input", { type: "text", value: s.container_cpus, style: "width:60px" });
  const dir = h("input", { type: "text", value: s.install_dir });
  return [
    h("div", { class: "section" }, h("h3", {}, "When the assistant runs something on your computer"),
      h("div", { class: "small muted" }, "It always asks first, and nothing runs until you click Run. Then, what it printed:"),
      radio("out", "review", s.output_mode, "Show it to me first (recommended)", "You read it and send it, or keep it private.", () => save({ output_mode: "review" })),
      radio("out", "auto", s.output_mode, "Send it straight away", "Passwords and keys are blanked out first, and anything that looks private still waits for you. You can always see what was sent.", () => save({ output_mode: "auto" })),
      h("div", { class: "row small" }, "Stop a command after", timeout, "seconds",
        h("button", { class: "small", onclick: () => save({ command_timeout: Number(timeout.value) }) }, "Save"))),
    aboutSettings(s, save),
    h("div", { class: "section" }, h("h3", {}, "Second opinions"),
      h("div", { class: "small muted" }, "A separate AI, outside the sandbox, reads the commands the assistant wants to run on your computer, before you decide."),
      radio("so", "changes", s.second_opinion, "On anything that changes your computer", null, () => save({ second_opinion: "changes" })),
      radio("so", "all", s.second_opinion, "On every command", null, () => save({ second_opinion: "all" })),
      radio("so", "off", s.second_opinion, "Only when I ask", null, () => save({ second_opinion: "off" })),
      h("div", { class: "row small" }, "Reviewer: ", h("span", { class: "mono" }, reviewer || "not set"), reviewer.startsWith("private/") ? h("span", { class: "chip private" }, "private") : null,
        nano?.base_url ? h("button", { class: "small", onclick: () => pickModel("Reviewer", nano.name, (id) => api("POST", "/api/settings", { review_model: `${nano.name}|${id}` })) }, "Change") : null)),
    h("div", { class: "section" }, h("h3", {}, "The assistant"),
      h("div", { class: "small muted" }, "The AI you talk to. It works in its sandbox, through NanoGPT. Any NanoGPT model works (Something else); these are the usual choices."),
      radio("am", "glm", preset, "GLM 5.3", "Included with a NanoGPT subscription. Screenshots are described to it by GLM 5.3 Flash.",
        () => save({ builder_model: "z-ai/glm-5.3", builder_small_model: "z-ai/glm-5.3-flash", builder_vision_model: "z-ai/glm-5.3-flash" }, "The assistant now uses GLM 5.3.")),
      radio("am", "private", preset, "Private GLM 5.3",
        "End-to-end encrypted: only an attested enclave can read what it sees. Paid per use.",
        () => save({ builder_model: "private/glm-5-3", builder_small_model: "private/glm-5-3-flash", builder_vision_model: "private/glm-5-3-flash" }, "The assistant now uses private GLM 5.3.")),
      radio("am", "claude", preset, "Claude Opus 5.5", "The strongest, especially for building apps. Paid per use; NanoGPT passes what it sees to Anthropic.",
        () => save({ builder_model: "anthropic/claude-opus-5.5", builder_small_model: "" }, "The assistant now uses Claude Opus 5.5.")),
      radio("am", "custom", preset, "Something else", null, () => { customBox.classList.remove("hidden"); }),
      customBox,
      !/^(anthropic\/|claude)/i.test(s.builder_model) ? h("div", { class: "row small" }, "How hard it thinks:",
        h("select", { onchange: (e) => save({ builder_reasoning: e.target.value }) },
          ["low", "medium", "high"].map((v) => h("option", { value: v, selected: s.builder_reasoning === v }, { low: "Low (fast; recommended)", medium: "Medium", high: "High (slow)" }[v])))) : null,
      nano?.base_url && /nano-gpt\.com/i.test(nano.base_url) && routable(s.builder_model) ? routeRow(s.builder_model) : null,
      nano?.base_url && /nano-gpt\.com/i.test(nano.base_url) && s.builder_small_model && s.builder_small_model !== s.builder_model && routable(s.builder_small_model)
        ? routeRow(s.builder_small_model) : null,
      h("div", { class: "warnbox" }, h("b", {}, "Mind the cost. "), COST_NOTE),
      h("div", { class: "field" }, h("span", {}, "NanoGPT API key"), h("div", { class: "row" }, key,
        h("button", { class: "small", onclick: () => guarded(async () => { if (!key.value.trim()) return; await api("POST", "/api/setup", { api_key: key.value }); key.value = ""; toast("Key saved.", "ok"); }) }, "Save")))),
    h("div", { class: "section" }, h("h3", {}, "Web searches"),
      h("label", { class: "radio" }, h("input", { type: "checkbox", checked: s.web_search !== false, onchange: (e) => save({ web_search: e.target.checked }) }),
        h("div", {}, h("div", {}, "Let the assistant search the web"), h("div", { class: "small muted" },
          "To learn how to do things and find what's already been built, for example a version of an app that already has the feature you want. It searches with what's in its sandbox only: the app refuses any search with something from your computer in it. NanoGPT charges a little per search."))),
      h("div", { class: "row small" }, "To learn things:", searchSelect("search_provider", s.search_provider)),
      h("div", { class: "row small" }, "To find official sites:", searchSelect("search_links_provider", s.search_links_provider))),
    appsSettings(s, save),
    backupSettings(s, save),
    h("div", { class: "section" }, h("h3", {}, "This app"),
      h("div", { class: "row small" }, "Colours:",
        h("select", { onchange: (e) => { applyTheme(e.target.value); save({ theme: e.target.value }, "Saved."); } },
          [["dark", "Dark"], ["light", "Light"], ["system", "Match my system"]].map(([v, label]) => h("option", { value: v, selected: (s.theme || "dark") === v }, label)))),
      h("label", { class: "radio" }, h("input", { type: "checkbox", checked: st.autostart, onchange: (e) => save({ autostart: e.target.checked }, e.target.checked ? "It will start with your computer, in the tray." : "It won't start by itself.") }),
        h("div", {}, "Start with my computer (in the tray)")),
      h("div", { class: "field" }, h("span", {}, "Install apps it builds to"), h("div", { class: "row" }, dir, h("button", { class: "small", onclick: () => save({ install_dir: dir.value.trim() }) }, "Save")))),
    h("div", { class: "section" }, h("h3", {}, "The sandbox"),
      h("div", { class: "row small" }, "Memory", mem, "CPUs", cpus, h("button", { class: "small", onclick: () => guarded(async () => {
        const out = await api("POST", "/api/settings", { container_memory: mem.value.trim(), container_cpus: cpus.value.trim() });
        toast(out.limits === "now" ? "Saved: the sandbox has them now." : "Saved: the sandbox gets them when it next starts.", "ok", 3000); }) }, "Save")),
      h("p", { class: "small muted" }, "Resetting starts the sandbox afresh, clearing out what has built up in it: its downloads, installed tools and builds are deleted, and fetched or made again as they're needed, so things take longer for a while. The assistant remembers your chats, and your apps, their changes, the builds you have and your backups aren't touched. Only work the assistant hasn't delivered yet is lost."),
      h("button", { class: "small danger", onclick: () => guarded(async () => {
        if (!(await confirmModal("Reset the sandbox?", "Its downloads, tools and builds are deleted, and come back as they're needed. The assistant remembers your chats and carries on. Work it hasn't delivered yet is lost. Your apps and backups aren't touched.", "Reset", "danger"))) return;
        await api("POST", "/api/workspace/reset"); toast("The sandbox is starting afresh.", "ok"); }) }, "Reset the sandbox…")),
    h("div", { class: "small muted", style: "text-align:center" }, `${st.computer.os} · ${st.computer.desktop}`),
  ];
}

// ------------------------------------------------------------------ composer & wiring

function autosize() {
  const ta = $("#input");
  ta.style.height = "auto";
  ta.style.height = `${Math.min(ta.scrollHeight, 160)}px`;
  if (S.state) renderStatus();
}

async function send(ev) {
  ev?.preventDefault();
  const message = $("#input").value.trim();
  if (S.files.some((f) => f.uploading)) { toast("Wait a moment: the files are still being added.", "info", 3000); return; }
  const files = S.files.filter((f) => f.id);
  if (!message && !files.length) return;
  await guarded(async () => {
    await api("POST", "/api/send", { message, attachments: files.map((f) => f.id) });
    $("#input").value = "";
    for (const f of files) if (f.url) URL.revokeObjectURL(f.url);
    S.files = S.files.filter((f) => !files.includes(f));
    renderFiles();
    autosize();
  });
}

// ---- files the user attaches: added at once (a picture is cleaned of its hidden details there),
// put into the sandbox with the message they go with

function filesEl(files) {
  if (!files?.length) return null;
  return h("div", { class: "msg-files" }, files.map((f) => (f.kind === "image"
    ? authImg(`/api/attachments/${encodeURIComponent(f.id)}`)
    : h("span", { class: "chip", title: f.path }, `📄 ${f.name} · ${fmtBytes(f.size)}`))));
}

function renderFiles() {
  const box = $("#attachments");
  box.classList.toggle("hidden", !S.files.length);
  box.replaceChildren(...S.files.map((f) => h("div", { class: `attachment${f.uploading ? " uploading" : ""}`, title: f.name },
    f.url ? h("img", { src: f.url, alt: "" }) : h("span", {}, "📄"),
    h("span", { class: "fname" }, f.name),
    h("span", { class: "small muted" }, f.uploading ? "adding…" : fmtBytes(f.size)),
    h("button", { type: "button", class: "icon-btn x", title: "Remove", onclick: () => removeFile(f) }, "×"))));
  if (S.state) renderStatus();
}

async function addFiles(list) {
  for (const file of list) {
    if (S.files.length >= 10) { toast("At most 10 files with one message.", "error"); break; }
    const f = { name: file.name || "pasted-picture.png", size: file.size, uploading: true,
      url: file.type.startsWith("image/") ? URL.createObjectURL(file) : null };
    S.files.push(f);
    renderFiles();
    try {
      const res = await fetch("/api/attachments", { method: "POST", body: file,
        headers: { "X-Token": TOKEN, "X-Filename": encodeURIComponent(f.name), "Content-Type": "application/octet-stream" } });
      let data = {};
      try { data = await res.json(); } catch { /* empty */ }
      if (!res.ok) throw new Error(data.error || `${res.status} ${res.statusText}`);
      if (!S.files.includes(f)) { api("DELETE", `/api/attachments/${data.id}`).catch(() => {}); continue; }   // removed meanwhile
      Object.assign(f, data, { uploading: false });
    } catch (e) {
      S.files = S.files.filter((x) => x !== f);
      if (f.url) URL.revokeObjectURL(f.url);
      toast(e.message, "error");
    }
    renderFiles();
  }
}

function removeFile(f) {
  S.files = S.files.filter((x) => x !== f);
  if (f.url) URL.revokeObjectURL(f.url);
  if (f.id) api("DELETE", `/api/attachments/${f.id}`).catch(() => {});
  renderFiles();
}

function wireFiles() {
  const input = $("#file-input");
  $("#attach-btn").addEventListener("click", () => input.click());
  input.addEventListener("change", () => { addFiles([...input.files]); input.value = ""; });
  $("#input").addEventListener("paste", (e) => {
    const files = [...(e.clipboardData?.files || [])];
    if (files.length) { e.preventDefault(); addFiles(files); }
  });
  const hasFiles = (e) => [...(e.dataTransfer?.types || [])].includes("Files");
  let depth = 0;
  document.addEventListener("dragenter", (e) => { if (hasFiles(e)) { depth++; document.body.classList.add("dropping"); } });
  document.addEventListener("dragleave", (e) => { if (hasFiles(e) && --depth <= 0) { depth = 0; document.body.classList.remove("dropping"); } });
  document.addEventListener("dragover", (e) => { if (hasFiles(e)) e.preventDefault(); });
  document.addEventListener("drop", (e) => {
    if (!hasFiles(e)) return;
    e.preventDefault();
    depth = 0;
    document.body.classList.remove("dropping");
    if (S.state?.ready && !S.panel) addFiles([...e.dataTransfer.files]);
  });
}

function hideMenu() { $("#menu").classList.add("hidden"); }

function init() {
  $("#composer").addEventListener("submit", send);
  $("#input").addEventListener("input", autosize);
  $("#input").addEventListener("keydown", (e) => { if (e.key === "Enter" && !e.shiftKey && !e.isComposing) send(e); });
  $("#stop-btn").addEventListener("click", () => guarded(() => api("POST", "/api/stop")));
  wireFiles();
  $("#new-btn").addEventListener("click", () => guarded(() => api("POST", "/api/chats/new")));
  $("#menu-btn").addEventListener("click", (e) => { e.stopPropagation(); $("#menu").classList.toggle("hidden"); });
  document.addEventListener("click", (e) => { if (!e.target.closest(".menu")) hideMenu(); });
  $("#menu").addEventListener("click", (e) => {
    const a = e.target.closest("button")?.dataset.act;
    hideMenu();
    if (a === "quit") {
      guarded(async () => {
        if (!(await confirmModal("Quit DA Vibe Manager?", "The assistant stops until you start the app again.", "Quit", "danger"))) return;
        await api("POST", "/api/quit");
        document.body.replaceChildren(h("div", { class: "quit-note" }, h("h2", {}, "DA Vibe Manager has quit."), h("p", {}, "You can close this window.")));
      });
    } else if (a) openPanel(a);
  });
  $("#panel-back").addEventListener("click", closePanel);
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && S.panel && !document.querySelector(".overlay")) closePanel();
  });
  if (DESKTOP) document.body.classList.add("desktop");
  connect();
}

init();
