"use strict";
// The window itself in a real DOM (tests/js/page.cjs): how the page takes its token, what it says when it can't be
// used or loses its connection, its dialogs and the keyboard, and what the chat shows around a turn. The server's
// side of the launch is tests/test_server.py.

const { test } = require("node:test");
const assert = require("node:assert/strict");
const { skip, STATE, withPage, plain } = require("./page.cjs");

const sockets = (page) => page.run("__sockets").filter((s) => s.url.includes("/ws/events"));

test("the token is read from the fragment of the address printed to open by hand, and the address is cleared", { skip }, () => withPage(async (page) => {
  assert.equal(page.run("TOKEN"), "from-the-fragment");
  assert.equal(page.w.location.href, "http://127.0.0.1:48599/");
  assert.match(sockets(page)[0].url, /\?t=from-the-fragment$/);
}, {}, "http://127.0.0.1:48599/#t=from-the-fragment"));

test("the app window's address still gives the token in its query", { skip }, () => withPage(async (page) => {
  assert.equal(page.run("TOKEN"), "tok");
  assert.equal(page.run("DESKTOP"), false);
}));

test("an address with no token says so in place of the page, and opens no socket", { skip }, () => withPage(async (page) => {
  assert.match(page.d.body.textContent, /DA Vibe Manager isn't open in this page\..*carries no access token/s);
  assert.equal(sockets(page).length, 0);
}, {}, "http://127.0.0.1:48599/"));

test("a token the server refuses ends with a message in place of the page, not a page left on Starting… for ever", { skip }, () => withPage(async (page) => {
  sockets(page)[0].onclose();
  assert.match(page.d.querySelector("#conn-banner").textContent, /connection to DA Vibe Manager is lost/);
  await page.tick(1700);                     // the next try: the token is tried on a small request first
  assert.match(page.d.body.textContent, /refused this page's access token/);
  assert.equal(sockets(page).length, 1);     // and nothing more is tried
}, { "GET /api/state": { __status: 403, error: "bad token" } }));

test("a lost connection shows a banner until the socket is back, and a server not answering is tried again", { skip }, () => withPage(async (page) => {
  await page.event({ type: "state", state: STATE });
  page.w.__down = true;
  sockets(page)[0].onclose();
  const banner = page.d.querySelector("#conn-banner");
  assert.ok(!banner.classList.contains("hidden"));
  await page.tick(1700);
  assert.equal(sockets(page).length, 1);     // not answering: not yet
  page.w.__down = false;
  await page.tick(1700);
  assert.equal(sockets(page).length, 2);
  sockets(page)[1].onopen();
  assert.ok(banner.classList.contains("hidden"));
}));

test("the menu before the first state opens nothing, and throws nothing", { skip }, () => withPage(async (page) => {
  page.run('openPanel("settings")');
  assert.ok(page.d.querySelector("#panel").classList.contains("hidden"));
}));

test("a copy that fails says so, never Copied.", { skip }, () => withPage(async (page) => {
  const state = structuredClone(STATE);
  state.ready = true;
  state.chat = [{ kind: "assistant", parts: [{ t: "text", text: "Copy me" }], at: 1 }];
  await page.event({ type: "state", state });
  page.d.execCommand = () => false;          // nothing can be copied here (jsdom has no clipboard either)
  [...page.d.querySelectorAll("#chat button")].find((b) => b.textContent === "Copy").click();
  await page.tick(50);
  const toasts = [...page.d.querySelectorAll("#toasts .toast")].map((t) => t.className + ": " + t.textContent);
  assert.equal(toasts.length, 1);
  assert.match(toasts[0], /error: Nothing was copied/);
}));

// ---- dialogs and the keyboard

function withProviders(names) {
  const state = structuredClone(STATE);
  state.ready = true;
  state.config.providers = names.map((name) => ({ name, base_url: "https://example.org/v1", builder_url: "", builder_auth: "bearer",
    has_key: true, key_for: ["https://example.org:443"], service: "" }));
  return state;
}
const dialogs = (page) => [...page.d.querySelectorAll("#modal-root .modal")];
const key = (page, el, k, extra = {}) => el.dispatchEvent(new page.w.KeyboardEvent("keydown", { key: k, bubbles: true, cancelable: true, ...extra }));
const rowButton = (page, name, label) => [...[...page.d.querySelectorAll("#settings-providers .list-item")]
  .find((r) => r.querySelector("b")?.textContent === name).querySelectorAll("button")].find((b) => b.textContent === label);

test("a dialog takes the focus as it opens, so Enter can't open it again over itself", { skip }, () => withPage(async (page) => {
  await page.event({ type: "state", state: withProviders(["One", "Two"]) });
  page.run('openPanel("settings")');
  const remove = rowButton(page, "Two", "Remove");
  remove.focus();
  remove.click();
  await page.tick(60);
  const box = dialogs(page)[0];
  assert.equal(dialogs(page).length, 1);
  assert.ok(box.contains(page.d.activeElement), "the focus is in the dialog");
  assert.equal(box.getAttribute("role"), "dialog");
  assert.equal(box.getAttribute("aria-label"), "Remove this provider?");
  key(page, page.d.activeElement, "Enter");
  await page.tick(60);
  assert.equal(dialogs(page).length, 1);                    // until Nov 2026: a second one, then a third
  assert.equal(plain(page.calls().filter((c) => c.method === "DELETE")).length, 0);
  page.d.querySelector("#panel-back").focus();              // the focus wandering out comes back
  assert.ok(box.contains(page.d.activeElement));
  key(page, page.d.body, "Tab");
  assert.ok(box.contains(page.d.activeElement));
  key(page, page.d.body, "Escape");
  await page.tick();
  assert.equal(dialogs(page).length, 0);
  assert.equal(page.d.activeElement, remove);               // back where it was
  assert.ok(!page.d.querySelector("#panel").classList.contains("hidden"));   // Escape closed the dialog, not Settings
}));

test("Escape closes the top dialog of two, and the focus goes back to the one under it", { skip }, () => withPage(async (page) => {
  await page.event({ type: "state", state: withProviders(["One"]) });
  page.run('modal({ title: "Under", body: "", buttons: [{ label: "Close" }] })');
  await page.tick(60);
  page.run('confirmModal("Over", "?")');
  await page.tick(60);
  key(page, page.d.body, "Escape");
  await page.tick();
  assert.deepEqual(dialogs(page).map((d) => d.getAttribute("aria-label")), ["Under"]);
  assert.ok(dialogs(page)[0].contains(page.d.activeElement));
}));

test("a half-filled provider form asks before Escape or a click outside discards it", { skip }, () => withPage(async (page) => {
  await page.event({ type: "state", state: withProviders(["One"]) });
  page.run('openPanel("settings")');
  rowButton(page, "One", "Edit").click();
  await page.tick(60);
  const form = dialogs(page)[0];
  assert.equal(page.d.activeElement, form.querySelector("input"));          // its first field
  const name = form.querySelector("input");
  name.value = "A name typed with care";
  name.dispatchEvent(new page.w.Event("input", { bubbles: true }));
  const overlay = form.parentElement;
  overlay.dispatchEvent(new page.w.MouseEvent("mousedown", { bubbles: true }));
  await page.tick();
  assert.deepEqual(dialogs(page).map((d) => d.getAttribute("aria-label")), ["Edit One", "Close without saving?"]);
  [...dialogs(page)[1].querySelectorAll("button")].find((b) => b.textContent === "Cancel").click();
  await page.tick();
  assert.deepEqual(dialogs(page).map((d) => d.getAttribute("aria-label")), ["Edit One"]);
  assert.equal(name.value, "A name typed with care");
  key(page, page.d.body, "Escape");
  await page.tick();
  assert.equal(dialogs(page).length, 2);
  [...dialogs(page)[1].querySelectorAll("button")].find((b) => b.textContent === "Discard it").click();
  await page.tick();
  assert.equal(dialogs(page).length, 0);
  assert.equal(plain(page.calls().filter((c) => c.path === "/api/providers")).length, 0);
}));

test("a dialog with nothing typed in it closes on Escape or a click outside without asking", { skip }, () => withPage(async (page) => {
  await page.event({ type: "state", state: withProviders(["One"]) });
  page.run('openPanel("settings")');
  rowButton(page, "One", "Edit").click();
  await page.tick(60);
  dialogs(page)[0].parentElement.dispatchEvent(new page.w.MouseEvent("mousedown", { bubbles: true }));
  await page.tick();
  assert.equal(dialogs(page).length, 0);
}));
