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
