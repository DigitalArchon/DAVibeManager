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
