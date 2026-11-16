"use strict";
// The page in a real DOM, for the window's tests: index.html, marked, DOMPurify and app.js loaded into jsdom (fetch
// and the events socket are stand-ins), fed a snapshot of a real Engine (tests/test_frontend.py writes it). Ported
// from DA Toolkit's tests/js/sanitize.test.cjs (bdbd4ce). jsdom is not one of this repository's packages: the tests
// are skipped where it isn't installed. To run them, put a jsdom on Node's path:
// NODE_PATH=<a node_modules with jsdom> .venv/bin/python -m pytest tests/test_frontend.py

const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const WEB = path.join(__dirname, "..", "..", "src", "davibemanager", "web");

let JSDOM = null;
try { ({ JSDOM } = require("jsdom")); } catch { /* not installed: skipped */ }
const skip = JSDOM ? false : "jsdom isn't installed";
const STATE = JSDOM ? JSON.parse(fs.readFileSync(process.env.DVM_STATE, "utf8")) : {};

// `replies`: what the stand-in fetch answers for a path ("GET /api/models"), any other call {}
function load(replies = {}) {
  const html = fs.readFileSync(path.join(WEB, "index.html"), "utf8").replace(/<script[^>]*><\/script>/g, "")
    .replace(/<link[^>]*>/g, "").replace(/<meta http-equiv[^>]*>/, "");
  const dom = new JSDOM(html, { url: "http://127.0.0.1:48599/?t=tok", runScripts: "outside-only", pretendToBeVisual: true });
  const ctx = dom.getInternalVMContext();
  const run = (code, filename = "test.js") => new vm.Script(code, { filename }).runInContext(ctx);
  run(`
    var __calls = [], __sockets = [], __replies = ${JSON.stringify(replies)};
    window.fetch = async (url, opts = {}) => {
      const call = { path: String(url).split("?")[0], query: String(url).split("?")[1] || "", method: opts.method || "GET",
        body: typeof opts.body === "string" ? JSON.parse(opts.body) : undefined };
      __calls.push(call);
      const reply = __replies[call.method + " " + call.path] ?? {};
      return { ok: true, status: 200, statusText: "OK", json: async () => reply, blob: async () => new Blob([]), headers: { get: () => null } };
    };
    window.WebSocket = class { constructor(url) { this.url = url; this.readyState = 1; this.sent = []; __sockets.push(this); }
      send(d) { this.sent.push(d); } close() { this.readyState = 3; } };
    WebSocket.OPEN = 1;
    window.ResizeObserver = class { observe() {} unobserve() {} disconnect() {} };
    if (!window.CSS) window.CSS = {};
    if (!CSS.escape) CSS.escape = (s) => s;
    window.requestAnimationFrame = (fn) => setTimeout(fn, 0);
  `);
  for (const file of ["vendor/marked.min.js", "vendor/purify.min.js", "app.js"]) run(fs.readFileSync(path.join(WEB, file), "utf8"), file);
  const w = dom.window;
  const tick = (ms = 20) => new Promise((resolve) => setTimeout(resolve, ms));
  return { w, run, tick, d: w.document, calls: () => run("__calls"),
    event: async (ev) => { run("__sockets").find((s) => s.url.includes("/ws/events")).onmessage({ data: JSON.stringify(ev) }); await tick(); },
    close: () => w.close() };
}

// the page's timers end with its window, so a failed assertion doesn't leave the run waiting on them
async function withPage(fn, replies) {
  const page = load(replies);
  try { await fn(page); } finally { page.close(); }
}
const plain = (x) => JSON.parse(JSON.stringify(x));     // a value of the page's realm, comparable here

module.exports = { skip, STATE, load, withPage, plain };
