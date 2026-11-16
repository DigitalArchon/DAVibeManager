"use strict";
// Settings → AI providers in a real DOM (tests/js/page.cjs), on a real Engine's snapshot: the Add buttons come from
// the server's table, a provider's form asks the key questions the server's machinery keeps the answers to (a saved
// key at a new address, No the default and kept; a key over plain http to another machine, No saving nothing), an
// address typed by hand is recognised, and the assistant's usual models follow its provider's service. The server's
// side is tests/test_providers.py.

const { test } = require("node:test");
const assert = require("node:assert/strict");
const { skip, STATE, withPage, plain } = require("./page.cjs");

const NANO = "https://nano-gpt.com/api/v1";

function stateWith(providers, settings = {}) {
  const state = structuredClone(STATE);
  state.ready = true;
  state.config.providers = providers;
  Object.assign(state.config.settings, settings);
  return state;
}
const buttons = (root) => [...root.querySelectorAll("button")];
const button = (root, text) => {
  const found = buttons(root).find((b) => b.textContent.trim() === text);
  assert.ok(found, `no "${text}" button among ${JSON.stringify(buttons(root).map((b) => b.textContent))}`);
  return found;
};
const dialogs = (page) => [...page.d.querySelectorAll("#modal-root .modal")];
const top = (page) => dialogs(page).at(-1);
const field = (box, label) => {
  const f = [...box.querySelectorAll(".field")].find((x) => x.querySelector("span")?.textContent.startsWith(label));
  assert.ok(f, `no field "${label}"`);
  return f.querySelector("input, select");
};
function type(page, input, value) {
  input.value = value;
  input.dispatchEvent(new page.w.Event("input", { bubbles: true }));
}
async function settle(page, n = 4) { for (let i = 0; i < n; i++) await page.tick(); }
async function openSettings(page, state) {
  await page.event({ type: "state", state });
  page.run('openPanel("settings")');
  return page.d.querySelector("#panel-body #settings-providers");
}
const posts = (page, path) => plain(page.calls().filter((c) => c.method === "POST" && c.path === path).map((c) => c.body));

test("the Add buttons are the server's table, and Add NanoGPT saves it with its addresses and the key", { skip }, () => withPage(async (page) => {
  const section = await openSettings(page, stateWith([]));
  const table = STATE.presets.providers;
  assert.ok(table.length >= 4);
  assert.deepEqual(buttons(section).map((b) => b.textContent), table.map((x) => x.label));
  assert.deepEqual(table.slice(0, 2).map((x) => x.id), ["nanogpt", "anthropic"]);
  button(section, "Add NanoGPT").click();
  const box = top(page);
  assert.equal(field(box, "Name").value, "NanoGPT");
  assert.equal(field(box, "Chat address").value, NANO);
  assert.equal(field(box, "The assistant's address").value, NANO);
  assert.match(box.textContent, /Recognised as NanoGPT\./);
  type(page, field(box, "API key"), "  sk-nano-1234567  ");
  button(box, "Save").click();
  await settle(page);
  assert.deepEqual(posts(page, "/api/providers"), [{ provider: { name: "NanoGPT", base_url: NANO, builder_url: NANO,
    builder_auth: "bearer", chat_api: "auto" }, api_key: "sk-nano-1234567", original_name: null, new: true }]);
  assert.equal(dialogs(page).length, 0);
}));

test("Add Anthropic is the assistant's address alone, its key in x-api-key; a name taken gets a number", { skip }, () => withPage(async (page) => {
  const section = await openSettings(page, stateWith([{ name: "Anthropic", base_url: "", builder_url: "https://api.anthropic.com",
    builder_auth: "x-api-key", has_key: true, key_for: ["https://api.anthropic.com:443"], service: "anthropic" }]));
  button(section, "Add Anthropic").click();
  const box = top(page);
  assert.equal(field(box, "Name").value, "Anthropic 2");
  assert.equal(field(box, "Chat address").value, "");
  assert.equal(field(box, "The assistant's address").value, "https://api.anthropic.com");
  assert.equal(field(box, "Its key goes in").value, "x-api-key");
  type(page, field(box, "API key"), "sk-ant-test-1234");
  button(box, "Save & test").click();
  await settle(page);
  assert.match(box.textContent, /no chat address, so there's no model list to test it with/);
  assert.deepEqual(plain(page.calls().filter((c) => c.path === "/api/models").map((c) => c.query)), []);
  assert.equal(posts(page, "/api/providers")[0].provider.builder_auth, "x-api-key");
}));

test("an address typed by hand is recognised: Tinfoil's is sealed whatever button added it", { skip }, () => withPage(async (page) => {
  const section = await openSettings(page, stateWith([]));
  button(section, "Add other (OpenAI-compatible)").click();
  const box = top(page);
  type(page, field(box, "Chat address"), "https://inference.tinfoil.sh/v1");
  assert.match(box.textContent, /Recognised as Tinfoil: every request to it must be sealed end to end\./);
  type(page, field(box, "Chat address"), "https://llm.chutes.ai/v1");
  assert.match(box.textContent, /Recognised as Chutes: its -TEE models are always sealed/);
  type(page, field(box, "Chat address"), "https://llm.example/v1");
  assert.doesNotMatch(box.textContent, /Recognised as/);
}));

test("a saved key at a new address is asked about, No the default, and a No is kept until Ask again", { skip }, () => withPage(async (page) => {
  const mine = { name: "Mine", base_url: "https://llm.example/v1", builder_url: "", builder_auth: "bearer", chat_api: "auto",
    has_key: true, key_for: ["https://llm.example:443"], key_declined: [], service: "", key_held: "" };
  let section = await openSettings(page, stateWith([mine]));
  button(section, "Edit").click();
  let box = top(page);
  type(page, field(box, "Chat address"), "https://llm2.example/v1");
  assert.match(box.textContent, /The saved API key is for https:\/\/llm.example, and isn't sent to https:\/\/llm2.example/);
  button(box, "Save").click();
  await settle(page);
  const ask = top(page);
  assert.match(ask.querySelector("h2").textContent, /^Use the saved API key with https:\/\/llm2.example\?$/);
  assert.equal(page.d.activeElement?.textContent, "No");                        // the default
  button(ask, "No").click();
  await settle(page);
  assert.deepEqual(posts(page, "/api/providers").map((b) => [b.provider.base_url, b.provider.use_saved_key, b.original_name, b.new]),
    [["https://llm2.example/v1", false, "Mine", false]]);
  // as the server kept it (key_declined): no question at the next Save, only from Ask again
  const declined = { ...mine, base_url: "https://llm2.example/v1", key_declined: ["https://llm2.example:443"],
    key_held: "The API key saved for Mine was entered for https://llm.example:443 …" };
  section = await openSettings(page, stateWith([declined]));
  button(section, "Edit").click();
  box = top(page);
  button(box, "Save").click();
  await settle(page);
  assert.equal(dialogs(page).length, 0);
  assert.equal(posts(page, "/api/providers").at(-1).provider.use_saved_key, undefined);
  section = await openSettings(page, stateWith([declined]));
  button(section, "Edit").click();
  box = top(page);
  button(box, "Ask again").click();
  await settle(page);
  button(top(page), "Use it with https://llm2.example").click();
  await settle(page);
  assert.equal(posts(page, "/api/providers").at(-1).provider.use_saved_key, true);
}));

test("a Chutes key moves between Chutes' own hosts without a question", { skip }, () => withPage(async (page) => {
  const chutes = { name: "Chutes", base_url: "https://llm.chutes.ai/v1", builder_url: "https://claude.chutes.ai", builder_auth: "bearer",
    chat_api: "auto", has_key: true, key_for: ["https://llm.chutes.ai:443"], key_declined: [], service: "chutes", key_held: "" };
  const section = await openSettings(page, stateWith([chutes]));
  button(section, "Edit").click();
  const box = top(page);
  assert.doesNotMatch(box.textContent, /isn't sent to/);
  button(box, "Save").click();
  await settle(page);
  assert.equal(dialogs(page).length, 0);
  assert.equal(posts(page, "/api/providers").length, 1);
}));

test("a key over plain http to another machine is asked about first, and No saves nothing", { skip }, () => withPage(async (page) => {
  const section = await openSettings(page, stateWith([]));
  button(section, "Add other (OpenAI-compatible)").click();
  const box = top(page);
  type(page, field(box, "Name"), "Lan");
  type(page, field(box, "Chat address"), "http://192.168.1.5:11434/v1");
  type(page, field(box, "API key"), "sk-lan-12345678");
  button(box, "Save").click();
  await settle(page);
  assert.match(top(page).querySelector("h2").textContent, /^Send the API key unencrypted to 192.168.1.5\?$/);
  button(top(page), "No").click();
  await settle(page);
  assert.deepEqual(posts(page, "/api/providers"), []);
  assert.match(box.textContent, /Not saved: the key would go unencrypted to 192.168.1.5\./);
  assert.ok(dialogs(page).includes(box));                                       // still open, to put right
  button(box, "Save").click();
  await settle(page);
  button(top(page), "Send it unencrypted").click();
  await settle(page);
  const sent = posts(page, "/api/providers");
  assert.equal(sent.length, 1);
  assert.equal(sent[0].provider.key_over_http, true);
  // this computer itself: nothing to ask
  button(page.d.querySelector("#panel-body #settings-providers"), "Add other (OpenAI-compatible)").click();
  const local = top(page);
  type(page, field(local, "Name"), "Here");
  type(page, field(local, "Chat address"), "http://localhost:11434/v1");
  type(page, field(local, "API key"), "sk-here-12345678");
  button(local, "Save").click();
  await settle(page);
  assert.equal(posts(page, "/api/providers").at(-1).provider.key_over_http, undefined);
}));

test("Remove asks, then removes the provider and its key", { skip }, () => withPage(async (page) => {
  const section = await openSettings(page, stateWith([{ name: "Old", base_url: "https://llm.example/v1", builder_url: "", has_key: true,
    key_for: ["https://llm.example:443"], service: "", key_held: "" }]));
  button(section, "Remove").click();
  await settle(page);
  button(top(page), "Remove").click();
  await settle(page);
  assert.deepEqual(plain(page.calls().filter((c) => c.method === "DELETE").map((c) => c.path)), ["/api/providers/Old"]);
}));

test("the assistant's usual models follow its provider's service, and it can run on another provider", { skip }, () => withPage(async (page) => {
  const nano = { name: "NanoGPT", base_url: NANO, builder_url: NANO, has_key: true, key_for: ["https://nano-gpt.com:443"], service: "nanogpt" };
  const anth = { name: "Anthropic", base_url: "", builder_url: "https://api.anthropic.com", builder_auth: "x-api-key", has_key: true,
    key_for: ["https://api.anthropic.com:443"], service: "anthropic" };
  const labels = () => [...page.d.querySelectorAll('#panel-body input[name="am"]')].map((r) => r.closest("label").querySelector(":scope > div > div").textContent);
  await openSettings(page, stateWith([nano, anth], { builder_provider: "NanoGPT", builder_model: "z-ai/glm-5.3" }));
  assert.deepEqual(labels(), ["GLM 5.3", "Private GLM 5.3", "Claude Opus 5.5", "Something else"]);
  assert.equal(page.d.querySelector('#panel-body input[name="am"]:checked').value, "glm");
  const priv = page.d.querySelector('#panel-body input[name="am"][value="private"]');
  priv.checked = true;
  priv.dispatchEvent(new page.w.Event("change", { bubbles: true }));
  await settle(page);
  assert.deepEqual(posts(page, "/api/settings").at(-1), { builder_model: "private/glm-5-3", builder_small_model: "",
    builder_vision_model: "private/deepseek-v4-1-flash", review_model: "NanoGPT|private/glm-5-3" });
  const runsOn = [...page.d.querySelectorAll("#panel-body select")].find((s) => [...s.options].some((o) => o.value === "Anthropic"));
  runsOn.value = "Anthropic";
  runsOn.dispatchEvent(new page.w.Event("change", { bubbles: true }));
  await settle(page);
  assert.deepEqual(posts(page, "/api/settings").at(-1), { builder_provider: "Anthropic" });
  await openSettings(page, stateWith([nano, anth], { builder_provider: "Anthropic", builder_model: "claude-opus-5-5" }));
  assert.deepEqual(labels(), ["Claude Opus 5.5", "Something else"]);
  assert.equal(page.d.querySelector('#panel-body input[name="am"]:checked').value, "anthropic-opus");
}));

test("the first run is still NanoGPT's quick setup, and a provider set up but not ready says why", { skip }, () => withPage(async (page) => {
  const fresh = stateWith([]);
  fresh.ready = false;
  fresh.assistant = { error: "Set up the assistant first: add your NanoGPT key, or another provider (Settings)." };
  await page.event({ type: "state", state: fresh });
  const chat = page.d.querySelector("#chat");
  assert.match(chat.textContent, /I run on NanoGPT\. Paste your API key/);
  assert.match(chat.textContent, /Using Anthropic, or another provider\? Add it in Settings → AI providers/);
  const key = chat.querySelector('input[type="password"]');
  key.value = "sk-nano-1234567";
  button(chat, "Get started").click();
  await settle(page);
  assert.deepEqual(posts(page, "/api/setup"), [{ api_key: "sk-nano-1234567" }]);
  const stuck = stateWith([{ name: "Tinfoil", base_url: "https://inference.tinfoil.sh/v1", builder_url: "", has_key: true, service: "tinfoil" }],
    { builder_provider: "Tinfoil" });
  stuck.ready = false;
  stuck.assistant = { error: "Tinfoil is Tinfoil's end-to-end encrypted API: … nothing is sent to it." };
  await page.event({ type: "state", state: stuck });
  assert.match(chat.textContent, /The assistant can't start yet/);
  assert.match(chat.textContent, /nothing is sent to it/);
  assert.doesNotMatch(chat.textContent, /Paste your API key/);
}));
