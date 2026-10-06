// Behaviour of the web dashboard's script (src/argus/apps/web/static/app.js), run in Node with a
// small fake DOM built from the real index.html, a scripted API and virtual timers.
//
// Run by tests/unit/test_web_dashboard.py (skipped where Node.js is missing), or directly:
//   node --test tests/web/dashboard.test.mjs
//
// What it pins down is the session logic the static checks cannot see: sign-in and sign-out,
// token refresh (one at a time; never reviving a signed-out session), the back/forward cache,
// answers that arrive for a previous organisation or report, idle sign-out, and focus.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const STATIC = join(ROOT, "src", "argus", "apps", "web", "static");
const HTML = readFileSync(join(STATIC, "index.html"), "utf8");
// Evaluated as an ES module, as the browser does (type="module"); a data: URL per page gives each
// test a fresh instance (a .js file without import/export would load as cached CommonJS).
const APP_SOURCE = readFileSync(join(STATIC, "app.js"), "utf8");

// ------------------------------------------------------------------------------- fake DOM
const VOID = new Set(["meta", "link", "input", "img", "br", "hr"]);

class FakeElement {
  constructor(document, localName) {
    this.ownerDocument = document;
    this.localName = localName;
    this.parent = null;
    this.children = [];
    this.attributes = new Map();
    this.listeners = new Map();
    this.className = "";
    this.value = "";
    this.open = false;
    this._hidden = false;
    this._disabled = false;
  }

  get hidden() {
    return this._hidden;
  }

  set hidden(value) {
    this._hidden = Boolean(value);
  }

  get disabled() {
    return this._disabled;
  }

  set disabled(value) {
    this._disabled = Boolean(value);
    // Browsers move focus away from a control that becomes disabled.
    if (this._disabled && this.ownerDocument.activeElement === this) {
      this.ownerDocument.activeElement = this.ownerDocument.body;
    }
  }

  setAttribute(name, value) {
    this.attributes.set(name, String(value));
    if (name === "hidden") this.hidden = true;
    if (name === "disabled") this.disabled = true;
  }

  getAttribute(name) {
    return this.attributes.has(name) ? this.attributes.get(name) : null;
  }

  removeAttribute(name) {
    this.attributes.delete(name);
  }

  get id() {
    return this.getAttribute("id") ?? "";
  }

  get textContent() {
    return this.children.map((c) => (typeof c === "string" ? c : c.textContent)).join("");
  }

  set textContent(value) {
    this.replaceChildren();
    if (value !== "") this.children.push(String(value));
  }

  append(...nodes) {
    for (const node of nodes) {
      if (node instanceof FakeElement) {
        node.remove();
        node.parent = this;
        this.children.push(node);
      } else {
        this.children.push(String(node));
      }
    }
  }

  replaceChildren(...nodes) {
    for (const child of this.children) if (child instanceof FakeElement) child.parent = null;
    this.children = [];
    this.append(...nodes);
  }

  remove() {
    if (this.parent) {
      this.parent.children = this.parent.children.filter((child) => child !== this);
      this.parent = null;
    }
  }

  get isConnected() {
    let node = this;
    while (node.parent) node = node.parent;
    return node === this.ownerDocument.documentElement;
  }

  *descendants() {
    for (const child of this.children) {
      if (child instanceof FakeElement) {
        yield child;
        yield* child.descendants();
      }
    }
  }

  querySelectorAll(selectors) {
    const tests = selectors.split(",").map((part) => {
      const selector = part.trim();
      const attribute = /^\[([\w-]+)\]$/.exec(selector);
      return attribute
        ? (node) => node.attributes.has(attribute[1])
        : (node) => node.localName === selector;
    });
    return [...this.descendants()].filter((node) => tests.some((matches) => matches(node)));
  }

  addEventListener(type, listener) {
    if (!this.listeners.has(type)) this.listeners.set(type, []);
    this.listeners.get(type).push(listener);
  }

  dispatch(type, init = {}) {
    const event = { type, target: this, currentTarget: this, defaultPrevented: false, ...init };
    event.preventDefault = () => {
      event.defaultPrevented = true;
    };
    for (const listener of this.listeners.get(type) ?? []) listener(event);
    return event;
  }

  focus() {
    if (!this.disabled) this.ownerDocument.activeElement = this;
  }

  showModal() {
    this.open = true;
  }

  close() {
    if (!this.open) return;
    this.open = false;
    this.dispatch("close");
  }
}

class FakeDocument {
  constructor(html) {
    this.listeners = new Map();
    this.visibilityState = "visible";
    this.documentElement = new FakeElement(this, "html");
    this.parse(html);
    this.body = this.documentElement.querySelectorAll("body")[0];
    this.activeElement = this.body;
  }

  parse(html) {
    const stack = [this.documentElement];
    const token =
      /<!--[\s\S]*?-->|<!doctype[^>]*>|<\/([a-zA-Z][\w-]*)\s*>|<([a-zA-Z][\w-]*)((?:\s+[^\s=>/]+(?:\s*=\s*"[^"]*")?)*)\s*\/?>/gi;
    let last = 0;
    for (const match of html.matchAll(token)) {
      const text = html.slice(last, match.index).trim();
      last = match.index + match[0].length;
      if (text) stack.at(-1).append(text);
      if (match[1]) {
        const name = match[1].toLowerCase();
        if (name === "html") continue;
        while (stack.length > 1 && stack.at(-1).localName !== name) stack.pop();
        if (stack.length > 1) stack.pop();
      } else if (match[2] && match[2].toLowerCase() !== "html") {
        const node = new FakeElement(this, match[2].toLowerCase());
        for (const attribute of (match[3] ?? "").matchAll(/([^\s=]+)(?:\s*=\s*"([^"]*)")?/g)) {
          node.setAttribute(attribute[1], attribute[2] ?? "");
        }
        stack.at(-1).append(node);
        if (!VOID.has(node.localName)) stack.push(node);
      }
    }
  }

  getElementById(id) {
    return [...this.documentElement.descendants()].find((node) => node.id === id) ?? null;
  }

  createElement(name) {
    return new FakeElement(this, name);
  }

  addEventListener(type, listener) {
    if (!this.listeners.has(type)) this.listeners.set(type, []);
    this.listeners.get(type).push(listener);
  }
}

// ------------------------------------------------------------------------- virtual time
const flush = async () => {
  for (let i = 0; i < 30; i += 1) await new Promise((resolve) => setImmediate(resolve));
};

class Clock {
  constructor() {
    this.now = Date.parse("2026-10-05T12:00:00Z");
    this.timers = new Map();
    this.nextId = 1;
  }

  setTimeout(callback, delay = 0) {
    const id = this.nextId++;
    this.timers.set(id, { at: this.now + Number(delay), delay: Number(delay), callback, every: 0 });
    return id;
  }

  setInterval(callback, delay) {
    const id = this.nextId++;
    this.timers.set(id, { at: this.now + delay, delay, callback, every: delay });
    return id;
  }

  clear(id) {
    this.timers.delete(id);
  }

  async advance(ms) {
    const until = this.now + ms;
    await flush();
    for (;;) {
      const [due] = [...this.timers.entries()]
        .filter(([, timer]) => timer.at <= until)
        .sort((a, b) => a[1].at - b[1].at);
      if (!due) break;
      const [id, timer] = due;
      this.now = timer.at;
      if (timer.every) timer.at += timer.every;
      else this.timers.delete(id);
      timer.callback();
      await flush();
    }
    this.now = until;
  }
}

// ---------------------------------------------------------------------- scripted API
const reply = (status, body = null) => ({
  status,
  ok: status >= 200 && status < 300,
  json: async () => {
    if (body === null) throw new SyntaxError("no body");
    return body;
  },
});

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((ok, fail) => {
    resolve = ok;
    reject = fail;
  });
  return { promise, resolve, reject };
}

class Api {
  constructor() {
    this.calls = [];
    this.routes = [];
  }

  // Later registrations win, so a test can override one answer.
  on(method, pattern, answer) {
    this.routes.unshift({ method, pattern, answer });
  }

  async fetch(url, init = {}) {
    const path = new URL(url).pathname.replace(/^\/api\/v1\//, "");
    const method = init.method ?? "GET";
    const call = { method, path, init, auth: init.headers?.Authorization ?? null };
    this.calls.push(call);
    const route = this.routes.find(
      (r) => r.method === method && (typeof r.pattern === "string" ? r.pattern === path : r.pattern.test(path)),
    );
    if (!route) return reply(404, { detail: "Not found." });
    return route.answer(call);
  }

  called(method, path) {
    return this.calls.filter((call) => call.method === method && call.path === path);
  }
}

const ORGS = [
  { id: "aaaaaaaa-0000-4000-8000-000000000001", name: "Alpha", status: "active" },
  { id: "bbbbbbbb-0000-4000-8000-000000000002", name: "Beta", status: "active" },
];
const TOKENS = { status: "authenticated", access_token: "access-1", refresh_token: "refresh-1", expires_in: 600 };

function overview(name, { reports = [`${name} report`], unread = 0 } = {}) {
  return {
    generated_at: "2026-10-05T12:00:00Z",
    projects: { count: 1, recent: [{ name: `${name} project`, visibility: "organization", jobs: 1 }] },
    jobs: { by_status: { running: 1 }, active: [] },
    reports: reports.map((title, index) => ({
      job_id: `${name}-job-${index}`,
      project_id: "project-1",
      title,
      finished_at: "2026-10-05T11:00:00Z",
    })),
    sources: { total: 2, blocked: 0, high_risk: 0 },
    knowledge: { documents: 1, ready: 1, quarantined: 0, bytes: 2048, chunks: 3 },
    monitoring: { active: 0, total: 0, new_changes: 0, recent_changes: [] },
    alerts: { unread },
    ai_usage: null,
    system: { database: "ok", migrations: "ok", redis: "ok" },
    security: null,
  };
}

function reportDocument(title) {
  return {
    title,
    objective: `${title} objective`,
    generated_at: "2026-10-05T11:00:00Z",
    confidence: 0.8,
    version: 1,
    executive_summary: `${title} summary`,
    sections: [],
    findings: [],
    contradictions: [],
    recommendations: [],
    limitations: [],
    sources: [],
    quality: { overall: 1 },
    methodology: { answered: 1, questions: 1, sources: 0, findings_included: 0, findings_total: 0, cost_usd: "0" },
  };
}

// ------------------------------------------------------------------------- the page
let loads = 0;

async function openPage() {
  const document = new FakeDocument(HTML);
  const clock = new Clock();
  const api = new Api();
  const windowListeners = new Map();
  const window = {
    location: { href: "http://localhost:8000/app/" },
    setTimeout: (callback, delay) => clock.setTimeout(callback, delay),
    clearTimeout: (id) => clock.clear(id),
    setInterval: (callback, delay) => clock.setInterval(callback, delay),
    clearInterval: (id) => clock.clear(id),
    addEventListener(type, listener) {
      if (!windowListeners.has(type)) windowListeners.set(type, []);
      windowListeners.get(type).push(listener);
    },
    dispatch(type, init = {}) {
      for (const listener of windowListeners.get(type) ?? []) listener({ type, ...init });
    },
  };
  Object.assign(globalThis, { document, window, fetch: (url, init) => api.fetch(String(url), init) });
  Date.now = () => clock.now;

  api.on("POST", "auth/login", () => reply(200, TOKENS));
  api.on("POST", "auth/logout", () => reply(204));
  api.on("GET", "auth/me", () => reply(200, { email: "ana@example.com" }));
  api.on("GET", "orgs", () => reply(200, ORGS));
  api.on("GET", `orgs/${ORGS[0].id}/dashboard`, () => reply(200, overview("Alpha")));
  api.on("GET", `orgs/${ORGS[1].id}/dashboard`, () => reply(200, overview("Beta")));

  loads += 1;
  const source = `${APP_SOURCE}
// page ${loads}
`;
  await import(`data:text/javascript;base64,${Buffer.from(source).toString("base64")}`);
  await clock.advance(0);
  const byId = (id) => document.getElementById(id);
  const visible = () => ["view-login", "view-mfa", "view-empty", "view-dashboard"].find((id) => !byId(id).hidden);
  const signIn = async () => {
    byId("email").value = "ana@example.com";
    byId("password").value = "a long and correct password";
    byId("login-form").dispatch("submit");
    await clock.advance(0);
  };
  return { document, window, clock, api, byId, visible, signIn };
}

// ------------------------------------------------------------------------------ tests
test("signs in and shows every section, without cookies or redirects", async () => {
  const { byId, visible, signIn, api } = await openPage();
  assert.equal(visible(), "view-login");
  await signIn();
  assert.equal(visible(), "view-dashboard");
  assert.equal(byId("who").textContent, "ana@example.com");
  assert.equal(byId("cards").children.length, 10);
  assert.match(byId("cards").textContent, /Alpha report/);
  for (const call of api.calls) {
    assert.equal(call.init.credentials, "omit", call.path);
    assert.equal(call.init.redirect, "error", call.path);
  }
});

test("a failed sign-in clears the password and gives focus back", async () => {
  const { byId, visible, api, document, clock } = await openPage();
  api.on("POST", "auth/login", () => reply(401, { detail: "The e-mail address or password is incorrect." }));
  byId("email").value = "ana@example.com";
  byId("password").value = "wrong";
  byId("password").focus();
  byId("login-form").dispatch("submit");
  await clock.advance(0);
  assert.equal(visible(), "view-login");
  assert.equal(byId("login-message").textContent, "The e-mail address or password is incorrect.");
  assert.equal(byId("password").value, "");
  assert.equal(byId("password").disabled, false);
  assert.equal(document.activeElement, byId("password"));
});

test("signing out clears the page before the server has answered", async () => {
  const { byId, visible, signIn, api } = await openPage();
  await signIn();
  api.on("POST", "auth/logout", () => deferred().promise); // the server never answers
  byId("signout").dispatch("click");
  assert.equal(visible(), "view-login");
  assert.equal(byId("cards").children.length, 0);
  assert.equal(byId("who").textContent, "");
  assert.equal(byId("session").hidden, true);
  const logout = api.called("POST", "auth/logout");
  assert.equal(logout.length, 1);
  assert.equal(logout[0].auth, "Bearer access-1");
});

test("one refresh at a time, and a late one cannot revive a signed-out session", async () => {
  const { byId, visible, signIn, api, clock } = await openPage();
  const refresh = deferred();
  api.on("POST", "auth/refresh", () => refresh.promise);
  await signIn();
  await clock.advance(480_000); // the proactive refresh (80% of the 600 s token)
  // A request that meets an expired token waits for the same refresh instead of starting one.
  api.on("GET", `orgs/${ORGS[0].id}/dashboard`, () => reply(401, { detail: "expired" }));
  byId("reload").dispatch("click");
  await clock.advance(0);
  assert.equal(api.called("POST", "auth/refresh").length, 1);

  byId("signout").dispatch("click");
  refresh.resolve(reply(200, { ...TOKENS, access_token: "access-2", refresh_token: "refresh-2" }));
  await clock.advance(0);
  assert.equal(visible(), "view-login");
  await clock.advance(30 * 60_000);
  assert.equal(api.calls.filter((call) => call.auth === "Bearer access-2").length, 0);
  assert.equal(api.called("POST", "auth/refresh").length, 1);
});

test("a page restored from the back/forward cache comes back signed out", async () => {
  const { byId, visible, signIn, api, window } = await openPage();
  await signIn();
  window.dispatch("pagehide", { persisted: true });
  assert.equal(api.called("POST", "auth/logout").length, 1);
  assert.equal(api.called("POST", "auth/logout")[0].init.keepalive, true);
  assert.equal(visible(), "view-login");
  assert.equal(byId("cards").children.length, 0);
});

test("answers for the previous organisation are dropped", async () => {
  const { byId, signIn, api, clock } = await openPage();
  await signIn();
  const slow = deferred();
  api.on("GET", `orgs/${ORGS[0].id}/dashboard`, () => slow.promise);
  byId("reload").dispatch("click"); // Alpha is loading...
  byId("org").value = ORGS[1].id; // ...when the viewer switches to Beta
  byId("org").dispatch("change");
  await clock.advance(0);
  assert.match(byId("cards").textContent, /Beta report/);
  slow.resolve(reply(403, { detail: "You do not have permission." }));
  await clock.advance(0);
  assert.match(byId("cards").textContent, /Beta report/);
  assert.equal(byId("dash-message").textContent, "");
});

test("a slower report never replaces the one on screen", async () => {
  const { byId, signIn, api, clock } = await openPage();
  api.on("GET", `orgs/${ORGS[0].id}/dashboard`, () =>
    reply(200, overview("Alpha", { reports: ["First", "Second"] })),
  );
  await signIn();
  const first = deferred();
  api.on("GET", /research-jobs\/Alpha-job-0\/report$/, () => first.promise);
  api.on("GET", /research-jobs\/Alpha-job-1\/report$/, () => reply(200, reportDocument("Second")));
  const buttons = byId("cards").querySelectorAll("[data-focus-key]");
  buttons[0].dispatch("click");
  byId("report-close").dispatch("click");
  buttons[1].dispatch("click");
  await clock.advance(0);
  assert.equal(byId("report-title").textContent, "Second");
  assert.match(byId("report-body").textContent, /Second objective/);
  first.resolve(reply(200, reportDocument("First")));
  await clock.advance(0);
  assert.match(byId("report-body").textContent, /Second objective/);
  assert.doesNotMatch(byId("report-body").textContent, /First objective/);
});

test("an idle tab signs itself out", async () => {
  const { byId, visible, signIn, api, clock } = await openPage();
  api.on("POST", "auth/refresh", () => reply(200, TOKENS)); // the session itself stays valid
  await signIn();
  await clock.advance(31 * 60_000);
  assert.equal(visible(), "view-login");
  assert.match(byId("login-message").textContent, /30 minutes without activity/);
  assert.equal(api.called("POST", "auth/logout").length, 1);
});

test("polling leaves an unchanged page alone and keeps focus when it changes", async () => {
  const { byId, signIn, api, clock, document } = await openPage();
  await signIn();
  const button = byId("cards").querySelectorAll("[data-focus-key]")[0];
  button.focus();
  await clock.advance(60_000); // same data: same elements
  assert.equal(button.isConnected, true);
  assert.equal(document.activeElement, button);
  api.on("GET", `orgs/${ORGS[0].id}/dashboard`, () => reply(200, overview("Alpha", { unread: 3 })));
  await clock.advance(60_000); // changed data: new elements, focus follows its key
  assert.equal(button.isConnected, false);
  assert.notEqual(document.activeElement, button);
  assert.equal(document.activeElement.getAttribute("data-focus-key"), button.getAttribute("data-focus-key"));
});

test("sections the viewer may not read say so", async () => {
  const { byId, signIn, api } = await openPage();
  api.on("GET", `orgs/${ORGS[0].id}/dashboard`, () =>
    reply(200, { ...overview("Alpha"), projects: null, jobs: null, reports: null }),
  );
  await signIn();
  assert.equal(byId("cards").children.length, 10);
  assert.match(byId("cards").textContent, /does not include this/);
  assert.doesNotMatch(byId("cards").textContent, /Alpha report/);
});
