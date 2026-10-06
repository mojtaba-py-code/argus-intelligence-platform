// Argus web dashboard (spec §53). One module, no framework, no build step.
//
// Rules this file keeps (tests/unit/test_web_dashboard.py checks them; the Content-Security-Policy
// with Trusted Types enforces them in the browser):
// * Every value from the API is rendered as text, with createElement and textContent. No HTML
//   sinks and no code from strings. Report titles, monitor change summaries and source URLs
//   come from untrusted web pages.
// * Tokens live in this module's memory only - never in localStorage, sessionStorage or
//   cookies. Reloading the tab signs out, closing it revokes the session, and an idle tab signs
//   itself out after IDLE_LIMIT_MS.
// * Requests go to this origin's API only, without cookies, and never follow a redirect.
// * Links are created only for http(s) source URLs, and open without a referrer or an opener.
// * A response is used only by the session (and organisation, and report) that asked for it:
//   every sign-out starts a new epoch, so late answers to a previous session are dropped.

const API = new URL("../api/v1/", window.location.href);
const POLL_MS = 60_000;
const IDLE_LIMIT_MS = 30 * 60_000;
const VIEWS = ["loading", "view-login", "view-mfa", "view-empty", "view-dashboard"];

const session = {
  epoch: 0,
  access: null,
  refresh: null,
  refreshTimer: 0,
  pollTimer: 0,
  mfaToken: null,
  orgs: [],
  orgId: null,
  loadedAt: 0,
  rendered: "",
  lastActivity: Date.now(),
};
let reportSeq = 0;

// ------------------------------------------------------------------------------------- DOM
function byId(id) {
  const node = document.getElementById(id);
  if (node === null) throw new Error(`missing element #${id}`);
  return node;
}

function el(tag, options = {}, ...children) {
  const node = document.createElement(tag);
  if (options.className) node.className = options.className;
  if (options.text !== undefined && options.text !== null) node.textContent = String(options.text);
  for (const [name, value] of Object.entries(options.attrs ?? {})) {
    node.setAttribute(name, String(value));
  }
  for (const child of children.flat(Infinity)) {
    if (child !== null && child !== undefined && child !== false) node.append(child);
  }
  return node;
}

function show(view) {
  for (const id of VIEWS) byId(id).hidden = id !== view;
}

function say(id, message) {
  byId(id).textContent = message ?? "";
}

// Focus after the current work settles: a control disabled by busy() cannot take focus yet.
function focusSoon(id) {
  window.setTimeout(() => byId(id).focus(), 0);
}

async function busy(form, action) {
  const controls = [...form.querySelectorAll("button, input")];
  const focused = document.activeElement;
  form.setAttribute("aria-busy", "true");
  for (const control of controls) control.disabled = true;
  try {
    await action();
  } finally {
    for (const control of controls) control.disabled = false;
    form.removeAttribute("aria-busy");
    // Disabling the focused control dropped focus to the page; give it back.
    if (document.activeElement === document.body && focused?.isConnected) focused.focus();
  }
}

// ------------------------------------------------------------------------------ formatting
const numbers = new Intl.NumberFormat();
const money = new Intl.NumberFormat(undefined, { style: "currency", currency: "USD" });
const dates = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });
const times = new Intl.DateTimeFormat(undefined, { timeStyle: "short" });

const format = {
  count: (value) => numbers.format(Number(value) || 0),
  usd: (value) => money.format(Number(value) || 0),
  date: (value) => (value ? dates.format(new Date(value)) : "-"),
  percent: (value) => `${Math.round((Number(value) || 0) * 100)}%`,
  bytes(value) {
    let size = Number(value) || 0;
    for (const unit of ["B", "KiB", "MiB", "GiB", "TiB"]) {
      if (size < 1024 || unit === "TiB") {
        return `${unit === "B" ? size : size.toFixed(1)} ${unit}`;
      }
      size /= 1024;
    }
    return `${size} B`;
  },
  words: (value) => String(value ?? "-").replaceAll("_", " "),
};

const TONES = new Map(
  Object.entries({
    ok: "good", active: "good", completed: "good", ready: "good", answered: "good", valid: "good",
    queued: "info", running: "info", pending: "info", new: "info", low: "info",
    awaiting_approval: "warn", paused: "warn", medium: "warn", restricted: "warn",
    insufficient_evidence: "warn", warning: "warn",
    fail: "bad", failed: "bad", high: "bad", critical: "bad", invalid: "bad", suspended: "bad",
  }),
);

function badge(value, label) {
  const tone = TONES.get(String(value)) ?? "muted";
  return el("span", { className: `badge tone-${tone}`, text: label ?? format.words(value) });
}

function significance(value) {
  const share = Math.min(1, Math.max(0, Number(value) || 0));
  const tone = share >= 0.7 ? "bad" : share >= 0.4 ? "warn" : "info";
  return el("span", { className: `badge tone-${tone}`, text: `significance ${format.percent(share)}` });
}

function safeLink(url, text) {
  let parsed = null;
  try {
    parsed = new URL(String(url));
  } catch {
    return el("span", { text: text ?? String(url ?? "") });
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    return el("span", { text: text ?? parsed.href });
  }
  return el("a", {
    text: text ?? parsed.href,
    attrs: { href: parsed.href, target: "_blank", rel: "noopener noreferrer nofollow" },
  });
}

// ------------------------------------------------------------------------------------- API
class ApiError extends Error {
  constructor(status, problem) {
    super(problem?.detail || problem?.title || `The request failed (${status}).`);
    this.status = status;
    this.code = problem?.code ?? null;
  }
}

function apiPath(...segments) {
  return segments.map((segment) => encodeURIComponent(String(segment))).join("/");
}

async function request(path, { method = "GET", body, auth = true, retried = false } = {}) {
  const headers = { Accept: "application/json" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (auth) {
    if (!session.access) throw new ApiError(401, null);
    headers.Authorization = `Bearer ${session.access}`;
  }
  let response;
  try {
    response = await fetch(new URL(path, API), {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      credentials: "omit",
      cache: "no-store",
      redirect: "error",
      referrerPolicy: "no-referrer",
    });
  } catch {
    throw new ApiError(0, { detail: "The server could not be reached. Check your connection." });
  }
  if (response.status === 401 && auth && !retried && session.refresh) {
    if (await refreshTokens()) return request(path, { method, body, auth, retried: true });
  }
  if (!response.ok) {
    let problem = null;
    try {
      problem = await response.json();
    } catch {
      problem = null;
    }
    throw new ApiError(response.status, problem);
  }
  return response.status === 204 ? null : response.json();
}

function describe(error) {
  if (!(error instanceof ApiError)) return "Something went wrong. Please try again.";
  if (error.status === 429) return "Too many attempts. Please wait a little and try again.";
  return error.message;
}

// --------------------------------------------------------------------------------- session
let refreshing = null;

function keepTokens(tokens) {
  session.access = tokens.access_token;
  session.refresh = tokens.refresh_token;
  window.clearTimeout(session.refreshTimer);
  const seconds = Math.max(15, Math.floor((Number(tokens.expires_in) || 60) * 0.8));
  session.refreshTimer = window.setTimeout(() => {
    if (idle()) signOut("You were signed out after 30 minutes without activity.");
    else void refreshTokens();
  }, seconds * 1000);
}

function refreshTokens() {
  // One refresh at a time: refresh tokens rotate, and the server treats a reused one as theft.
  if (refreshing !== null) return refreshing;
  const token = session.refresh;
  const epoch = session.epoch;
  if (!token) return Promise.resolve(false);
  const attempt = (async () => {
    try {
      const tokens = await request("auth/refresh", {
        method: "POST",
        body: { refresh_token: token },
        auth: false,
      });
      if (epoch !== session.epoch) return false; // signed out meanwhile: do not revive it
      keepTokens(tokens);
      return true;
    } catch {
      if (epoch === session.epoch) endSession("Your session has ended. Please sign in again.");
      return false;
    }
  })();
  refreshing = attempt;
  void attempt.finally(() => {
    if (refreshing === attempt) refreshing = null;
  });
  return attempt;
}

function idle() {
  return Date.now() - session.lastActivity > IDLE_LIMIT_MS;
}

function endSession(message) {
  window.clearTimeout(session.refreshTimer);
  window.clearInterval(session.pollTimer);
  Object.assign(session, {
    epoch: session.epoch + 1,
    access: null,
    refresh: null,
    mfaToken: null,
    orgs: [],
    orgId: null,
    loadedAt: 0,
    rendered: "",
  });
  closeReport();
  byId("cards").replaceChildren();
  byId("org").replaceChildren();
  say("who", "");
  say("updated", "");
  say("dash-message", "");
  byId("session").hidden = true;
  show("view-login");
  say("login-message", message);
  focusSoon("email");
}

// Ends the session on the server. keepalive: it still goes out while the page is unloading.
function revoke(token) {
  return fetch(new URL("auth/logout", API), {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
    credentials: "omit",
    cache: "no-store",
    redirect: "error",
    referrerPolicy: "no-referrer",
    keepalive: true,
  }).catch(() => undefined); // the server expires the session on its own
}

// The page forgets everything first, so nothing stays on screen while the network is slow.
function signOut(message) {
  const token = session.access;
  endSession(message);
  if (token) void revoke(token);
}

// ------------------------------------------------------------------------------- sign in
async function onLogin(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const email = byId("email").value.trim();
  const password = byId("password").value;
  if (!email || !password) {
    say("login-message", "Enter your email address and password.");
    return;
  }
  say("login-message", "");
  await busy(form, async () => {
    try {
      const result = await request("auth/login", {
        method: "POST",
        body: { email, password },
        auth: false,
      });
      byId("password").value = "";
      if (result.status === "mfa_required") {
        session.mfaToken = result.mfa_token;
        say("mfa-message", "");
        show("view-mfa");
        focusSoon("code");
        return;
      }
      keepTokens(result);
      await start();
    } catch (error) {
      byId("password").value = "";
      // Signed in but the dashboard could not start: do not keep a half-open session.
      if (session.access) signOut(describe(error));
      else say("login-message", describe(error));
    }
  });
}

async function onMfa(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const code = byId("code").value.replace(/\s+/g, "");
  byId("code").value = "";
  if (code.length < 6) {
    say("mfa-message", "Enter the 6-digit code or a recovery code.");
    return;
  }
  await busy(form, async () => {
    try {
      const tokens = await request("auth/mfa/verify", {
        method: "POST",
        body: { mfa_token: session.mfaToken, code },
        auth: false,
      });
      session.mfaToken = null;
      keepTokens(tokens);
      await start();
    } catch (error) {
      if (session.access) signOut(describe(error));
      else say("mfa-message", describe(error));
    }
  });
}

async function start() {
  const epoch = session.epoch;
  const [me, orgs] = await Promise.all([request("auth/me"), request("orgs")]);
  if (epoch !== session.epoch) return; // signed out meanwhile
  session.orgs = orgs;
  say("who", me.email);
  byId("session").hidden = false;
  const select = byId("org");
  select.replaceChildren(
    ...orgs.map((org) =>
      el("option", {
        text: org.status === "active" ? org.name : `${org.name} (${format.words(org.status)})`,
        attrs: { value: org.id },
      }),
    ),
  );
  // The poll also enforces the idle limit, so it runs even without an organisation.
  window.clearInterval(session.pollTimer);
  session.pollTimer = window.setInterval(() => void tick(), POLL_MS);
  if (orgs.length === 0) {
    show("view-empty");
    return;
  }
  session.orgId = orgs.find((org) => org.status === "active")?.id ?? orgs[0].id;
  session.rendered = "";
  select.value = session.orgId;
  show("view-dashboard");
  byId("main").focus();
  await load();
}

async function tick() {
  if (!session.access) return;
  if (idle()) {
    signOut("You were signed out after 30 minutes without activity.");
    return;
  }
  if (document.visibilityState === "visible") await load();
}

// Refresh: reload the overview, or look for memberships again when there is none yet.
async function reload() {
  if (session.orgId) await load();
  else if (session.access) await start().catch(() => undefined);
}

// ------------------------------------------------------------------------------ dashboard
async function load() {
  const orgId = session.orgId;
  const epoch = session.epoch;
  if (!orgId || !session.access) return;
  // An answer for another session or organisation (switched or signed out meanwhile) is dropped.
  const current = () => epoch === session.epoch && orgId === session.orgId;
  try {
    const overview = await request(apiPath("orgs", orgId, "dashboard"));
    const usage = overview.ai_usage ? await request(apiPath("orgs", orgId, "usage")) : null;
    if (!current()) return;
    render(overview, usage);
    session.loadedAt = Date.now();
    say("dash-message", "");
    say("updated", `Updated at ${times.format(new Date())}`);
  } catch (error) {
    if (!current()) return;
    say("dash-message", describe(error));
    if (error instanceof ApiError && (error.status === 403 || error.status === 404)) {
      byId("cards").replaceChildren();
      session.rendered = "";
    }
  }
}

function render(overview, usage) {
  const signature = JSON.stringify([{ ...overview, generated_at: null }, usage]);
  // Unchanged data keeps the page as it is (and keyboard focus where it is); an open report
  // keeps the element that opened it, so focus can return there when the dialog closes.
  if (signature === session.rendered || byId("report").open) return;
  const key = document.activeElement?.getAttribute?.("data-focus-key") ?? null;
  byId("cards").replaceChildren(...cards(overview, usage));
  session.rendered = signature;
  if (key === null) return;
  for (const node of byId("cards").querySelectorAll("[data-focus-key]")) {
    if (node.getAttribute("data-focus-key") === key) {
      node.focus();
      break;
    }
  }
}

// A section the viewer may not read arrives as null (the API applies the same permissions as
// the endpoints behind it): the card says so instead of showing anything.
function cards(o, usage) {
  const section = (data, render, title) =>
    data === null || data === undefined
      ? card(title, [unavailable("Your role or API key does not include this.")])
      : render(data);
  return [
    section(o.projects, projectsCard, "Research projects"),
    section(o.jobs, jobsCard, "Active jobs"),
    section(o.reports, reportsCard, "Reports"),
    section(o.sources, sourcesCard, "Sources"),
    section(o.knowledge, knowledgeCard, "Knowledge base"),
    section(o.monitoring, monitoringCard, "Monitoring", { wide: true }),
    alertsCard(o.alerts, o.monitoring, o.security),
    usageCard(o.ai_usage, usage),
    healthCard(o.system),
    securityCard(o.security),
  ];
}

function card(title, children, { wide = false } = {}) {
  const id = `card-${title.toLowerCase().replace(/[^a-z]+/g, "-")}`;
  return el(
    "section",
    { className: wide ? "card wide" : "card", attrs: { "aria-labelledby": id } },
    el("h2", { text: title, attrs: { id } }),
    children,
  );
}

function stats(entries) {
  return el(
    "dl",
    { className: "stats" },
    entries.map(([label, value, extra]) =>
      el("div", { className: "stat" }, el("dt", { text: label }), el("dd", { text: value }, extra)),
    ),
  );
}

function list(items, render, emptyText) {
  if (!items || items.length === 0) return el("p", { className: "empty", text: emptyText });
  return el(
    "ul",
    { className: "rows" },
    items.map((item) => el("li", {}, render(item))),
  );
}

function unavailable(text) {
  return el("p", { className: "empty", text });
}

function projectsCard(projects) {
  return card("Research projects", [
    stats([["Projects you can see", format.count(projects.count)]]),
    list(
      projects.recent,
      (p) => [
        el("span", { className: "row-title", text: p.name }),
        el("span", { className: "row-meta" }, badge(p.visibility), ` ${format.count(p.jobs)} jobs`),
      ],
      "No projects yet.",
    ),
  ]);
}

function jobsCard(jobs) {
  const counts = jobs.by_status ?? {};
  return card("Active jobs", [
    stats([
      ["Running", format.count(counts.running)],
      ["Queued", format.count(counts.queued)],
      ["Awaiting approval", format.count(counts.awaiting_approval)],
      ["Completed (30 days)", format.count(counts.completed)],
      ["Failed (30 days)", format.count(counts.failed)],
    ]),
    list(
      jobs.active,
      (job) => [
        el("span", { className: "row-title", text: job.title || "Untitled job" }),
        el("span", { className: "row-meta" }, badge(job.status), ` ${format.words(job.stage)}`),
        el("progress", {
          attrs: { max: 100, value: Number(job.progress) || 0, "aria-label": "Progress" },
        }),
      ],
      "Nothing is running.",
    ),
  ]);
}

function reportsCard(reports) {
  return card("Reports", [
    list(
      reports,
      (report) => {
        const open = el("button", {
          className: "link",
          text: report.title || "Untitled report",
          attrs: { type: "button", "data-focus-key": `report:${report.job_id}` },
        });
        open.addEventListener("click", () => void openReport(report));
        return [open, el("span", { className: "row-meta", text: format.date(report.finished_at) })];
      },
      "No finished reports yet.",
    ),
  ]);
}

function sourcesCard(sources) {
  return card("Sources", [
    stats([
      ["Collected", format.count(sources.total)],
      ["Blocked by policy", format.count(sources.blocked)],
      ["High injection risk", format.count(sources.high_risk)],
    ]),
  ]);
}

function knowledgeCard(k) {
  return card("Knowledge base", [
    stats([
      ["Documents", format.count(k.documents)],
      ["Ready", format.count(k.ready)],
      ["Quarantined", format.count(k.quarantined)],
      ["Stored", format.bytes(k.bytes)],
      ["Indexed passages", format.count(k.chunks)],
    ]),
  ]);
}

function monitoringCard(m) {
  return card(
    "Monitoring",
    [
      stats([
        ["Active monitors", `${format.count(m.active)} of ${format.count(m.total)}`],
        ["Changes to review", format.count(m.new_changes)],
      ]),
      list(
        m.recent_changes,
        (change) => [
          el("span", { className: "row-title", text: change.monitor }),
          el("span", { className: "row-meta" }, significance(change.significance), " ", badge(change.status)),
          el("span", { className: "row-text", text: change.summary }),
          el("span", { className: "row-meta", text: format.date(change.created_at) }),
        ],
        "No changes detected.",
      ),
    ],
    { wide: true },
  );
}

function alertsCard(alerts, monitoring, security) {
  const entries = [["Unread notifications", format.count(alerts.unread)]];
  if (monitoring) entries.push(["Monitor changes to review", format.count(monitoring.new_changes)]);
  if (security) {
    const open = security.recommendation_count ?? security.recommendations.length;
    entries.push(["Security recommendations", format.count(open)]);
  }
  return card("Alerts", [stats(entries)]);
}

function usageCard(ai, usage) {
  if (!ai) return card("AI usage and costs", [unavailable("Visible to members who may read usage.")]);
  const spent = Number(ai.cost_usd) || 0;
  const budget = Number(ai.budget_usd) || 0;
  const children = [
    stats([
      ["Spent this month", format.usd(spent), budgetMeter(spent, budget)],
      ["Budget", format.usd(budget)],
      ["Plan", format.words(ai.plan)],
      ["Model calls", format.count(ai.calls)],
      ["Failed calls", format.count(ai.failed_calls)],
      ["Tokens in / out", `${format.count(ai.input_tokens)} / ${format.count(ai.output_tokens)}`],
    ]),
  ];
  if (usage) children.push(quotaTable(usage.metrics));
  return card("AI usage and costs", children, { wide: true });
}

function budgetMeter(spent, budget) {
  if (budget <= 0) return null;
  return el("meter", {
    attrs: {
      min: 0,
      max: budget,
      low: budget * 0.7,
      high: budget * 0.9,
      optimum: 0,
      value: Math.min(spent, budget),
      "aria-label": "Share of the monthly budget spent",
    },
  });
}

const QUOTA_LABELS = new Map(
  Object.entries({
    members: "Members",
    projects: "Projects",
    monitors: "Monitors",
    api_keys: "API keys",
    research_jobs_per_month: "Research jobs this month",
    storage_bytes: "Document storage",
  }),
);

function quotaTable(metrics) {
  const rows = Object.entries(metrics ?? {}).map(([name, { used, limit }]) => {
    const amount = name === "storage_bytes" ? format.bytes : format.count;
    return el(
      "tr",
      {},
      el("th", { text: QUOTA_LABELS.get(name) ?? format.words(name), attrs: { scope: "row" } }),
      el("td", { text: amount(used) }),
      el("td", { text: limit === null ? "Unlimited" : amount(limit) }),
    );
  });
  return el(
    "table",
    { className: "quota" },
    el("caption", { text: "Plan limits" }),
    el(
      "thead",
      {},
      el(
        "tr",
        {},
        el("th", { text: "Resource", attrs: { scope: "col" } }),
        el("th", { text: "Used", attrs: { scope: "col" } }),
        el("th", { text: "Limit", attrs: { scope: "col" } }),
      ),
    ),
    el("tbody", {}, rows),
  );
}

function healthCard(system) {
  const checks = Object.entries(system ?? {});
  return card("System health", [
    stats(checks.map(([name, state]) => [format.words(name), "", badge(state)])),
  ]);
}

function securityCard(security) {
  if (!security) {
    return card("Security events", [unavailable("Visible to members who may read the audit log.")]);
  }
  const chain =
    security.audit_valid === null
      ? badge("pending", "not verified yet")
      : badge(security.audit_valid ? "valid" : "invalid");
  return card(
    "Security events",
    [
      stats([
        ["Denied requests (7 days)", format.count(security.denied)],
        ["Agent tool denials", format.count(security.tool_denials)],
        ["High-risk injected content", format.count(security.injection_high)],
        ["Blocked outbound requests", format.count(security.blocked_egress)],
        ["Active kill switches", format.count(security.active_kill_switches)],
        ["Audit chain", "", chain],
      ]),
      list(
        security.recommendations,
        (r) => [badge(r.severity), el("span", { className: "row-text", text: r.message })],
        "No recommendations: nothing needs attention.",
      ),
    ],
    { wide: true },
  );
}

// --------------------------------------------------------------------------------- report
async function openReport(report) {
  const seq = ++reportSeq; // a slower answer for a report opened earlier must not land here
  const dialog = byId("report");
  say("report-title", report.title || "Untitled report");
  byId("report-body").replaceChildren(el("p", { className: "muted", text: "Loading…" }));
  if (!dialog.open) dialog.showModal();
  try {
    const doc = await request(
      apiPath("orgs", session.orgId, "projects", report.project_id, "research-jobs", report.job_id, "report"),
    );
    if (seq !== reportSeq) return;
    byId("report-body").replaceChildren(el("article", { className: "report" }, reportView(doc)));
  } catch (error) {
    if (seq !== reportSeq) return;
    byId("report-body").replaceChildren(el("p", { className: "message", text: describe(error) }));
  }
}

function closeReport() {
  reportSeq += 1;
  const dialog = byId("report");
  if (dialog.open) dialog.close();
  byId("report-body").replaceChildren();
}

function paragraphs(text) {
  return String(text ?? "")
    .split(/\n{2,}/)
    .filter((part) => part.trim())
    .map((part) => el("p", { text: part.trim() }));
}

function reportView(doc) {
  const q = doc.quality ?? {};
  const m = doc.methodology ?? {};
  return [
    el(
      "p",
      { className: "row-meta" },
      `Generated ${format.date(doc.generated_at)} · confidence ${format.percent(doc.confidence)}`,
      ` · quality ${format.percent(q.overall)} · version ${doc.version}`,
    ),
    el("h3", { text: "Objective" }),
    paragraphs(doc.objective),
    el("h3", { text: "Executive summary" }),
    paragraphs(doc.executive_summary),
    doc.sections.length ? el("h3", { text: "Analysis" }) : null,
    doc.sections.map((section) =>
      el(
        "div",
        { className: "section" },
        el("h4", {}, `${section.question} `, badge(section.status)),
        paragraphs(section.narrative),
      ),
    ),
    el("h3", { text: "Findings" }),
    list(
      doc.findings,
      (f) => [
        el("span", { className: "row-title", text: `${f.ref} ${f.statement}` }),
        el(
          "span",
          { className: "row-meta" },
          `confidence ${format.percent(f.confidence)} · evidence ${format.words(f.support)} `,
          f.contested ? badge("warning", "contested") : null,
        ),
      ],
      "No findings.",
    ),
    doc.contradictions.length ? el("h3", { text: "Contradictions" }) : null,
    doc.contradictions.length
      ? list(doc.contradictions, (c) => [
          el("span", { className: "row-title", text: `${c.a} vs ${c.b}: ${c.attribute}` }),
          el("span", { className: "row-text", text: c.explanation }),
        ])
      : null,
    el("h3", { text: "Recommendations" }),
    list(doc.recommendations, (r) => [el("span", { className: "row-text", text: r.text })], "None."),
    doc.limitations.length ? el("h3", { text: "Limitations" }) : null,
    doc.limitations.length ? list(doc.limitations, (text) => [el("span", { text })]) : null,
    el("h3", { text: "Sources" }),
    list(
      doc.sources,
      (s) => [
        el("span", { className: "row-title", text: `[${s.key}] ${s.title ?? s.filename ?? "Untitled"}` }),
        s.url ? safeLink(s.url) : el("span", { className: "row-meta", text: s.filename ?? "" }),
        el(
          "span",
          { className: "row-meta" },
          `${format.words(s.origin)} · retrieved ${format.date(s.retrieved_at)}`,
          s.trust_tier ? ` · ${format.words(s.trust_tier)}` : "",
        ),
      ],
      "No sources.",
    ),
    el("h3", { text: "Methodology" }),
    stats([
      ["Questions answered", `${format.count(m.answered)} of ${format.count(m.questions)}`],
      ["Sources", format.count(m.sources)],
      ["Findings included", `${format.count(m.findings_included)} of ${format.count(m.findings_total)}`],
      ["Model cost", format.usd(m.cost_usd)],
    ]),
  ];
}

// ---------------------------------------------------------------------------------- wiring
function wire() {
  byId("login-form").addEventListener("submit", (event) => void onLogin(event));
  byId("mfa-form").addEventListener("submit", (event) => void onMfa(event));
  byId("mfa-cancel").addEventListener("click", () => {
    session.mfaToken = null;
    byId("code").value = "";
    show("view-login");
    focusSoon("email");
  });
  byId("signout").addEventListener("click", () => signOut("You have signed out."));
  byId("reload").addEventListener("click", () => void reload());
  byId("org").addEventListener("change", (event) => {
    session.orgId = event.currentTarget.value;
    session.rendered = "";
    byId("cards").replaceChildren();
    say("updated", "");
    say("dash-message", "");
    void load();
  });
  byId("report-close").addEventListener("click", closeReport);
  byId("report").addEventListener("close", () => {
    reportSeq += 1;
    byId("report-body").replaceChildren();
  });
  for (const type of ["pointerdown", "keydown"]) {
    document.addEventListener(type, () => {
      session.lastActivity = Date.now();
    }, { passive: true });
  }
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible" && session.access && Date.now() - session.loadedAt > POLL_MS) {
      void tick();
    }
  });
  // Leaving the page (closing, reloading, navigating away) revokes the session on the server.
  // A page the browser keeps in its back/forward cache must come back signed out, not showing
  // the previous user's data.
  window.addEventListener("pagehide", (event) => {
    if (session.access) void revoke(session.access);
    if (event.persisted) endSession("You were signed out when you left the page.");
  });
  show("view-login");
  focusSoon("email");
}

wire();
