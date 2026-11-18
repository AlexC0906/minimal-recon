"use strict";

// All remote text (titles, bios, names, headers) is untrusted: it is only ever
// written with textContent, and links are only created for http(s) URLs.

const TOKEN = document.querySelector('meta[name="api-token"]').content;
const MAX_UPLOAD_BYTES = 20 * 1024 * 1024;

const STATE_LABELS = {
  found: "Found",
  not_found: "Not found",
  unknown: "Unknown",
  rate_limited: "Rate limited",
  not_applicable: "N/A",
};

const PROFILE_LABELS = {
  display_name: "Name",
  bio: "Bio",
  location: "Location",
  website: "Website",
  created_at: "Joined",
  declared_accounts: "Self-declared accounts (not verified)",
};

/* ---------- tool definitions (everything except the username search) ---------- */

const F = {
  domain: { name: "domain", label: "Domain", placeholder: "example.com" },
  url: { name: "url", label: "URL", placeholder: "https://example.com" },
  ip: { name: "ip", label: "IP address", placeholder: "1.1.1.1" },
  target: { name: "target", label: "IP address or domain", placeholder: "example.com or 1.1.1.1" },
  apiKey: (env) => ({
    name: "api_key", label: `API key (optional if ${env} is set)`, type: "password", optional: true,
  }),
};

const TOOL_TABS = [
  {
    id: "domain", label: "Domain",
    tools: [
      {
        id: "report", label: "Full report", special: "report",
        about: "Runs every passive domain check at once and builds the visual report.",
        fields: [F.domain, { name: "username", label: "Username (optional)", placeholder: "octocat", optional: true },
          { name: "details", label: "Profile details for the username", type: "checkbox" },
          { name: "save", label: "Save to history", type: "checkbox", value: true }],
      },
      { id: "dns", label: "DNS", about: "A, AAAA, MX, NS, TXT and CNAME records with provider hints.", fields: [F.domain] },
      { id: "whois", label: "WHOIS", about: "Registrar, dates and nameservers from RDAP.", fields: [F.domain] },
      { id: "subdomains", label: "Subdomains", about: "Names seen in public Certificate Transparency logs.", fields: [F.domain] },
      {
        id: "archive", label: "Archive", about: "Wayback Machine snapshots of the domain.",
        fields: [F.domain, { name: "limit", label: "Max snapshots", type: "number", value: "100" }],
      },
      {
        id: "tls", label: "TLS", about: "Certificate, protocol and cipher of one host, including invalid certificates.",
        fields: [{ name: "hostname", label: "Host", placeholder: "example.com" },
          { name: "port", label: "Port", type: "number", value: "443" }],
      },
      {
        id: "anti_spoofing", label: "Email spoofing", about: "SPF, DMARC and selected DKIM records.",
        fields: [F.domain, { name: "selectors", label: "DKIM selectors (optional)", placeholder: "google, default", optional: true }],
      },
    ],
  },
  {
    id: "ip", label: "IP",
    tools: [
      { id: "lookup", label: "Lookup", about: "Resolve a domain, or reverse-resolve an IP address.", fields: [F.target] },
      { id: "geoip", label: "Geolocation", about: "Approximate location and network owner (usually the host or ISP).", fields: [F.ip] },
      {
        id: "reputation", label: "VirusTotal", about: "Existing VirusTotal verdicts. Needs your own API key.",
        fields: [F.target, F.apiKey("VT_API_KEY")],
      },
      {
        id: "shodan", label: "Shodan", about: "Shodan's already indexed data for an IP. Needs your own API key.",
        fields: [F.ip, F.apiKey("SHODAN_API_KEY")],
      },
    ],
  },
  {
    id: "web", label: "Web",
    tools: [
      { id: "web", label: "Headers & tech", about: "Security headers, WAF and technology hints from one request.", fields: [F.url] },
      {
        id: "links", label: "Links", about: "Links on one page, split into internal and external. Nothing is followed.",
        fields: [F.url, { name: "max_links", label: "Max links", type: "number", value: "500" }],
      },
      { id: "public_files", label: "Public files", about: "robots.txt, sitemap.xml, security.txt and humans.txt.", fields: [F.url] },
    ],
  },
  {
    id: "email", label: "Email",
    tools: [{
      id: "email", label: "Email address", about: "Format, MX records, role and disposable-domain flags. No mail is sent.",
      fields: [{ name: "address", label: "Email address", placeholder: "name@example.com" }],
    }],
  },
  {
    id: "file", label: "File",
    tools: [{
      id: "metadata", label: "Metadata", special: "upload",
      about: "Size, image format and readable EXIF fields. The file is inspected on this computer only and deleted afterwards.",
      fields: [{ name: "file", label: "File", type: "file" }],
    }],
  },
  {
    id: "compare", label: "Compare",
    tools: [{
      id: "diff", label: "Compare reports", special: "json-files",
      about: "Differences between two saved JSON reports of the same target. No network requests.",
      fields: [{ name: "old", label: "Earlier report (.json)", type: "file", accept: ".json,application/json" },
        { name: "new", label: "Later report (.json)", type: "file", accept: ".json,application/json" }],
    }],
  },
  {
    id: "verify", label: "Verify",
    tools: [
      { id: "verify_token", label: "New token", about: "Create a token to place on profiles you control.", fields: [] },
      {
        id: "verify", label: "Check profiles",
        about: "Checks that the exact token appears on each profile URL you list.",
        fields: [{ name: "token", label: "Token", placeholder: "minimal-recon-verify-..." },
          { name: "urls", label: "Profile URLs (one per line)", type: "textarea", placeholder: "https://github.com/you" }],
      },
    ],
  },
];

/* ---------- helpers ---------- */

const $ = (id) => document.getElementById(id);

function el(tag, options = {}, children = []) {
  const node = document.createElement(tag);
  if (options.className) node.className = options.className;
  if (options.text !== undefined) node.textContent = String(options.text);
  for (const [name, value] of Object.entries(options.attrs || {})) node.setAttribute(name, value);
  for (const child of [].concat(children)) if (child !== null && child !== undefined) node.append(child);
  return node;
}

function isHttpUrl(value) {
  try {
    const url = new URL(value);
    return url.protocol === "http:" || url.protocol === "https:";
  } catch {
    return false;
  }
}

function safeLink(url, text) {
  if (!isHttpUrl(url)) return el("span", { text: text || url });
  return el("a", { text: text || url, attrs: { href: new URL(url).href, target: "_blank", rel: "noopener noreferrer" } });
}

async function api(path, payload = {}) {
  const response = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Recon-Token": TOKEN },
    body: JSON.stringify(payload),
  });
  let data = {};
  try {
    data = await response.json();
  } catch {
    /* handled below */
  }
  if (!response.ok) throw new Error(data.error || `request failed (HTTP ${response.status})`);
  return data;
}

function download(name, text, type) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const link = el("a", { attrs: { href: url, download: name } });
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function setStatus(node, text, kind = "") {
  node.textContent = text;
  node.className = `status ${kind}`.trim();
}

function startTimer(node, label) {
  const started = Date.now();
  const tick = () => setStatus(node, `${label} ${Math.round((Date.now() - started) / 1000)}s`, "busy");
  tick();
  const handle = setInterval(tick, 1000);
  return () => clearInterval(handle);
}

function fileName(text) {
  return text.replace(/[^A-Za-z0-9._-]+/g, "_").slice(0, 80) || "result";
}

/** Replace a node's children, skipping null or undefined entries. */
function fill(node, ...children) {
  node.replaceChildren(...children.filter((child) => child !== null && child !== undefined));
}

/** Render any JSON value as nested tables and lists, text only. */
function renderValue(value) {
  if (value === null || value === undefined || value === "") return el("span", { className: "muted", text: "-" });
  if (typeof value === "boolean") return el("span", { text: value ? "yes" : "no" });
  if (typeof value === "number") return el("span", { text: String(value) });
  if (typeof value === "string") return isHttpUrl(value) ? safeLink(value) : el("span", { text: value });
  if (Array.isArray(value)) {
    if (!value.length) return el("span", { className: "muted", text: "none" });
    if (value.every((item) => item && typeof item === "object" && !Array.isArray(item))) {
      const columns = [...new Set(value.flatMap((item) => Object.keys(item)))];
      return el("div", { className: "scroll" }, el("table", { className: "table" }, [
        el("thead", {}, el("tr", {}, columns.map((column) => el("th", { text: column.replaceAll("_", " ") })))),
        el("tbody", {}, value.map((item) =>
          el("tr", {}, columns.map((column) => el("td", {}, renderValue(item[column])))))),
      ]));
    }
    return el("ul", { className: "plain" }, value.map((item) => el("li", {}, renderValue(item))));
  }
  const entries = Object.entries(value);
  if (!entries.length) return el("span", { className: "muted", text: "none" });
  return el("table", { className: "table kv" }, el("tbody", {}, entries.map(([key, item]) =>
    el("tr", {}, [el("th", { text: key.replaceAll("_", " ") }), el("td", {}, renderValue(item))]))));
}

function readFile(file, mode) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = () => reject(new Error(`could not read ${file.name}`));
    if (mode === "text") reader.readAsText(file);
    else reader.readAsDataURL(file);
  });
}

/* ---------- tabs ---------- */

function activateTab(name) {
  for (const tab of document.querySelectorAll(".tab")) {
    const active = tab.dataset.tab === name;
    tab.classList.toggle("active", active);
    tab.setAttribute("aria-selected", String(active));
    $(`tab-${tab.dataset.tab}`).classList.toggle("hidden", !active);
  }
  if (name === "history") loadHistory();
}

$("tabs").addEventListener("click", (event) => {
  const tab = event.target.closest(".tab");
  if (tab) activateTab(tab.dataset.tab);
});

/* ---------- generic tool panels ---------- */

function buildToolPanels() {
  const historyTab = document.querySelector('.tab[data-tab="history"]');
  const historyPanel = $("tab-history");
  for (const group of TOOL_TABS) {
    historyTab.before(el("button", {
      className: "tab", text: group.label, attrs: { role: "tab", "aria-selected": "false", "data-tab": group.id },
    }));
    historyPanel.before(buildPanel(group));
  }
}

function buildPanel(group) {
  const values = {};
  const panel = el("section", { className: "panel hidden", attrs: { id: `tab-${group.id}` } });
  const picker = el("div", { className: "segmented", attrs: { role: "group" } });
  const about = el("p", { className: "muted about" });
  const form = el("form", { className: "search tool-form" });
  const status = el("div", { className: "status", attrs: { role: "status", "aria-live": "polite" } });
  const output = el("div", { className: "output" });
  let current = group.tools[0];

  function renderForm() {
    about.textContent = current.about || "";
    for (const button of picker.children) button.classList.toggle("active", button.dataset.tool === current.id);
    const fields = current.fields.map((field) => fieldControl(field, values));
    const submit = el("button", { className: "primary", text: current.id === "verify_token" ? "Create" : "Run",
      attrs: { type: "submit" } });
    form.replaceChildren(...fields, submit);
    const first = form.querySelector("input, textarea");
    if (first) first.focus();
  }

  if (group.tools.length > 1) {
    for (const tool of group.tools) {
      const button = el("button", { text: tool.label, attrs: { type: "button", "data-tool": tool.id } });
      button.addEventListener("click", () => {
        current = tool;
        output.replaceChildren();
        setStatus(status, "");
        renderForm();
      });
      picker.append(button);
    }
  }

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const submit = form.querySelector("button[type=submit]");
    submit.disabled = true;
    output.replaceChildren();
    const stop = startTimer(status, "Running...");
    try {
      const args = await collectArgs(current, form);
      if (current.special === "report") {
        const data = await api("/api/report", args);
        stop();
        setStatus(status, "Report ready.", "ok");
        showReport(output, data);
      } else {
        const data = await api("/api/tool", { tool: current.id, args });
        stop();
        setStatus(status, "Done.", "ok");
        showResult(output, current, data.result, args);
      }
    } catch (error) {
      stop();
      setStatus(status, error.message, "error");
    } finally {
      submit.disabled = false;
    }
  });

  renderForm();
  panel.append(group.tools.length > 1 ? picker : null, about, form, status, output);
  return panel;
}

function fieldControl(field, values) {
  if (field.type === "checkbox") {
    const box = el("input", { attrs: { type: "checkbox", name: field.name } });
    box.checked = Boolean(values[field.name] ?? field.value ?? false);
    box.addEventListener("change", () => { values[field.name] = box.checked; });
    return el("label", { className: "check" }, [box, ` ${field.label}`]);
  }
  let input;
  if (field.type === "textarea") {
    input = el("textarea", { attrs: { name: field.name, rows: "4", spellcheck: "false" } });
  } else {
    input = el("input", { attrs: { name: field.name, type: field.type || "text", autocomplete: "off", spellcheck: "false" } });
    if (field.accept) input.setAttribute("accept", field.accept);
    if (field.type === "number") input.setAttribute("min", "1");
  }
  if (field.placeholder) input.setAttribute("placeholder", field.placeholder);
  if (!field.optional) input.required = true;
  if (field.type !== "file") {
    input.value = values[field.name] ?? field.value ?? "";
    input.addEventListener("input", () => { values[field.name] = input.value; });
  }
  const wide = field.type === "textarea" || ["domain", "url", "target", "hostname", "address", "token"].includes(field.name);
  return el("label", { className: `field${wide ? " grow" : ""}` }, [el("span", { text: field.label }), input]);
}

async function collectArgs(tool, form) {
  const args = {};
  for (const field of tool.fields) {
    const input = form.elements[field.name];
    if (field.type === "checkbox") args[field.name] = input.checked;
    else if (field.type === "file") {
      const file = input.files[0];
      if (!file) throw new Error(`choose ${field.label.toLowerCase()}`);
      if (file.size > MAX_UPLOAD_BYTES) throw new Error(`${file.name} is larger than 20 MB`);
      if (tool.special === "json-files") {
        try {
          args[field.name] = JSON.parse(await readFile(file, "text"));
        } catch {
          throw new Error(`${file.name} is not valid JSON`);
        }
      } else {
        args.name = file.name;
        args.data = String(await readFile(file, "data-url")).split(",", 2)[1] || "";
      }
    } else args[field.name] = input.value.trim();
  }
  return args;
}

function showResult(output, tool, result, args) {
  const label = args.domain || args.url || args.target || args.ip || args.address || args.hostname || args.name || tool.id;
  const exportButton = el("button", { text: "Export JSON", attrs: { type: "button" } });
  exportButton.addEventListener("click", () =>
    download(`${tool.id}-${fileName(String(label))}.json`, JSON.stringify(result, null, 2), "application/json"));
  const children = [el("div", { className: "run-actions" }, exportButton)];
  if (tool.id === "verify_token") {
    children.push(el("p", {}, [
      el("code", { className: "token", text: result.token }),
      el("span", { className: "muted", text: "  Put it in the bio of each profile you own, then use Check profiles." }),
    ]));
  } else if (tool.id === "diff" && result.changes && !result.changes.length) {
    children.push(el("p", { text: "No changes between the two reports." }));
  } else {
    children.push(renderValue(result));
  }
  output.replaceChildren(...children);
}

function showReport(output, data) {
  const target = fileName(String(data.report.target));
  const jsonButton = el("button", { text: "Download JSON", attrs: { type: "button" } });
  const htmlButton = el("button", { text: "Download HTML", attrs: { type: "button" } });
  jsonButton.addEventListener("click", () =>
    download(`report-${target}.json`, JSON.stringify(data.report, null, 2), "application/json"));
  htmlButton.addEventListener("click", () => download(`report-${target}.html`, data.html, "text/html"));
  const frame = el("iframe", {
    className: "report-frame",
    attrs: { title: "Report", sandbox: "allow-popups allow-popups-to-escape-sandbox" },
  });
  frame.srcdoc = data.html;
  fill(output,
    el("div", { className: "run-actions" }, [jsonButton, htmlButton]),
    data.history ? changesBanner(data.history, "domain") : null,
    frame,
  );
}

/* ---------- history: shared rendering ---------- */

function formatDate(iso) {
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? iso : date.toLocaleString();
}

function compact(value) {
  if (value === null || value === undefined) return "-";
  const text = typeof value === "string" ? value : JSON.stringify(value);
  return text.length > 300 ? `${text.slice(0, 300)}...` : text;
}

/** "N changes since <date>" with an inline, on-demand list of the changes. */
function changesBanner(info, noun) {
  if (!info.previous_id) {
    return el("div", { className: "banner" }, el("span", {
      text: `Saved to history. This is the first saved run for this ${noun}; next time you will see what changed.`,
    }));
  }
  const box = el("div", { className: "hidden" });
  const button = el("button", { text: "Show changes", attrs: { type: "button" } });
  button.disabled = !info.changes;
  button.addEventListener("click", async () => {
    if (!box.classList.contains("hidden")) {
      box.classList.add("hidden");
      button.textContent = "Show changes";
      return;
    }
    box.classList.remove("hidden");
    button.textContent = "Hide changes";
    if (box.childElementCount) return;
    try {
      box.append(changesView(await api("/api/history/compare", { old_id: info.previous_id, new_id: info.id })));
    } catch (error) {
      box.append(el("p", { className: "error", text: error.message }));
    }
  });
  const label = info.changes
    ? `${info.changes} change(s) since the last run on ${formatDate(info.previous_at)}.`
    : `No changes since the last run on ${formatDate(info.previous_at)}.`;
  return el("div", { className: `banner ${info.changes ? "changed" : ""}` }, [
    el("div", { className: "banner-row" }, [el("span", { text: label }), info.changes ? button : null]),
    box,
  ]);
}

function changesView(comparison) {
  const parts = [];
  if (comparison.alerts && comparison.alerts.length) {
    parts.push(el("ul", { className: "alerts" }, comparison.alerts.map((alert) => el("li", { text: alert }))));
  }
  if (!comparison.changes.length) {
    parts.push(el("p", { className: "muted", text: "No changes." }));
  } else {
    parts.push(el("div", { className: "scroll" }, el("table", { className: "table" }, [
      el("thead", {}, el("tr", {}, ["Change", "Where", "Before", "After"].map((h) => el("th", { text: h })))),
      el("tbody", {}, comparison.changes.map((change) => el("tr", {}, [
        el("td", {}, el("span", { className: `pill change-${change.change}`, text: change.change })),
        el("td", { className: "mono", text: change.path }),
        el("td", { text: change.change === "added" ? "" : compact(change.old) }),
        el("td", { text: change.change === "removed" ? "" : compact(change.new) }),
      ]))),
    ])));
  }
  return el("div", { className: "changes" }, parts);
}

/* ---------- username: site picker ---------- */

let allSites = [];

function selectedSites() {
  return [...document.querySelectorAll("#sites-grid input:checked")].map((box) => box.value);
}

function updateSitesCount() {
  const count = selectedSites().length;
  $("sites-count").textContent = count === allSites.length ? `all ${count}` : `${count} of ${allSites.length}`;
}

async function loadSites() {
  try {
    const data = await api("/api/sites");
    $("version").textContent = `v${data.version}`;
    allSites = data.sites;
    const grid = $("sites-grid");
    for (const site of allSites) {
      const box = el("input", { attrs: { type: "checkbox", value: site.name } });
      box.checked = true;
      box.addEventListener("change", updateSitesCount);
      grid.append(el("label", { className: "check" }, [box, ` ${site.label}`]));
    }
    updateSitesCount();
  } catch (error) {
    setStatus($("footprint-status"), error.message, "error");
  }
}

$("sites-all").addEventListener("click", () => {
  for (const box of document.querySelectorAll("#sites-grid input")) box.checked = true;
  updateSitesCount();
});
$("sites-none").addEventListener("click", () => {
  for (const box of document.querySelectorAll("#sites-grid input")) box.checked = false;
  updateSitesCount();
});

/* ---------- username: results ---------- */

let lastRuns = [];

function profileList(result) {
  const list = el("dl", { className: "profile" });
  const add = (label, value) => list.append(el("dt", { text: label }), el("dd", {}, value));
  if (result.owner_verified !== null && result.owner_verified !== undefined) {
    add("Audit token", el("span", { text: result.owner_verified ? "found - verified as yours" : "not found" }));
  }
  for (const [name, value] of Object.entries(result.profile || {})) {
    if (name === "stats") continue;
    if (name === "website") add(PROFILE_LABELS[name], safeLink(value));
    else if (name === "created_at") add(PROFILE_LABELS[name], el("span", { text: formatDay(value) }));
    else if (value && typeof value === "object") {
      add(PROFILE_LABELS[name] || name, el("span", {
        text: Object.entries(value).map(([label, item]) => `${label}: ${item}`).join(", "),
      }));
    } else add(PROFILE_LABELS[name] || name, clampedText(value));
  }
  if (!result.profile || !result.profile.display_name) {
    if (result.page_title) add("Page title", clampedText(result.page_title, 2));
    if (result.meta_description && !result.profile?.bio) {
      add("Description", clampedText(result.meta_description));
    }
  }
  if (result.profile_note) add("Details", el("span", { className: "muted", text: result.profile_note }));
  return list.childElementCount ? list : null;
}

function statsRow(stats) {
  if (!stats) return null;
  return el("div", { className: "stats" },
    Object.entries(stats).map(([label, value]) =>
      el("span", { className: "stat" }, [
        el("strong", { text: Number(value).toLocaleString() }),
        el("span", { text: ` ${label}` }),
      ])));
}

/** Long remote text, cut to a few lines; the full text is in the tooltip. */
function clampedText(value, lines = 4) {
  const text = String(value);
  return el("span", { className: `clamp clamp-${lines}`, text, attrs: { title: text } });
}

function formatDay(value) {
  const date = new Date(value);
  if (!/^\d{4}-\d{2}-\d{2}/.test(String(value)) || Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}

function siteLabel(name) {
  const site = allSites.find((item) => item.name === name);
  if (site) return site.label;
  const mastodon = /^mastodon@(.+)$/.exec(name);
  return mastodon ? `Mastodon (${mastodon[1]})` : name;
}

function resultCard(result) {
  const head = el("div", { className: "card-head" }, [
    el("span", { className: "site", text: siteLabel(result.site) }),
    el("span", { className: `pill ${result.state}`, text: STATE_LABELS[result.state] || result.state }),
    result.confidence ? el("span", { className: `confidence ${result.confidence}`, text: result.confidence }) : null,
  ]);
  const card = el("article", { className: `card ${result.state}` }, [
    head,
    el("div", { className: "url" }, safeLink(result.url)),
  ]);
  if (result.discovered_from) {
    card.append(el("div", { className: "muted small", text: `Declared on ${result.discovered_from}` }));
  }
  if (result.found) {
    const stats = statsRow(result.profile && result.profile.stats);
    const details = profileList(result);
    if (stats) card.append(stats);
    if (details) card.append(details);
  } else {
    card.append(el("div", { className: "muted small", text: result.match_basis.replaceAll("_", " ") }));
  }
  return card;
}

function summaryBar(results) {
  const count = (state) => results.filter((result) => result.state === state).length;
  return el("div", { className: "summary" }, [
    ["found", "Found"], ["not_found", "Not found"], ["unknown", "Unknown"],
    ["rate_limited", "Rate limited"], ["not_applicable", "N/A"],
  ].filter(([state]) => state === "found" || count(state) > 0)
    .map(([state, label]) => el("span", { className: `count ${state}` }, [
      el("strong", { text: count(state) }), el("span", { text: ` ${label}` }),
    ])));
}

function renderRuns() {
  const container = $("footprint-results");
  container.replaceChildren();
  const foundOnly = $("opt-found-only").checked;
  for (const run of lastRuns) {
    const visible = run.results.filter((result) => !foundOnly || result.found);
    const linksButton = el("button", { text: "Search links", attrs: { type: "button" } });
    const exportButton = el("button", { text: "Export JSON", attrs: { type: "button" } });
    const linksBox = el("div", { className: "links-box hidden" });
    linksButton.addEventListener("click", () => toggleSearchLinks(run.username, linksBox, linksButton));
    exportButton.addEventListener("click", () =>
      download(`footprint-${fileName(run.username)}.json`, JSON.stringify(run, null, 2), "application/json"));

    const running = !run.done;
    exportButton.disabled = running;
    let emptyText = null;
    if (!visible.length) {
      if (running) emptyText = "Waiting for the first profile...";
      else if (run.error) emptyText = null;
      else emptyText = foundOnly ? "Not found on any checked site." : "No results.";
    }
    container.append(el("section", { className: "run" }, [
      el("div", { className: "run-head" }, [
        el("h2", { text: run.username }),
        el("div", { className: "run-actions" }, [linksButton, exportButton]),
      ]),
      running ? progressBar(run.results.length, run.total) : null,
      summaryBar(run.results),
      run.error ? el("p", { className: "error", text: run.error }) : null,
      run.history ? changesBanner(run.history, "username") : null,
      linksBox,
      el("div", { className: "grid" }, visible.map(resultCard)),
      emptyText ? el("p", { className: "muted", text: emptyText }) : null,
    ]));
  }
}

function progressBar(done, total) {
  const bar = el("progress", { attrs: { max: String(total || 1), value: String(done) } });
  return el("div", { className: "progress" }, [bar, el("span", { className: "muted small", text: `${done} / ${total} sites` })]);
}

/** POST and read newline-delimited JSON events as they arrive. */
async function streamApi(path, payload, onEvent) {
  const response = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Recon-Token": TOKEN },
    body: JSON.stringify(payload),
  });
  if (!response.ok) {
    let data = {};
    try {
      data = await response.json();
    } catch {
      /* handled below */
    }
    throw new Error(data.error || `request failed (HTTP ${response.status})`);
  }
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  for (;;) {
    const { value, done } = await reader.read();
    buffer += decoder.decode(value || new Uint8Array(), { stream: !done });
    let newline;
    while ((newline = buffer.indexOf("\n")) >= 0) {
      const line = buffer.slice(0, newline).trim();
      buffer = buffer.slice(newline + 1);
      if (line) onEvent(JSON.parse(line));
    }
    if (done) break;
  }
}

async function toggleSearchLinks(username, box, button) {
  if (!box.classList.contains("hidden")) {
    box.classList.add("hidden");
    return;
  }
  box.classList.remove("hidden");
  if (box.childElementCount) return;
  button.disabled = true;
  try {
    const links = await api("/api/search-links", { username });
    box.append(
      el("h3", { text: "Exact-match web searches" }),
      el("ul", {}, Object.entries(links.search_engines).map(([engine, url]) =>
        el("li", {}, [el("strong", { text: `${engine}: ` }), safeLink(url, `"${username}"`)]))),
      el("h3", { text: "Wayback Machine history" }),
      el("ul", { className: "columns" }, Object.entries(links.archived_profiles).map(([site, url]) =>
        el("li", {}, safeLink(url, site)))),
    );
  } catch (error) {
    box.append(el("p", { className: "error", text: error.message }));
  } finally {
    button.disabled = false;
  }
}

$("opt-found-only").addEventListener("change", renderRuns);

$("footprint-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const status = $("footprint-status");
  const sites = selectedSites();
  if (!sites.length) {
    setStatus(status, "Select at least one site.", "error");
    return;
  }
  const submit = $("footprint-submit");
  submit.disabled = true;
  $("footprint-empty").classList.add("hidden");
  lastRuns = [];
  renderRuns();
  const stop = startTimer(status, "Checking sites...");
  const runFor = (username) => lastRuns.find((run) => run.username === username);
  try {
    await streamApi("/api/footprint/stream", {
      usernames: $("usernames").value,
      details: $("opt-details").checked,
      sites: sites.length === allSites.length ? [] : sites,
      mastodon: $("opt-mastodon").value,
      audit_token: $("opt-audit").value.trim(),
      save: $("opt-save").checked,
    }, (event) => {
      if (event.type === "start") {
        lastRuns.push({ username: event.username, total: event.total, results: [], done: false, history: null });
      } else if (event.type === "result") {
        runFor(event.username)?.results.push(event.result);
      } else if (event.type === "done") {
        Object.assign(runFor(event.username), { results: event.results, done: true, history: event.history || null });
      } else if (event.type === "error") {
        const run = runFor(event.username);
        if (run) Object.assign(run, { done: true, error: event.error });
      }
      if (event.type !== "end") renderRuns();
    });
    stop();
    const found = lastRuns.reduce((total, run) => total + run.results.filter((r) => r.found).length, 0);
    setStatus(status, `Done. ${found} profile(s) found.`, "ok");
  } catch (error) {
    stop();
    setStatus(status, error.message, "error");
  } finally {
    submit.disabled = false;
  }
});

/* ---------- self-test ---------- */

$("selftest-run").addEventListener("click", async () => {
  const status = $("selftest-status");
  const button = $("selftest-run");
  button.disabled = true;
  const stop = startTimer(status, "Testing rules...");
  try {
    const data = await api("/api/self-test");
    stop();
    const broken = data.rules.filter((rule) => rule.status === "broken").length;
    setStatus(status, `${data.rules.length - broken} of ${data.rules.length} rules not broken.`, broken ? "error" : "ok");
    const rows = data.rules.map((rule) => el("tr", {}, [
      el("td", { text: siteLabel(rule.site) }),
      el("td", {}, el("span", { className: `pill rule-${rule.status}`, text: rule.status })),
      el("td", { text: rule.present ?? "-" }),
      el("td", { text: rule.absent ?? "-" }),
    ]));
    $("selftest-results").replaceChildren(el("table", { className: "table" }, [
      el("thead", {}, el("tr", {}, ["Site", "Status", "Known account", "Missing account"].map((h) => el("th", { text: h })))),
      el("tbody", {}, rows),
    ]));
  } catch (error) {
    stop();
    setStatus(status, error.message, "error");
  } finally {
    button.disabled = false;
  }
});

/* ---------- history tab ---------- */

const KIND_LABELS = { footprint: "Username", report: "Domain report" };

function summaryText(entry) {
  const summary = entry.summary || {};
  if (entry.kind === "footprint") {
    const sites = (summary.found_sites || []).map(siteLabel).join(", ");
    return `Found on ${summary.found ?? 0} of ${summary.checked ?? 0}${sites ? `: ${sites}` : ""}`;
  }
  const parts = [];
  if (summary.subdomains !== undefined) parts.push(`${summary.subdomains} subdomains`);
  if (summary.tls_days !== undefined && summary.tls_days !== null) parts.push(`TLS ${summary.tls_days} days`);
  if (summary.errors && summary.errors.length) parts.push(`errors: ${summary.errors.join(", ")}`);
  return parts.join(" · ") || "-";
}

function selectedHistoryIds() {
  return [...document.querySelectorAll("#history-list input[type=checkbox]:checked")].map((box) => box.value);
}

function updateCompareButton() {
  $("history-compare").disabled = selectedHistoryIds().length !== 2;
}

async function loadHistory() {
  const status = $("history-status");
  try {
    const data = await api("/api/history/list", { kind: $("history-kind").value, target: $("history-target").value });
    $("history-folder").textContent = `Saved only on this computer, in ${data.folder}`;
    setStatus(status, data.entries.length ? "" : "No saved runs yet. Searches and reports are saved when "
      + "\"Save to history\" is ticked.");
    if (!data.entries.length) {
      $("history-list").replaceChildren();
      return;
    }
    const rows = data.entries.map((entry) => {
      const box = el("input", { attrs: { type: "checkbox", value: entry.id, "aria-label": "Select for comparison" } });
      box.addEventListener("change", updateCompareButton);
      const view = el("button", { text: "View", attrs: { type: "button" } });
      const previous = el("button", { text: "vs previous", attrs: { type: "button" } });
      const remove = el("button", { text: "Delete", attrs: { type: "button" }, className: "danger" });
      view.addEventListener("click", () => showHistoryEntry(entry.id));
      previous.addEventListener("click", () => showComparison({ new_id: entry.id }));
      remove.addEventListener("click", async () => {
        if (!window.confirm(`Delete the saved run for ${entry.target} from ${formatDate(entry.created_at)}?`)) return;
        try {
          await api("/api/history/delete", { id: entry.id });
          $("history-output").replaceChildren();
          loadHistory();
        } catch (error) {
          setStatus(status, error.message, "error");
        }
      });
      return el("tr", {}, [
        el("td", {}, box),
        el("td", { className: "nowrap", text: formatDate(entry.created_at) }),
        el("td", { text: KIND_LABELS[entry.kind] || entry.kind }),
        el("td", { className: "strong nowrap", text: entry.target }),
        el("td", { className: "muted", text: summaryText(entry) }),
        el("td", {}, el("div", { className: "row-actions" }, [view, previous, remove])),
      ]);
    });
    $("history-list").replaceChildren(el("div", { className: "scroll" }, el("table", { className: "table" }, [
      el("thead", {}, el("tr", {}, ["", "Date", "Kind", "Target", "Summary", ""].map((h) => el("th", { text: h })))),
      el("tbody", {}, rows),
    ])));
    updateCompareButton();
  } catch (error) {
    setStatus(status, error.message, "error");
  }
}

async function showHistoryEntry(id) {
  const output = $("history-output");
  try {
    const data = await api("/api/history/get", { id });
    const heading = el("h2", { text: `${data.entry.target} · ${formatDate(data.entry.created_at)}` });
    if (data.entry.kind === "report") {
      const frame = el("iframe", {
        className: "report-frame",
        attrs: { title: "Saved report", sandbox: "allow-popups allow-popups-to-escape-sandbox" },
      });
      frame.srcdoc = data.html;
      output.replaceChildren(heading, frame);
    } else {
      const results = data.data.results || [];
      const found = results.filter((result) => result.found);
      fill(output, heading, summaryBar(results),
        el("div", { className: "grid" }, found.map(resultCard)),
        found.length ? null : el("p", { className: "muted", text: "Not found on any checked site." }));
    }
    output.scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (error) {
    setStatus($("history-status"), error.message, "error");
  }
}

async function showComparison(ids) {
  const output = $("history-output");
  try {
    const comparison = await api("/api/history/compare", ids);
    fill(output,
      el("h2", { text: `${comparison.new.target}: ${formatDate(comparison.old.created_at)} → `
        + `${formatDate(comparison.new.created_at)}` }),
      comparison.changes.length
        ? el("p", { className: "muted", text: `${comparison.changes.length} change(s).` })
        : null,
      changesView(comparison),
    );
    output.scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (error) {
    setStatus($("history-status"), error.message, "error");
  }
}

$("history-refresh").addEventListener("click", loadHistory);
$("history-kind").addEventListener("change", loadHistory);
$("history-target").addEventListener("input", () => {
  clearTimeout(loadHistory.timer);
  loadHistory.timer = setTimeout(loadHistory, 300);
});
$("history-compare").addEventListener("click", () => {
  const [newer, older] = selectedHistoryIds();  // the list is newest first
  showComparison({ old_id: older, new_id: newer });
});

buildToolPanels();
loadSites();
