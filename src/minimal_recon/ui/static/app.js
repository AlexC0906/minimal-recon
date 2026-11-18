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
          { name: "details", label: "Profile details for the username", type: "checkbox" }],
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
}

$("tabs").addEventListener("click", (event) => {
  const tab = event.target.closest(".tab");
  if (tab) activateTab(tab.dataset.tab);
});

/* ---------- generic tool panels ---------- */

function buildToolPanels() {
  const rulesTab = document.querySelector('.tab[data-tab="rules"]');
  const rulesPanel = $("tab-rules");
  for (const group of TOOL_TABS) {
    rulesTab.before(el("button", {
      className: "tab", text: group.label, attrs: { role: "tab", "aria-selected": "false", "data-tab": group.id },
    }));
    rulesPanel.before(buildPanel(group));
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
    box.checked = Boolean(values[field.name]);
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
  output.replaceChildren(el("div", { className: "run-actions" }, [jsonButton, htmlButton]), frame);
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
      grid.append(el("label", { className: "check" }, [box, ` ${site.name}`]));
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
    else if (value && typeof value === "object") {
      add(PROFILE_LABELS[name] || name, el("span", {
        text: Object.entries(value).map(([label, item]) => `${label}: ${item}`).join(", "),
      }));
    } else add(PROFILE_LABELS[name] || name, el("span", { text: value }));
  }
  if (!result.profile || !result.profile.display_name) {
    if (result.page_title) add("Page title", el("span", { text: result.page_title }));
    if (result.meta_description && !result.profile?.bio) {
      add("Description", el("span", { text: result.meta_description }));
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

function resultCard(result) {
  const head = el("div", { className: "card-head" }, [
    el("span", { className: "site", text: result.site }),
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
  ].map(([state, label]) => el("span", { className: `count ${state}` }, [
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

    container.append(el("section", { className: "run" }, [
      el("div", { className: "run-head" }, [
        el("h2", { text: run.username }),
        el("div", { className: "run-actions" }, [linksButton, exportButton]),
      ]),
      summaryBar(run.results),
      linksBox,
      el("div", { className: "grid" }, visible.map(resultCard)),
      visible.length ? null : el("p", {
        className: "muted",
        text: foundOnly ? "Not found on any checked site." : "No results.",
      }),
    ]));
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
  const stop = startTimer(status, "Checking sites...");
  try {
    const data = await api("/api/footprint", {
      usernames: $("usernames").value,
      details: $("opt-details").checked,
      sites: sites.length === allSites.length ? [] : sites,
      mastodon: $("opt-mastodon").value,
      audit_token: $("opt-audit").value.trim(),
    });
    lastRuns = data.runs;
    stop();
    const found = lastRuns.reduce((total, run) => total + run.results.filter((r) => r.found).length, 0);
    setStatus(status, `Done. ${found} profile(s) found.`, "ok");
    renderRuns();
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
      el("td", { text: rule.site }),
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

buildToolPanels();
loadSites();
