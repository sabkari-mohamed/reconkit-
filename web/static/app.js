/* ReconKit dashboard front-end. Streams a scan over SSE and renders the
   aggregated result: risk grade, stat cards, factor chart, detail tables. */
"use strict";

const $ = (sel) => document.querySelector(sel);
const el = (tag, cls) => { const e = document.createElement(tag); if (cls) e.className = cls; return e; };
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const GRADE = { A: "var(--grade-A)", B: "var(--grade-B)", C: "var(--grade-C)", D: "var(--grade-D)", F: "var(--grade-F)" };
const ICON = (id) => `<svg class="ic" aria-hidden="true"><use href="#${id}"/></svg>`;
const MOD_INFO = {
  subdomains: (i) => `${i.found} found`, dns: (i) => `SPF ${i.spf ? "✓" : "✗"} · DMARC ${i.dmarc ? "✓" : "✗"}`,
  whois: () => "", tools: (i) => `${i.used}/${i.installed} tool(s)`,
  asn: (i) => `${i.networks} network(s)`, urlscan: (i) => `${i.results} scan(s)`,
  threat: (i) => `${i.pulses} pulse(s)`, wayback: (i) => `${i.urls} URL(s)`,
  emails: (i) => i.key ? `${i.found} found` : "no key", shodan: (i) => i.key ? `${i.hosts} host(s)` : "no key",
};

let lastData = null, timer = null, t0 = 0, source = null;

/* ---------- scan lifecycle ---------- */
$("#scan-form").addEventListener("submit", (ev) => {
  ev.preventDefault();
  const domain = $("#domain").value.trim().toLowerCase().replace(/^\*\./, "");
  const errEl = $("#domain-help");
  if (!/^([a-z0-9](-?[a-z0-9])*\.)+[a-z]{2,}$/i.test(domain)) {
    errEl.textContent = "Enter a valid domain, e.g. example.com"; errEl.hidden = false; return;
  }
  errEl.hidden = true;
  const modules = [...document.querySelectorAll('input[name="m"]:checked')].map((c) => c.value);
  if (!modules.length) { errEl.textContent = "Select at least one module."; errEl.hidden = false; return; }
  startScan(domain, modules);
});

function startScan(domain, modules) {
  if (source) source.close();
  setRunning(true);
  $("#results").hidden = true;
  const prog = $("#progress"); prog.hidden = false;
  $("#prog-domain").textContent = domain;
  const list = $("#modlist"); list.innerHTML = "";
  modules.forEach((m) => list.appendChild(modRow(m)));
  t0 = performance.now();
  clearInterval(timer);
  timer = setInterval(() => { $("#prog-elapsed").textContent = ((performance.now() - t0) / 1000).toFixed(1) + "s"; }, 100);

  const url = `/api/scan?domain=${encodeURIComponent(domain)}&modules=${encodeURIComponent(modules.join(","))}`;
  source = new EventSource(url);
  source.addEventListener("module", (e) => updateMod(JSON.parse(e.data)));
  source.addEventListener("result", (e) => { lastData = JSON.parse(e.data); renderResult(lastData); });
  source.addEventListener("done", () => finish());
  source.onerror = () => { if (source.readyState === EventSource.CLOSED) return; finish(true); };
}

function finish(failed) {
  clearInterval(timer);
  if (source) source.close();
  setRunning(false);
  if (failed && !lastData) {
    const errEl = $("#domain-help");
    errEl.textContent = "Scan stream interrupted. Check the server and try again.";
    errEl.hidden = false;
  }
}

function setRunning(on) {
  const btn = $("#run");
  btn.disabled = on;
  btn.querySelector(".cta-label").textContent = on ? "Scanning…" : "Run Recon";
  btn.querySelector(".spinner").hidden = !on;
}

/* ---------- progress rows ---------- */
function modRow(name) {
  const li = el("li", "modrow"); li.id = `mod-${name}`;
  li.innerHTML = `<span class="dot"><span class="mini"></span></span>
    <span class="nm">${esc(name)}</span><span class="info"></span>`;
  return li;
}
function updateMod({ name, status, info, error }) {
  const row = $(`#mod-${name}`); if (!row) return;
  row.className = `modrow ${status}`;
  const infoEl = row.querySelector(".info");
  const dot = row.querySelector(".dot");
  if (status === "done") {
    dot.innerHTML = ICON("i-check");
    infoEl.textContent = (MOD_INFO[name] ? MOD_INFO[name](info || {}) : "");
  } else if (status === "error") {
    dot.innerHTML = ICON("i-alert"); infoEl.textContent = error || "error";
  }
}

/* ---------- result rendering ---------- */
function renderResult(d) {
  $("#progress").hidden = true;
  $("#results").hidden = false;
  $("#r-domain").textContent = d.target;

  const risk = d.risk || {}; const grade = risk.grade || "A";
  const color = GRADE[grade] || GRADE.A;
  $("#r-grade").textContent = grade;
  $("#r-grade").style.color = color;
  $("#r-score").textContent = risk.score ?? 0;
  $("#r-summary").textContent = risk.summary || "";
  const ring = $("#ring-fg"); const C = 327;
  ring.style.stroke = color;
  ring.style.strokeDashoffset = C * (1 - (risk.score || 0) / 100);

  renderCards(d.summary || {});
  renderChart(risk.factors || []);
  renderNotes(d.security_notes || []);
  renderSections(d);
  $("#results").scrollIntoView({ behavior: "smooth", block: "start" });
}

function renderCards(s) {
  const defs = [
    ["i-globe", "Subdomains", s.subdomains], ["i-server", "Live hosts", s.live_hosts],
    ["i-network", "ASNs", s.asn_count], ["i-link", "Archived URLs", s.archived_urls],
    ["i-shield", "Open ports", s.open_ports], ["i-alert", "Threat pulses", s.threat_pulses],
  ];
  $("#cards").innerHTML = defs.map(([ic, label, val]) =>
    `<div class="card"><div class="ck">${ICON(ic)} ${esc(label)}</div>
     <div class="cv">${esc(val ?? 0)}</div></div>`).join("");
}

function renderChart(factors) {
  const box = $("#chart");
  if (!factors.length) { box.innerHTML = `<div class="chart-empty">No risk factors — clean exposure.</div>`; $("#chart-table").innerHTML = ""; return; }
  const max = Math.max(...factors.map((f) => f.points), 1);
  box.innerHTML = factors.map((f) =>
    `<div class="bar-row"><div class="bar-top"><span>${esc(f.name)}</span><span class="pts">+${esc(f.points)}</span></div>
     <div class="bar-track"><div class="bar-fill" data-w="${Math.round(f.points / max * 100)}"></div></div></div>`).join("");
  requestAnimationFrame(() => box.querySelectorAll(".bar-fill").forEach((b) => { b.style.width = b.dataset.w + "%"; }));
  $("#chart-table").innerHTML = "<tr><th>Factor</th><th>Points</th></tr>" +
    factors.map((f) => `<tr><td>${esc(f.name)}</td><td>${esc(f.points)}</td></tr>`).join("");
}

function renderNotes(notes) {
  const ul = $("#notes");
  if (!notes.length) { ul.innerHTML = `<li class="ok">${ICON("i-check")} No security notes flagged.</li>`; return; }
  ul.innerHTML = notes.map((n) => `<li>${ICON("i-alert")} <span>${esc(n)}</span></li>`).join("");
}

/* ---------- detail sections ---------- */
function section(title, icon, count, bodyHTML, scroll) {
  const wrap = el("div", "panel sec");
  const cnt = count != null ? `<span class="count">(${count})</span>` : "";
  wrap.innerHTML = `<h3 class="sec-title">${ICON(icon)} ${esc(title)} ${cnt}</h3>
    <div class="tbl-wrap${scroll ? " scroll" : ""}">${bodyHTML}</div>`;
  return wrap;
}
function table(headers, rows) {
  return `<table class="data"><thead><tr>${headers.map((h) => `<th>${esc(h)}</th>`).join("")}</tr></thead>
    <tbody>${rows.map((r) => `<tr>${r.map((c) => `<td>${c}</td>`).join("")}</tr>`).join("")}</tbody></table>`;
}

function renderSections(d) {
  const root = $("#sections"); root.innerHTML = "";

  const subs = d.subdomains || [];
  if (subs.length) {
    const rows = subs.map((s) => [
      `<span class="mono">${esc(s.subdomain)}</span>`,
      s.resolves ? `<span class="badge live">live</span>` : s.resolves === null ? `<span class="badge dead">—</span>` : `<span class="badge dead">historical</span>`,
      `<span class="mono">${esc(s.ip || "—")}</span>`]);
    root.appendChild(section("Subdomains", "i-globe", subs.length, table(["Subdomain", "Resolves", "IP"], rows), subs.length > 12));
  }

  const dns = d.dns || {};
  if (dns.records) {
    const rows = Object.entries(dns.records).map(([t, vals]) =>
      [`<span class="mono">${esc(t)}</span>`, vals.length ? vals.map((v) => `<div class="mono">${esc(v)}</div>`).join("") : `<span class="muted">none</span>`]);
    root.appendChild(section("DNS records", "i-server", null, table(["Type", "Values"], rows)));
  }

  const w = d.whois || {};
  if (w && !w.error && Object.keys(w).length) {
    const rows = [
      ["Registrar", esc(w.registrar || "—")], ["Created", esc(w.creation_date || "—")],
      ["Expires", esc(w.expiration_date || "—") + (w.expiring_soon ? ` <span class="badge bad">${esc(w.days_to_expiry)}d</span>` : "")],
      ["Org", esc(w.registrant_org || "—")], ["Country", esc(w.registrant_country || "—")],
      ["Name servers", (w.name_servers || []).map((n) => `<span class="tag mono">${esc(n)}</span>`).join("") || "—"]];
    root.appendChild(section("WHOIS", "i-shield", null, table(["Field", "Value"], rows)));
  }

  const nets = (d.asn || {}).networks || [];
  if (nets.length) {
    const rows = nets.map((n) => [`<span class="mono">${esc(n.asn || "—")}</span>`, esc(n.as_name || "—"),
      `<span class="mono">${esc(n.prefix || "—")}</span>`, esc(n.country || "—")]);
    root.appendChild(section("Networks / ASN", "i-network", nets.length, table(["ASN", "Organisation", "Prefix", "Country"], rows)));
  }

  const tools = d.tools || {};
  if (tools.available && Object.keys(tools.available).length) {
    const rows = Object.entries(tools.available).map(([name, ok]) => [
      `<span class="mono">${esc(name)}</span>`,
      ok ? `<span class="badge live">installed</span>` : `<span class="badge dead">not installed</span>`,
      `<span class="mono">${ok ? esc((tools.counts || {})[name] || 0) : "—"}</span>`]);
    root.appendChild(section("Tool orchestration", "i-network", (tools.used || []).length + " used",
      table(["Tool", "Status", "Results"], rows)));
  }

  const interesting = (d.urls || {}).interesting || [];
  if (interesting.length) {
    const rows = interesting.map((i) => [`<span class="tag bad">${esc(i.match)}</span>`, `<span class="mono">${esc(i.url)}</span>`]);
    root.appendChild(section("Sensitive archived URLs", "i-link", interesting.length, table(["Match", "URL"], rows), true));
  }

  const t = d.threat || {};
  if (t.pulses || (t.passive_dns || []).length) {
    const rows = [["Threat pulses", t.malicious ? `<span class="badge bad">${esc(t.pulses)} pulse(s)</span>` : `<span class="badge live">clean (${esc(t.pulses)})</span>`],
      ["Passive DNS records", esc((t.passive_dns || []).length)]];
    root.appendChild(section("Threat intelligence (AlienVault OTX)", "i-alert", null, table(["Signal", "Value"], rows)));
  }

  const emails = d.emails || [];
  if (emails.length) {
    const rows = emails.map((e) => [`<span class="mono">${esc(e.email)}</span>`,
      esc(`${e.first_name || ""} ${e.last_name || ""}`.trim() || "—"), esc(e.position || "—"), esc(e.confidence ?? "—")]);
    root.appendChild(section("Emails", "i-mail", emails.length, table(["Email", "Name", "Position", "Confidence"], rows)));
  }

  const shodan = d.shodan || [];
  if (shodan.length) {
    const rows = shodan.map((h) => [`<span class="mono">${esc(h.ip)}</span>`,
      (h.ports || []).map((p) => `<span class="tag mono">${esc(p)}</span>`).join("") || "—",
      esc(h.org || "—"), (h.vulns || []).map((v) => `<span class="tag bad">${esc(v)}</span>`).join("") || "—"]);
    root.appendChild(section("Shodan hosts", "i-server", shodan.length, table(["IP", "Ports", "Org", "Vuln tags"], rows)));
  }
}

/* ---------- downloads ---------- */
function download(name, text, type) {
  const blob = new Blob([text], { type });
  const a = el("a"); a.href = URL.createObjectURL(blob); a.download = name;
  document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(a.href);
}
$("#dl-json").addEventListener("click", () => {
  if (lastData) download(`${lastData.target}_recon.json`, JSON.stringify(lastData, null, 2), "application/json");
});
$("#dl-md").addEventListener("click", () => { if (lastData) download(`${lastData.target}_recon.md`, toMarkdown(lastData), "text/markdown"); });

function toMarkdown(d) {
  const r = d.risk || {}, s = d.summary || {};
  let md = `# ReconKit OSINT Report — ${d.target}\n\n_Scan: ${d.scan_date}_\n\n`;
  md += `## Exposure: Grade ${r.grade} (${r.score}/100)\n\n> ${r.summary}\n\n## Summary\n\n| Metric | Count |\n|---|---|\n`;
  [["Subdomains", "subdomains"], ["Live hosts", "live_hosts"], ["ASNs", "asn_count"],
   ["Archived URLs", "archived_urls"], ["Open ports", "open_ports"], ["Threat pulses", "threat_pulses"]]
    .forEach(([l, k]) => { md += `| ${l} | ${s[k] ?? 0} |\n`; });
  md += `\n## Security Notes\n\n` + ((d.security_notes || []).map((n) => `- ${n}`).join("\n") || "- None flagged.");
  md += `\n\n---\n_Generated by ReconKit v${(d.meta || {}).version || ""} — for authorized OSINT only._\n`;
  return md;
}
