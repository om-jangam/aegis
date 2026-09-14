"use strict";

// Every value from the API is rendered with textContent; nothing is parsed as HTML.
(function () {
  const REFRESH_MS = 5000;
  const TOKEN_KEY = "aegis-token";

  function readToken() {
    const match = /(?:^|[#&])token=([^&]+)/.exec(location.hash);
    if (match) {
      const token = decodeURIComponent(match[1]);
      try { sessionStorage.setItem(TOKEN_KEY, token); } catch (e) { /* storage blocked */ }
      // Drop the secret from the address bar, history and screenshots.
      history.replaceState(null, "", location.pathname);
      return token;
    }
    try { return sessionStorage.getItem(TOKEN_KEY); } catch (e) { return null; }
  }

  const token = readToken();
  const $ = (id) => document.getElementById(id);

  function el(tag, props, ...children) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(props || {})) {
      if (key === "class") node.className = value;
      else if (key === "onclick") node.addEventListener("click", value);
      else node.setAttribute(key, value);
    }
    for (const child of children) {
      if (child === null || child === undefined) continue;
      node.append(child instanceof Node ? child : document.createTextNode(String(child)));
    }
    return node;
  }

  async function api(path, method = "GET") {
    const response = await fetch(path, {
      method,
      headers: { Authorization: "Bearer " + (token || "") },
      cache: "no-store",
    });
    if (response.status === 401) {
      $("auth-error").hidden = false;
      throw new Error("unauthorised");
    }
    if (!response.ok) throw new Error(path + " failed: " + response.status);
    return response.json();
  }

  function when(ts) {
    const date = new Date(ts);
    if (Number.isNaN(date.getTime())) return ts || "";
    const seconds = Math.round((Date.now() - date.getTime()) / 1000);
    if (seconds < 60) return "just now";
    if (seconds < 3600) return Math.floor(seconds / 60) + " min ago";
    if (seconds < 86400) return Math.floor(seconds / 3600) + " h ago";
    return date.toLocaleString();
  }

  const badge = (severity) =>
    el("span", { class: "sev sev-" + String(severity || "info").toLowerCase() }, severity);

  function replace(target, rows, emptyText, columns) {
    const node = $(target);
    node.replaceChildren();
    if (!rows.length) {
      const cell = el("td", { class: "empty" }, emptyText);
      if (columns) cell.setAttribute("colspan", columns);
      node.append(columns ? el("tr", {}, cell) : el("li", { class: "empty" }, emptyText));
      return;
    }
    node.append(...rows);
  }

  function renderBars(target, items, labelKey, emptyText) {
    const max = Math.max(1, ...items.map((item) => item.n));
    replace(target, items.map((item) => {
      const fill = el("span", { class: "fill" });
      fill.style.width = Math.round((item.n / max) * 100) + "%";
      return el("li", {},
        el("span", { class: "bar-label" }, item[labelKey]),
        el("span", { class: "track" }, fill),
        el("span", { class: "bar-value" }, item.n));
    }), emptyText);
  }

  async function refreshSummary() {
    const summary = await api("/api/summary");
    const stats = summary.stats;
    $("host").textContent = "Aegis " + summary.version + " on " + summary.platform;
    const live = $("live");
    live.textContent = summary.monitoring ? "monitoring live" : "viewing stored data";
    live.className = "pill " + (summary.monitoring ? "pill-live" : "pill-idle");
    $("kpi-open").textContent = stats.open_alerts;
    $("kpi-findings").textContent = stats.total_findings;
    $("kpi-events").textContent = stats.total_events;
    renderBars("techniques", stats.top_techniques, "technique", "No detections yet.");
    renderBars("remotes", stats.top_remote_ips, "remote_ip", "No remote connections recorded.");
  }

  async function refreshAlerts() {
    const alerts = await api("/api/alerts?limit=50");
    replace("alerts", alerts.map((alert) => el("tr", { class: alert.acknowledged ? "done" : "" },
      el("td", {}, badge(alert.severity)),
      el("td", {}, el("div", { class: "strong" }, alert.title), el("div", { class: "muted small" }, alert.technique)),
      el("td", { class: "mono" }, alert.source),
      el("td", { class: "nowrap" }, when(alert.ts)),
      el("td", {}, alert.acknowledged ? el("span", { class: "muted small" }, "acknowledged")
        : el("button", { type: "button", class: "small-btn", onclick: () => acknowledge(alert.id) }, "Acknowledge")),
    )), "No alerts. Nothing needs your attention.", 5);
  }

  async function refreshFindings() {
    const findings = await api("/api/findings?limit=50");
    replace("findings", findings.map((f) => el("tr", {},
      el("td", {}, badge(f.severity)),
      el("td", {}, el("div", { class: "strong" }, f.title),
        el("div", { class: "muted small" }, [f.technique, f.reasons].filter(Boolean).join(" - "))),
      el("td", { class: "mono" }, f.entity),
      el("td", { class: "small" }, f.guidance),
      el("td", { class: "nowrap" }, when(f.ts)),
    )), "No findings recorded.", 5);
  }

  async function refreshAudit() {
    const events = await api("/api/audit?limit=50");
    replace("audit", events.map((a) => el("tr", {},
      el("td", { class: "nowrap" }, when(a.ts)),
      el("td", {}, a.category),
      el("td", { class: "mono small" }, a.action),
      el("td", {}, a.message, a.detail ? el("div", { class: "muted small" }, a.detail) : null),
      el("td", { class: "muted" }, a.actor),
    )), "The audit trail is empty.", 5);
  }

  const STATUS_ORDER = { fail: 0, warn: 1, pass: 2, skip: 3 };

  async function refreshPosture(force) {
    const button = $("rerun");
    button.disabled = true;
    try {
      const report = await api("/api/posture" + (force ? "?refresh=1" : ""));
      $("kpi-score").textContent = report.score;
      $("kpi-grade").textContent = "grade " + report.grade;
      const results = [...report.results].sort((a, b) => STATUS_ORDER[a.status] - STATUS_ORDER[b.status]);
      replace("posture", results.map((r) => el("li", { class: "check check-" + r.status },
        el("div", { class: "check-line" },
          el("span", { class: "status status-" + r.status }, r.status.toUpperCase()),
          el("span", { class: "strong" }, r.title)),
        el("div", { class: "small" }, r.summary),
        r.details.length ? el("ul", { class: "details small" }, ...r.details.map((d) => el("li", {}, d))) : null,
        r.remediation ? el("div", { class: "fix small" }, el("span", { class: "strong" }, "Fix: "), r.remediation) : null,
      )), "No checks apply to this platform.");
    } finally {
      button.disabled = false;
    }
  }

  async function acknowledge(id) {
    await api("/api/alerts/" + encodeURIComponent(id) + "/ack", "POST");
    await Promise.all([refreshAlerts(), refreshSummary(), refreshAudit()]);
  }

  async function refreshAll() {
    try {
      await Promise.all([refreshSummary(), refreshAlerts(), refreshFindings(), refreshAudit()]);
    } catch (error) {
      if (error.message !== "unauthorised") {
        const live = $("live");
        live.textContent = "connection lost";
        live.className = "pill pill-error";
      }
    }
  }

  $("rerun").addEventListener("click", () => refreshPosture(true).catch(() => {}));
  $("ack-all").addEventListener("click", async () => {
    await api("/api/alerts/ack-all", "POST");
    await refreshAll();
  });

  if (!token) {
    $("auth-error").hidden = false;
    return;
  }
  refreshAll();
  refreshPosture(false).catch(() => {});
  setInterval(refreshAll, REFRESH_MS);
})();
