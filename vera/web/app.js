/* vera web viewer */
"use strict";

const state = {
  info: null,       // /api/case payload: meta, evidence, counts, types
  tab: "investigation",
  jumpTo: null,     // node id to scroll to after switching to investigation
};

/* ---------- tiny DOM helpers ---------- */

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") node.className = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else if (v !== null && v !== undefined) node.setAttribute(k, v);
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined) continue;
    node.append(child.nodeType ? child : document.createTextNode(child));
  }
  return node;
}

async function api(path, opts = {}) {
  if (opts.body) {
    opts.headers = { "Content-Type": "application/json" };
    opts.body = JSON.stringify(opts.body);
  }
  const res = await fetch(path, opts);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `${res.status} ${res.statusText}`);
  return data;
}

function typeInfo(key) {
  return state.info.types.find((t) => t.key === key)
      || { key, label: key, fields: [], view: "" };
}

/* ---------- layout ---------- */

async function boot() {
  state.info = await api("/api/case");
  document.getElementById("case-title").textContent =
    state.info.meta.name || state.info.file;
  document.title = `vera — ${state.info.meta.name || state.info.file}`;
  buildTabs();
  await render();
}

function tabList() {
  const tabs = [
    { id: "investigation", label: "Investigation" },
    { id: "timeline", label: "Timeline" },
  ];
  for (const t of state.info.types) {
    if (t.view) tabs.push({ id: `type:${t.key}`, label: t.view });
  }
  tabs.push({ id: "evidence", label: "Evidence" });
  return tabs;
}

function buildTabs() {
  const nav = document.getElementById("tabs");
  nav.replaceChildren();
  for (const tab of tabList()) {
    nav.append(el("button", {
      class: tab.id === state.tab ? "active" : "",
      onclick: () => { state.tab = tab.id; render(); },
    }, tab.label));
  }
}

function updateCounts() {
  const c = state.info.counts;
  document.getElementById("case-counts").textContent =
    `${c.actions} actions · ${c.findings} findings · ${c.evidence} evidence`;
}

async function refreshInfo() {
  state.info = await api("/api/case");
}

async function render() {
  buildTabs();
  updateCounts();
  const view = document.getElementById("view");
  view.replaceChildren(el("div", { class: "hint" }, "loading…"));
  try {
    if (state.tab === "investigation") await renderInvestigation(view);
    else if (state.tab === "timeline") await renderTimeline(view);
    else if (state.tab === "evidence") await renderEvidence(view);
    else if (state.tab.startsWith("type:")) {
      await renderCategory(view, state.tab.slice(5));
    }
  } catch (err) {
    view.replaceChildren(el("div", { class: "form-error" }, String(err.message || err)));
  }
}

function emptyState(view, title, hint) {
  view.replaceChildren(el("div", { class: "empty" },
    el("p", { class: "empty-title" }, title),
    el("p", { class: "empty-hint" }, hint)));
}

async function reload(jumpTo = null) {
  await refreshInfo();
  state.jumpTo = jumpTo;
  await render();
}

/* ---------- shared form machinery ---------- */

function field(labelText, input, wide = false) {
  return el("label", { class: "field" + (wide ? " wide" : "") }, labelText, input);
}

function textInput(name, placeholder = "", value = "") {
  return el("input", { name, placeholder, value, autocomplete: "off" });
}

function formCard({ fields, submitLabel, onsubmit, oncancel }) {
  const err = el("div", { class: "form-error" });
  const form = el("form", {
    class: "card",
    onsubmit: async (ev) => {
      ev.preventDefault();
      err.textContent = "";
      try {
        await onsubmit(new FormData(form), form);
      } catch (e) {
        err.textContent = String(e.message || e);
      }
    },
  },
    el("div", { class: "form-grid" }, fields),
    el("div", { class: "form-actions" },
      el("button", { class: "btn primary", type: "submit" }, submitLabel),
      el("button", { class: "btn", type: "button", onclick: oncancel }, "Cancel")),
    err);
  return form;
}

/* Toggle helper: mounts a form right after `anchor`, focuses first input. */
function toggleForm(anchor, build) {
  if (anchor._form && anchor._form.isConnected) {
    anchor._form.remove();
    anchor._form = null;
    return;
  }
  const form = build(() => { form.remove(); anchor._form = null; });
  anchor._form = form;
  anchor.after(form);
  const first = form.querySelector("input, textarea, select");
  if (first) first.focus();
}

/* ---------- finding form (shared: add + edit) ---------- */

function findingForm({ actionId, existing, done, close }) {
  const typeSelect = el("select", { name: "ftype" },
    state.info.types.map((t) =>
      el("option", { value: t.key, selected: existing && existing.ftype === t.key ? "" : null }, t.label)));
  const attrsGrid = el("div", { class: "form-grid", style: "grid-column: 1 / -1;" });

  function renderAttrFields() {
    const t = typeInfo(typeSelect.value);
    const current = (existing && existing.attrs) || {};
    attrsGrid.replaceChildren(t.fields.map((f) =>
      field(f.label, textInput(`attr:${f.key}`, f.hint || "", current[f.key] || ""))));
  }
  typeSelect.addEventListener("change", renderAttrFields);

  const fieldsEls = [
    field("What did you find?", textInput("title", "e.g. rundll32 spawned from wmiprvse",
      existing ? existing.title : ""), true),
    field("Type", typeSelect),
    field("Host", textInput("host", "", existing ? existing.host : "")),
    field("Event time (in the incident)", textInput("event_time", "e.g. 2026-07-01 14:22",
      existing ? existing.event_time : "")),
    attrsGrid,
    field("Detail / evidence for this finding",
      el("textarea", { name: "detail" }, existing ? existing.detail : ""), true),
  ];

  const form = formCard({
    fields: fieldsEls,
    submitLabel: existing ? "Save finding" : "Add finding",
    oncancel: close,
    onsubmit: async (data) => {
      const attrs = {};
      for (const [k, v] of data.entries()) {
        if (k.startsWith("attr:") && v.trim() !== "") attrs[k.slice(5)] = v.trim();
      }
      const payload = {
        title: data.get("title").trim(),
        ftype: data.get("ftype"),
        host: data.get("host").trim(),
        event_time: data.get("event_time").trim(),
        detail: data.get("detail").trim(),
        attrs,
      };
      if (!payload.title) throw new Error("a title is required");
      if (existing) {
        await api(`/api/findings/${existing.id}`, { method: "PATCH", body: payload });
        await done(existing.id);
      } else {
        payload.action_id = actionId ?? null;
        const res = await api("/api/findings", { method: "POST", body: payload });
        await done(res.id);
      }
    },
  });
  renderAttrFields();
  return form;
}

/* ---------- action form (shared: add + edit + follow-up) ---------- */

function actionForm({ parentFindingId, existing, done, close }) {
  const evOptions = [el("option", { value: "" }, "— none —")];
  for (const e of state.info.evidence) {
    evOptions.push(el("option", {
      value: String(e.id),
      selected: existing && existing.evidence_id === e.id ? "" : null,
    }, `E${e.id} ${e.label}`));
  }
  const fieldsEls = [
    field("Exact command line you ran", el("textarea", {
      name: "command",
      placeholder: "vol.py -f WS01.mem windows.pstree",
    }, existing ? existing.command : ""), true),
    field("Host", textInput("host", "", existing ? existing.host : "")),
    field("Tool (defaults to first word)", textInput("tool", "", existing ? existing.tool : "")),
    field("Evidence used", el("select", { name: "evidence_id" }, evOptions)),
    field("Why you ran it / notes", el("textarea", { name: "notes" },
      existing ? existing.notes : ""), true),
  ];
  if (!existing) {
    fieldsEls.push(field("Captured output (paste, optional)",
      el("textarea", { name: "output" }), true));
  }

  return formCard({
    fields: fieldsEls,
    submitLabel: existing ? "Save action" : "Log action",
    oncancel: close,
    onsubmit: async (data) => {
      const payload = {
        command: data.get("command").trim(),
        host: data.get("host").trim(),
        tool: data.get("tool").trim(),
        notes: data.get("notes").trim(),
        evidence_id: data.get("evidence_id") ? Number(data.get("evidence_id")) : null,
      };
      if (!payload.command) throw new Error("the command is required");
      if (existing) {
        await api(`/api/actions/${existing.id}`, { method: "PATCH", body: payload });
        await done(existing.id);
      } else {
        payload.output = data.get("output") || "";
        payload.parent_finding_id = parentFindingId ?? null;
        const res = await api("/api/actions", { method: "POST", body: payload });
        await done(res.id);
      }
    },
  });
}

/* ---------- investigation tree ---------- */

async function renderInvestigation(view) {
  const tree = await api("/api/tree");
  view.replaceChildren();

  const addBtn = el("button", { class: "btn primary" }, "+ Log action");
  addBtn.addEventListener("click", () => toggleForm(toolbar, (close) =>
    actionForm({ done: (id) => reload(`node-A${id}`), close })));
  const toolbar = el("div", { class: "toolbar" },
    addBtn,
    el("span", { class: "hint" },
      "Each action is a command or tool run, in the order you worked. " +
      "Attach findings to actions; log follow-up actions from a finding to record your drill-down."));
  view.append(toolbar);

  if (!tree.roots.length && !tree.unattached.length) {
    view.append(el("div", { class: "empty" },
      el("p", { class: "empty-title" }, "No actions logged yet"),
      el("p", { class: "empty-hint" },
        "Click “+ Log action”, or from a terminal: ",
        el("code", {}, "vera run \"vol.py -f mem.raw windows.pstree\" --host WS01"))));
    return;
  }
  for (const a of tree.roots) view.append(actionCard(a));
  if (tree.unattached.length) {
    view.append(el("h3", {}, "Unattached findings"));
    for (const f of tree.unattached) view.append(findingCard(f));
  }

  if (state.jumpTo) {
    const target = document.getElementById(state.jumpTo);
    state.jumpTo = null;
    if (target) {
      target.scrollIntoView({ behavior: "smooth", block: "center" });
      target.classList.add("highlight");
      setTimeout(() => target.classList.remove("highlight"), 2200);
    }
  }
}

function actionCard(a) {
  const card = el("div", { class: "card node-action", id: `node-A${a.id}` });
  const evidence = state.info.evidence.find((e) => e.id === a.evidence_id);

  card.append(el("div", { class: "node-head" },
    el("span", { class: "ref a" }, `A${a.id}`),
    el("span", { class: "tag" }, a.tool || "action"),
    a.host ? el("span", { class: "node-title" }, `@${a.host}`) : null,
    el("span", { class: "meta" }, a.performed_at),
    evidence ? el("span", { class: "meta" }, `evidence: E${evidence.id} ${evidence.label}`) : null,
    a.exit_code !== null && a.exit_code !== undefined && a.exit_code !== 0
      ? el("span", { class: "meta", style: "color: var(--danger)" }, `exit ${a.exit_code}`) : null));

  card.append(el("div", { class: "cmd" }, a.command));
  if (a.notes) card.append(el("div", { class: "notes" }, a.notes));

  if (a.output) {
    const truncated = a.output_truncated ? " (truncated)" : "";
    card.append(el("details", { class: "output" },
      el("summary", {}, `captured output${truncated} · sha256 ${a.output_sha256.slice(0, 16)}…`),
      el("pre", {}, a.output)));
  }

  const tools = el("div", { class: "node-tools" });
  const addFindingBtn = el("button", { class: "btn small" }, "+ Finding");
  addFindingBtn.addEventListener("click", () => toggleForm(tools, (close) =>
    findingForm({ actionId: a.id, done: (id) => reload(`node-F${id}`), close })));
  const editBtn = el("button", { class: "btn small ghost" }, "Edit");
  editBtn.addEventListener("click", () => toggleForm(tools, (close) =>
    actionForm({ existing: a, done: (id) => reload(`node-A${id}`), close })));
  tools.append(addFindingBtn, editBtn);
  card.append(tools);

  if (a.findings.length) {
    const kids = el("div", { class: "children" });
    for (const f of a.findings) kids.append(findingCard(f));
    card.append(kids);
  }
  return card;
}

function findingCard(f) {
  const t = typeInfo(f.ftype);
  const card = el("div", { class: "card node-finding", id: `node-F${f.id}` });

  const star = el("span", {
    class: "star" + (f.starred ? "" : " off"),
    title: "toggle key finding",
    onclick: async () => {
      await api(`/api/findings/${f.id}`, { method: "PATCH", body: { starred: f.starred ? 0 : 1 } });
      await reload(`node-F${f.id}`);
    },
  }, "★");

  card.append(el("div", { class: "node-head" },
    el("span", { class: "ref f" }, `F${f.id}`),
    el("span", { class: "tag" }, t.label),
    star,
    el("span", { class: "node-title" }, f.title),
    f.host ? el("span", { class: "meta" }, `@${f.host}`) : null,
    f.event_time ? el("span", { class: "meta" }, f.event_time) : null));

  const chips = Object.entries(f.attrs || {}).filter(([, v]) => v);
  if (chips.length) {
    card.append(el("div", { class: "attr-chips" },
      chips.map(([k, v]) => el("span", {}, el("b", {}, k.replaceAll("_", " ") + ": "), v))));
  }
  if (f.detail) card.append(el("div", { class: "notes" }, f.detail));

  const tools = el("div", { class: "node-tools" });
  const followBtn = el("button", { class: "btn small" }, "+ Follow-up action");
  followBtn.addEventListener("click", () => toggleForm(tools, (close) =>
    actionForm({ parentFindingId: f.id, done: (id) => reload(`node-A${id}`), close })));
  const editBtn = el("button", { class: "btn small ghost" }, "Edit");
  editBtn.addEventListener("click", () => toggleForm(tools, (close) =>
    findingForm({ existing: f, done: (id) => reload(`node-F${id}`), close })));
  tools.append(followBtn, editBtn);
  card.append(tools);

  if (f.actions && f.actions.length) {
    const kids = el("div", { class: "children" });
    for (const a of f.actions) kids.append(actionCard(a));
    card.append(kids);
  }
  return card;
}

function refLink(refText, nodeId) {
  return el("a", {
    class: "ref-link",
    href: "#",
    onclick: (ev) => {
      ev.preventDefault();
      state.tab = "investigation";
      state.jumpTo = nodeId;
      render();
    },
  }, refText);
}

/* ---------- timeline ---------- */

async function renderTimeline(view) {
  const rows = await api("/api/timeline");
  if (!rows.length) {
    emptyState(view, "No timeline entries yet",
      "Findings appear here when they have an event time — the moment something happened in the incident.");
    return;
  }
  const table = el("table", {},
    el("thead", {}, el("tr", {},
      ["Date / Time", "Host", "Activity", "Type", "Ref"].map((h) => el("th", {}, h)))),
    el("tbody", {}, rows.map((f) => el("tr", {},
      el("td", { class: "mono" }, f.event_time),
      el("td", {}, f.host),
      el("td", {}, (f.attrs && f.attrs.activity) || f.title),
      el("td", {}, typeInfo(f.ftype).label),
      el("td", {}, refLink(`F${f.id}`, `node-F${f.id}`))))));
  view.replaceChildren(el("div", { class: "table-wrap" }, table));
}

/* ---------- category views ---------- */

async function renderCategory(view, typeKey) {
  const t = typeInfo(typeKey);
  const rows = await api(`/api/findings?type=${encodeURIComponent(typeKey)}`);
  if (!rows.length) {
    emptyState(view, `No ${t.view.toLowerCase()} recorded yet`,
      `Add findings with type “${t.label}” and they will be collected here automatically.`);
    return;
  }
  const headers = ["Ref", "Title", "Host", "Event time",
    ...t.fields.map((f) => f.label), "Detail"];
  const table = el("table", {},
    el("thead", {}, el("tr", {}, headers.map((h) => el("th", {}, h)))),
    el("tbody", {}, rows.map((f) => el("tr", {},
      el("td", {}, refLink(`F${f.id}`, `node-F${f.id}`)),
      el("td", {}, (f.starred ? "★ " : "") + f.title),
      el("td", {}, f.host),
      el("td", { class: "mono" }, f.event_time),
      t.fields.map((fld) => el("td", { class: "mono" }, (f.attrs || {})[fld.key] || "")),
      el("td", {}, f.detail)))));
  view.replaceChildren(el("div", { class: "table-wrap" }, table));
}

/* ---------- evidence ---------- */

async function renderEvidence(view) {
  view.replaceChildren();
  const addBtn = el("button", { class: "btn primary" }, "+ Add evidence");
  const toolbar = el("div", { class: "toolbar" }, addBtn,
    el("span", { class: "hint" },
      "Register each evidence item (image, memory dump, triage collection) with its hash — " +
      "this is what makes the case reproducible."));
  addBtn.addEventListener("click", () => toggleForm(toolbar, (close) => formCard({
    fields: [
      field("Label", textInput("label", "WS01 memory dump"), true),
      field("Kind", textInput("kind", "disk / memory / triage / logs")),
      field("SHA-256", textInput("sha256")),
      field("Source / acquisition detail", textInput("source"), true),
      field("Notes", el("textarea", { name: "notes" }), true),
    ],
    submitLabel: "Add evidence",
    oncancel: close,
    onsubmit: async (data) => {
      const label = data.get("label").trim();
      if (!label) throw new Error("a label is required");
      await api("/api/evidence", { method: "POST", body: {
        label,
        kind: data.get("kind").trim(),
        sha256: data.get("sha256").trim(),
        source: data.get("source").trim(),
        notes: data.get("notes").trim(),
      }});
      await reload();
    },
  })));
  view.append(toolbar);

  const items = state.info.evidence;
  if (!items.length) {
    view.append(el("div", { class: "empty" },
      el("p", { class: "empty-title" }, "No evidence registered"),
      el("p", { class: "empty-hint" },
        "From a terminal: ",
        el("code", {}, "vera evidence add \"WS01 memory dump\" --kind memory --sha256 <hash>"))));
    return;
  }
  const table = el("table", {},
    el("thead", {}, el("tr", {},
      ["Ref", "Label", "Kind", "Source", "SHA-256", "Notes"].map((h) => el("th", {}, h)))),
    el("tbody", {}, items.map((e) => el("tr", {},
      el("td", { class: "mono" }, `E${e.id}`),
      el("td", {}, e.label),
      el("td", {}, e.kind),
      el("td", { class: "mono" }, e.source),
      el("td", { class: "mono" }, e.sha256),
      el("td", {}, e.notes)))));
  view.append(el("div", { class: "table-wrap" }, table));
}

boot().catch((err) => {
  document.getElementById("view").replaceChildren(
    el("div", { class: "form-error" }, `failed to load case: ${err.message || err}`));
});
