/* vera web viewer */
"use strict";

const state = {
  info: null,       // /api/case payload: meta, evidence, counts, types
  tab: "investigation",
  jumpTo: null,     // node id to scroll to after switching to investigation
  notice: null,     // one-shot message shown on the next render
};

// host disposition — '' means not yet triaged
const STATUS_OPTS = [["", "—"], ["clean", "clean"],
  ["suspicious", "suspicious"], ["compromised", "compromised"]];
const statusClass = (s) => (s ? " st-" + s : "");

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
  const exportLink = document.getElementById("export-md");
  if (!state.info.active) {
    if (exportLink) exportLink.style.display = "none";
    await renderLanding();
    return;
  }
  if (exportLink) exportLink.style.display = "";
  ensureSwitchButton();
  document.getElementById("case-title").textContent =
    state.info.meta.name || state.info.file;
  document.title = `vera — ${state.info.meta.name || state.info.file}`;
  buildTabs();
  await render();
}

function ensureSwitchButton() {
  if (document.getElementById("switch-case")) return;
  const btn = el("button", {
    id: "switch-case", class: "btn small",
    title: "Start or open another investigation",
    onclick: renderLanding,
  }, "Investigations");
  const hr = document.querySelector(".header-right");
  hr.insertBefore(btn, hr.firstChild);
}

async function renderLanding() {
  const data = await api("/api/cases");
  document.getElementById("case-title").textContent = "";
  document.getElementById("case-counts").textContent = "";
  document.getElementById("tabs").replaceChildren();
  const view = document.getElementById("view");

  const nameInput = el("input", {
    placeholder: "e.g. FOR508 Lab 3 — Stark Research Labs", autocomplete: "off",
  });
  const err = el("div", { class: "form-error" });
  const start = async () => {
    const name = nameInput.value.trim();
    if (!name) { err.textContent = "give your investigation a name"; nameInput.focus(); return; }
    err.textContent = "";
    try {
      await api("/api/cases", { method: "POST", body: { name } });
      await boot();
    } catch (e) { err.textContent = String(e.message || e); }
  };
  nameInput.addEventListener("keydown", (e) => { if (e.key === "Enter") start(); });

  const newCard = el("div", { class: "card" },
    el("h2", { class: "landing-h" }, "Start a new investigation"),
    el("p", { class: "hint" },
      "Name it, then log each command you run and the findings it produces. " +
      "Everything is saved to a portable case file you can hand to anyone."),
    el("label", { class: "field wide" }, "Investigation name", nameInput),
    el("div", { class: "form-actions" },
      el("button", { class: "btn primary", onclick: start }, "Start investigation")),
    err);

  const cards = [newCard];
  if (data.cases && data.cases.length) {
    cards.push(el("div", { class: "card" },
      el("h3", {}, "Or reopen an investigation"),
      el("div", { class: "case-list" }, data.cases.map((c) =>
        el("button", {
          class: "case-row",
          onclick: async () => {
            await api("/api/open", { method: "POST", body: { file: c.file } });
            await boot();
          },
        },
          el("span", { class: "case-name" }, c.name || c.file),
          el("span", { class: "meta" },
            `${c.counts.actions} actions · ${c.counts.findings} findings · ${c.counts.evidence} evidence`),
          el("span", { class: "mono meta" }, c.file))))));
  }
  view.replaceChildren(el("div", { class: "landing-wrap" }, cards));
  nameInput.focus();
}

function tabList() {
  const tabs = [
    { id: "investigation", label: "Investigation" },
    { id: "timeline", label: "Timeline" },
    { id: "stack", label: "Stack" },
    { id: "hosts", label: "Hosts" },
    { id: "coverage", label: "Coverage" },
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
  const bits = [`${c.actions} actions`, `${c.findings} findings`,
    `${c.evidence} evidence`];
  if (c.hosts) bits.push(`${c.hosts} hosts`);
  document.getElementById("case-counts").textContent = bits.join(" · ");
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
    else if (state.tab === "stack") await renderStack(view);
    else if (state.tab === "hosts") await renderHosts(view);
    else if (state.tab === "coverage") await renderCoverage(view);
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

/* ---------- attachments (screenshots) ---------- */

function readFileAsB64(file) {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onerror = () => reject(new Error("could not read file"));
    r.onload = () => {
      const res = String(r.result);
      resolve({
        filename: file.name || "pasted.png",
        mime: file.type || "application/octet-stream",
        data_base64: res.slice(res.indexOf(",") + 1),
      });
    };
    r.readAsDataURL(file);
  });
}

async function uploadAttachment(ownerType, ownerId, file, role, caption) {
  const meta = await readFileAsB64(file);
  return api("/api/attachments", { method: "POST", body: {
    owner_type: ownerType, owner_id: ownerId, role,
    filename: meta.filename, mime: meta.mime, data_base64: meta.data_base64,
    caption: caption || "",
  }});
}

function imagesFromClipboard(ev) {
  const out = [];
  const items = (ev.clipboardData && ev.clipboardData.items) || [];
  for (const it of items) {
    if (it.kind === "file" && it.type.startsWith("image/")) {
      const f = it.getAsFile();
      if (f) out.push(f);
    }
  }
  return out;
}

const onlyImages = (list) => [...list].filter((f) => f.type.startsWith("image/"));

/* Multi-image stager: drop/choose/paste as many screenshots as you like, each
   with its own caption. Used both for not-yet-created owners (creation forms)
   and, wrapped in an Upload button, for adding views to an existing item. */
function shotStager(role, label) {
  const items = [];  // {file, capInput, wrap}
  const strip = el("div", { class: "shot-stage" });
  const input = el("input", { type: "file", accept: "image/*", multiple: "",
    style: "display:none" });
  const zone = el("div", { class: "dropzone", tabindex: "0" },
    el("span", {}, label ||
      "📎 Add screenshots — drop, choose, or paste (Ctrl+V). Add as many views as you like."),
    input);
  const add = (list) => {
    for (const f of onlyImages(list)) {
      const capInput = el("input", { class: "cap-input",
        placeholder: "caption / which view (optional)" });
      const item = { file: f, capInput };
      const wrap = el("div", { class: "stage-item" },
        el("img", { class: "thumb", src: URL.createObjectURL(f),
          onclick: () => window.open(URL.createObjectURL(f), "_blank") }),
        capInput,
        el("button", { type: "button", class: "chip-x", title: "remove",
          onclick: () => {
            const i = items.indexOf(item);
            if (i >= 0) { items.splice(i, 1); wrap.remove(); }
          } }, "×"));
      item.wrap = wrap;
      items.push(item);
      strip.append(wrap);
    }
  };
  zone.addEventListener("click", () => input.click());
  input.addEventListener("change", () => { add(input.files); input.value = ""; });
  zone.addEventListener("dragover", (e) => { e.preventDefault(); zone.classList.add("drag"); });
  zone.addEventListener("dragleave", () => zone.classList.remove("drag"));
  zone.addEventListener("drop", (e) => {
    e.preventDefault(); zone.classList.remove("drag"); add(e.dataTransfer.files);
  });
  zone.addEventListener("paste", (e) => {
    const imgs = imagesFromClipboard(e);
    if (imgs.length) { e.preventDefault(); add(imgs); }
  });
  return { el: el("div", {}, zone, strip), items, role };
}

// Back-compat alias for the creation-form dropzones.
const pendingShots = (role, label) => shotStager(role, label);

async function uploadPending(ownerType, id, pending) {
  for (const it of pending.items) {
    await uploadAttachment(ownerType, id, it.file, pending.role,
      it.capInput.value.trim());
  }
}

function attachmentStrip(atts, onChange) {
  if (!atts || !atts.length) return null;
  const strip = el("div", { class: "shot-strip" });
  for (const at of atts) {
    const src = `/api/attachments/${at.id}`;
    const isImg = (at.mime || "").startsWith("image/");
    const view = isImg
      ? el("img", { class: "thumb", src, loading: "lazy",
          title: at.caption || at.filename || "" })
      : el("a", { class: "file-chip", href: src, target: "_blank" },
          `📎 ${at.filename || "file"}`);
    if (isImg) view.addEventListener("click", () => openLightbox(at));
    const del = el("button", { class: "shot-del", title: "delete",
      onclick: async (e) => {
        e.stopPropagation();
        if (!confirm("Delete this screenshot?")) return;
        await api(`/api/attachments/${at.id}`, { method: "DELETE" });
        await onChange();
      } }, "×");
    strip.append(el("div", { class: "shot" }, view, del,
      at.role === "output" ? el("span", { class: "shot-role" }, "output") : null,
      at.caption ? el("span", { class: "shot-cap" }, at.caption) : null));
  }
  return strip;
}

function openLightbox(at) {
  const overlay = el("div", { class: "lightbox", onclick: () => overlay.remove() },
    el("figure", { onclick: (e) => e.stopPropagation() },
      el("img", { src: `/api/attachments/${at.id}` }),
      el("figcaption", {},
        `${at.caption || at.filename || ""}  ·  sha256 ${(at.sha256 || "").slice(0, 16)}…`),
      el("button", { class: "btn small", onclick: () => overlay.remove() }, "Close")));
  const esc = (e) => { if (e.key === "Escape") { overlay.remove(); document.removeEventListener("keydown", esc); } };
  document.addEventListener("keydown", esc);
  document.body.append(overlay);
}

/* "📎 Screenshots" button on a card: stage several captioned views, then upload. */
function shotButton(ownerType, ownerId, role, done) {
  const tools = el("span", { class: "shot-add" });
  const btn = el("button", { class: "btn small ghost" }, "📎 Screenshots");
  btn.addEventListener("click", () => toggleForm(tools, (close) => {
    const stager = shotStager(role);
    const err = el("div", { class: "form-error" });
    const upload = el("button", { class: "btn small primary" }, "Upload");
    upload.addEventListener("click", async () => {
      if (!stager.items.length) { err.textContent = "add at least one screenshot"; return; }
      upload.disabled = true; err.textContent = "";
      try {
        await uploadPending(ownerType, ownerId, stager);
        await done();
      } catch (e) { err.textContent = String(e.message || e); upload.disabled = false; }
    });
    const panel = el("div", { class: "card shot-panel" }, stager.el,
      el("div", { class: "form-actions" }, upload,
        el("button", { class: "btn small", onclick: close }, "Cancel")),
      err);
    setTimeout(() => panel.querySelector(".dropzone")?.focus(), 0);
    return panel;
  }));
  tools.append(btn);
  return tools;
}

/* ---------- host picker (strict select from the registry) ---------- */

function roleSnippet(h) {
  // notes look like "Windows 11 - Timothy Dungan - Sr. R&D Engineer"
  const parts = (h.notes || "").split(" - ");
  return parts.length > 1 ? parts.slice(1).join(" - ") : (h.notes || "");
}

function hostPicker(initial, hint) {
  const chosen = new Map();  // id -> host object (from state.info.hosts)
  const byId = new Map((state.info.hosts || []).map((h) => [h.id, h]));
  for (const h of (initial || [])) {
    const full = byId.get(h.id) || h;
    chosen.set(h.id, full);
  }

  const chips = el("div", { class: "host-chips" });
  const count = el("span", { class: "stack-count" });
  const search = el("input", { class: "host-search",
    placeholder: "search / filter by name, IP or subnet (e.g. 172.16.6), or person…",
    autocomplete: "off" });
  const list = el("div", { class: "host-checklist" });
  const quickBar = el("div", { class: "host-quick" });

  const allHosts = () => state.info.hosts || [];
  function filtered() {
    const q = search.value.trim().toLowerCase();
    if (!q) return allHosts();
    return allHosts().filter((h) =>
      (h.name + " " + h.ip + " " + (h.os || "") + " " + (h.system_type || "")
        + " " + (h.notes || "")).toLowerCase().includes(q));
  }

  function selectHosts(hs, on) {
    for (const h of hs) { if (on) chosen.set(h.id, h); else chosen.delete(h.id); }
    refresh();
  }
  function refresh() { refreshChips(); renderQuick(); renderList(); }

  function refreshChips() {
    chips.replaceChildren(...[...chosen.values()].map((h) =>
      el("span", { class: "host-chip" }, h.name,
        el("button", { type: "button", class: "chip-x", title: "remove",
          onclick: () => { chosen.delete(h.id); refresh(); } }, "×"))));
    count.textContent = chosen.size
      ? `🖥 ${chosen.size} host${chosen.size > 1 ? "s" : ""}` : "";
  }

  function groupChips(keyFn, kind) {
    const values = [...new Set(allHosts().map(keyFn).filter(Boolean))];
    return values.map((v) => {
      const members = allHosts().filter((h) => keyFn(h) === v);
      const allOn = members.every((h) => chosen.has(h.id));
      return el("button", { type: "button", class: "seg-chip" + (allOn ? " on" : ""),
        title: allOn ? `deselect these ${kind}` : `select all ${kind}: ${v}`,
        onclick: () => selectHosts(members, !allOn) },
        v, el("span", { class: "seg-n" }, String(members.length)));
    });
  }

  function renderQuick() {
    const shown = filtered();
    const allShownOn = shown.length && shown.every((h) => chosen.has(h.id));
    const controls = [
      el("button", { type: "button", class: "btn small",
        title: "select every host matching the current search",
        onclick: () => selectHosts(shown, !allShownOn) },
        allShownOn ? "Deselect shown" : `Select shown (${shown.length})`),
    ];
    if (chosen.size) {
      controls.push(el("button", { type: "button", class: "btn small ghost",
        onclick: () => { chosen.clear(); refresh(); } }, "Clear"));
    }
    // system_type doubles as the network/CIDR label; os is a first-class field
    const segChips = groupChips((h) => h.system_type, "in segment");
    const osChips = groupChips((h) => h.os, "with OS");
    const statChips = groupChips((h) => h.status, "with disposition");
    const rowOf = (label, chipList) => chipList.length
      ? el("div", { class: "host-quick-row segs" },
          el("span", { class: "quick-label" }, label), ...chipList) : null;
    quickBar.replaceChildren(
      el("div", { class: "host-quick-row" }, ...controls),
      rowOf("OS", osChips),
      rowOf("Segment", segChips),
      rowOf("Status", statChips));
  }

  function renderList() {
    const rows = filtered();
    const q = search.value.trim().toLowerCase();
    list.replaceChildren(...rows.map((h) => {
      const on = chosen.has(h.id);
      const row = el("label", { class: "host-opt" + (on ? " on" : "") },
        el("input", { type: "checkbox", ...(on ? { checked: "" } : {}) }),
        el("span", { class: "host-opt-name" }, h.name),
        el("span", { class: "host-opt-ip mono" }, h.ip || ""),
        el("span", { class: "host-opt-role" }, roleSnippet(h)));
      row.querySelector("input").addEventListener("change", (e) => {
        if (e.target.checked) chosen.set(h.id, h); else chosen.delete(h.id);
        refreshChips(); renderQuick();
        row.classList.toggle("on", e.target.checked);
      });
      return row;
    }));
    if (!rows.length) {
      list.append(el("div", { class: "hint", style: "padding:8px" },
        q ? "no match — " : "no hosts registered — ",
        el("a", { href: "#", class: "ref-link", onclick: (ev) => {
          ev.preventDefault(); addForm.style.display = "block";
          addForm.querySelector("input").value = q;
          addForm.querySelector("input").focus();
        } }, "add a host")));
    }
  }
  search.addEventListener("input", () => { renderQuick(); renderList(); });

  // inline "+ new host" — the only way to introduce one, keeps registry authoritative
  const nameI = el("input", { placeholder: "new host name (e.g. RD11)" });
  const ipI = el("input", { placeholder: "IP (optional)" });
  const typeI = el("input", { placeholder: "type / segment (optional)" });
  const addErr = el("span", { class: "form-error" });
  const addForm = el("div", { class: "host-add", style: "display:none" },
    nameI, ipI, typeI,
    el("button", { type: "button", class: "btn small primary", onclick: async () => {
      const name = nameI.value.trim();
      if (!name) { addErr.textContent = "name required"; return; }
      addErr.textContent = "";
      try {
        const res = await api("/api/hosts", { method: "POST", body: {
          name, ip: ipI.value.trim(), system_type: typeI.value.trim() } });
        const id = (res.ids || [])[0];
        await refreshInfo();
        const full = (state.info.hosts || []).find((h) => h.id === id);
        if (full) { chosen.set(id, full); }
        nameI.value = ipI.value = typeI.value = "";
        addForm.style.display = "none";
        refresh();
      } catch (e) { addErr.textContent = String(e.message || e); }
    } }, "Add"),
    el("button", { type: "button", class: "btn small",
      onclick: () => { addForm.style.display = "none"; } }, "Cancel"),
    addErr);
  const addToggle = el("button", { type: "button", class: "btn small ghost",
    onclick: () => {
      addForm.style.display = addForm.style.display === "none" ? "block" : "none";
      if (addForm.style.display === "block") nameI.focus();
    } }, "+ new host");

  const wrap = el("div", { class: "host-picker" },
    el("div", { class: "host-tags-head" },
      el("span", { class: "hint" }, hint || "Select from the registry."), count),
    chips,
    el("div", { class: "host-picker-controls" }, search, addToggle),
    addForm, quickBar, list);
  refresh();
  return {
    el: wrap,
    ids: () => [...chosen.keys()],
    addHosts: (hs) => {
      for (const h of (hs || [])) chosen.set(h.id, byId.get(h.id) || h);
      refresh();
    },
  };
}

/* one-line "N host(s): a, b, c +4 more" summary for read-only host notes */
function hostNames(hosts) {
  const names = (hosts || []).map((h) => h.name);
  if (!names.length) return "";
  const shown = names.slice(0, 10).join(", ");
  const more = names.length > 10 ? ` +${names.length - 10} more` : "";
  return `${names.length} host(s): ${shown}${more}`;
}

/* ---------- finding form (shared: add + edit) ---------- */

function findingForm({ actionId, inheritHosts, existing, done, close }) {
  const typeSelect = el("select", { name: "ftype" },
    state.info.types.map((t) =>
      el("option", { value: t.key, selected: existing && existing.ftype === t.key ? "" : null }, t.label)));
  const attrsGrid = el("div", { class: "form-grid", style: "grid-column: 1 / -1;" });

  function renderAttrFields() {
    const t = typeInfo(typeSelect.value);
    const current = (existing && existing.attrs) || {};
    attrsGrid.replaceChildren(...t.fields.map((f) =>
      field(f.label, textInput(`attr:${f.key}`, f.hint || "", current[f.key] || ""))));
  }
  typeSelect.addEventListener("change", renderAttrFields);

  const shots = existing ? null : pendingShots("exhibit",
    "📎 Attach screenshot proof — drop, choose, or paste. Several views are fine.");
  // a new finding inherits the host(s) of the action it hangs off — you can adjust
  const initialHosts = existing ? existing.affected_hosts : (inheritHosts || []);
  const picker = hostPicker(initialHosts,
    "Affected host(s) — inherited from the action; adjust if the finding spans "
    + "more or fewer systems. Picking 2+ stacks it across hosts.");

  // hashes: md5 / sha1 / sha256 of the file this finding is about
  const HASHES = [["md5", "MD5", 32], ["sha1", "SHA-1", 40], ["sha256", "SHA-256", 64]];
  const existingHashes = (existing && existing.hashes) || {};
  const hashInputs = {};
  const hashGrid = el("div", { class: "form-grid", style: "grid-column:1/-1" },
    HASHES.map(([key, label, len]) => {
      const inp = el("input", { class: "mono hash-input", name: `hash:${key}`,
        placeholder: `${len} hex chars`, value: existingHashes[key] || "",
        autocomplete: "off", spellcheck: "false" });
      hashInputs[key] = inp;
      return field(label, inp);
    }));

  const fieldsEls = [
    field("What did you find?", textInput("title", "e.g. rundll32 spawned from wmiprvse",
      existing ? existing.title : ""), true),
    field("Type", typeSelect),
    field("Event time (in the incident)", textInput("event_time", "e.g. 2026-07-01 14:22",
      existing ? existing.event_time : "")),
    attrsGrid,
    field("Affected host(s)", picker.el, true),
    field("File hashes (optional)", hashGrid, true),
    field("Detail / evidence for this finding",
      el("textarea", { name: "detail" }, existing ? existing.detail : ""), true),
    shots ? field("Screenshot", shots.el, true) : null,
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
      const hashes = {};
      for (const [key] of HASHES) {
        const v = hashInputs[key].value.trim().toLowerCase();
        if (v) hashes[key] = v;
      }
      const payload = {
        title: data.get("title").trim(),
        ftype: data.get("ftype"),
        event_time: data.get("event_time").trim(),
        detail: data.get("detail").trim(),
        attrs,
        hashes,
        host_ids: picker.ids(),
      };
      if (!payload.title) throw new Error("a title is required");
      if (existing) {
        await api(`/api/findings/${existing.id}`, { method: "PATCH", body: payload });
        await refreshInfo();
        await done(existing.id);
      } else {
        payload.action_id = actionId ?? null;
        const res = await api("/api/findings", { method: "POST", body: payload });
        await uploadPending("finding", res.id, shots);
        await refreshInfo();
        await done(res.id);
      }
    },
  });
  renderAttrFields();
  return form;
}

/* ---------- action form (shared: add + edit + follow-up) ---------- */

function actionForm({ parentFindingId, existing, done, close }) {
  const isManual = existing ? existing.method === "manual" : false;

  const method = el("select", { name: "method" },
    el("option", { value: "command", selected: isManual ? null : "" }, "Command (CLI)"),
    el("option", { value: "manual", selected: isManual ? "" : null }, "Tool / manual step"));

  const evOptions = [el("option", { value: "" }, "— none —")];
  for (const e of state.info.evidence) {
    evOptions.push(el("option", {
      value: String(e.id),
      selected: existing && existing.evidence_id === e.id ? "" : null,
    }, `E${e.id} ${e.label}`));
  }

  const commandField = field("Exact command line you ran", el("textarea", {
    name: "command", placeholder: "vol.py -f WS01.mem windows.pstree",
  }, existing ? existing.command : ""), true);
  const procedureField = field("Steps to reproduce (what you did in the tool)",
    el("textarea", { name: "procedure",
      placeholder: "In Registry Explorer, open NTUSER.DAT → …\\CurrentVersion\\Run",
    }, existing ? existing.procedure : ""), true);
  const outputField = existing ? null
    : field("Captured output (paste, optional)", el("textarea", { name: "output" }), true);
  const shots = existing ? null
    : pendingShots("output",
        "📎 Screenshot(s) of the result — drop, choose, or paste. Add several views if useful.");

  const toolField = field("Tool", textInput("tool",
    "Registry Explorer, Timeline Explorer …", existing ? existing.tool : ""));

  // hosts belong to evidence/collections, not individual steps — the step's
  // hosts derive from the evidence it examines, shown here read-only
  const evSelect = el("select", { name: "evidence_id" }, evOptions);
  const hostNote = el("div", { class: "hint host-note" });
  function syncHostNote() {
    const ev = state.info.evidence.find((x) => String(x.id) === evSelect.value);
    const names = ((ev && ev.hosts) || []).map((h) => h.name);
    if (!names.length) {
      hostNote.textContent = evSelect.value
        ? "the selected evidence has no source hosts"
        : "pick the evidence this step examined — its source host(s) apply to the step";
      return;
    }
    const shown = names.slice(0, 10).join(", ");
    const more = names.length > 10 ? ` +${names.length - 10} more` : "";
    hostNote.textContent =
      `applies to ${names.length} host(s) from the evidence: ${shown}${more}`;
  }
  evSelect.addEventListener("change", syncHostNote);
  syncHostNote();

  function sync() {
    const manual = method.value === "manual";
    commandField.style.display = manual ? "none" : "";
    procedureField.style.display = manual ? "" : "none";
    if (outputField) outputField.style.display = manual ? "none" : "";
  }
  method.addEventListener("change", sync);

  const fieldsEls = [
    field("How was this done?", method),
    toolField,
    field("Evidence used", evSelect),
    el("div", { class: "field wide" }, hostNote),
    commandField,
    procedureField,
    field("Why you did it / notes", el("textarea", { name: "notes" },
      existing ? existing.notes : ""), true),
    outputField,
    shots ? field("Screenshot", shots.el, true) : null,
  ];

  const form = formCard({
    fields: fieldsEls,
    submitLabel: existing ? "Save step" : "Log step",
    oncancel: close,
    onsubmit: async (data) => {
      const m = data.get("method");
      const payload = {
        method: m,
        tool: data.get("tool").trim(),
        notes: data.get("notes").trim(),
        evidence_id: data.get("evidence_id") ? Number(data.get("evidence_id")) : null,
      };
      if (m === "manual") {
        payload.procedure = data.get("procedure").trim();
        payload.command = "";
        if (!payload.tool) throw new Error("a manual step needs a Tool");
      } else {
        payload.command = data.get("command").trim();
        payload.procedure = "";
        if (!payload.command) throw new Error("the command is required");
      }
      if (existing) {
        await api(`/api/actions/${existing.id}`, { method: "PATCH", body: payload });
        await refreshInfo();
        await done(existing.id);
      } else {
        payload.output = m === "command" ? (data.get("output") || "") : "";
        payload.parent_finding_id = parentFindingId ?? null;
        const res = await api("/api/actions", { method: "POST", body: payload });
        if (shots) await uploadPending("action", res.id, shots);
        await refreshInfo();
        await done(res.id);
      }
    },
  });
  sync();
  return form;
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

  const manual = a.method === "manual";
  const hostChips = (a.hosts || []).map((h) =>
    el("span", { class: "host-chip mini", title: "jump to host",
      onclick: () => { state.tab = "hosts"; render(); } }, h.name));
  card.append(el("div", { class: "node-head" },
    el("span", { class: "ref a" }, `A${a.id}`),
    el("span", { class: "tag" }, a.tool || "action"),
    manual ? el("span", { class: "tag method" }, "manual") : null,
    ...hostChips,
    el("span", { class: "meta" }, a.performed_at),
    evidence ? el("span", { class: "meta" }, `evidence: E${evidence.id} ${evidence.label}`) : null,
    a.exit_code !== null && a.exit_code !== undefined && a.exit_code !== 0
      ? el("span", { class: "meta", style: "color: var(--danger)" }, `exit ${a.exit_code}`) : null));

  if (manual) {
    card.append(el("div", { class: "procedure" },
      el("span", { class: "proc-tool" }, `🔧 ${a.tool}`),
      a.procedure ? el("div", { class: "proc-steps" }, a.procedure) : null));
  } else {
    card.append(el("div", { class: "cmd" }, a.command));
  }
  if (a.notes) card.append(el("div", { class: "notes" }, a.notes));

  if (a.output) {
    const truncated = a.output_truncated ? " (truncated)" : "";
    card.append(el("details", { class: "output" },
      el("summary", {}, `captured output${truncated} · sha256 ${a.output_sha256.slice(0, 16)}…`),
      el("pre", {}, a.output)));
  }

  const strip = attachmentStrip(a.attachments, () => reload(`node-A${a.id}`));
  if (strip) card.append(strip);

  const tools = el("div", { class: "node-tools" });
  const addFindingBtn = el("button", { class: "btn small" }, "+ Finding");
  addFindingBtn.addEventListener("click", () => toggleForm(tools, (close) =>
    findingForm({ actionId: a.id, inheritHosts: a.hosts || [],
      done: (id) => reload(`node-F${id}`), close })));
  const editBtn = el("button", { class: "btn small ghost" }, "Edit");
  editBtn.addEventListener("click", () => toggleForm(tools, (close) =>
    actionForm({ existing: a, done: (id) => reload(`node-A${id}`), close })));
  tools.append(addFindingBtn, editBtn,
    shotButton("action", a.id, "exhibit", () => reload(`node-A${a.id}`)));
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
    f.stack ? hostCountChip(f) : null,
    f.event_time ? el("span", { class: "meta" }, f.event_time) : null));

  const chips = Object.entries(f.attrs || {}).filter(([, v]) => v);
  if (chips.length) {
    card.append(el("div", { class: "attr-chips" },
      chips.map(([k, v]) => el("span", {}, el("b", {}, k.replaceAll("_", " ") + ": "), v))));
  }
  const hashes = Object.entries(f.hashes || {}).filter(([, v]) => v);
  if (hashes.length) {
    const HLABEL = { md5: "MD5", sha1: "SHA-1", sha256: "SHA-256" };
    card.append(el("div", { class: "hash-row" }, hashes.map(([k, v]) =>
      el("span", { class: "hash-chip", title: "click to copy",
        onclick: () => navigator.clipboard && navigator.clipboard.writeText(v) },
        el("b", {}, (HLABEL[k] || k) + " "), el("code", {}, v)))));
  }
  if (f.detail) card.append(el("div", { class: "notes" }, f.detail));

  const strip = attachmentStrip(f.attachments, () => reload(`node-F${f.id}`));
  if (strip) card.append(strip);

  const tools = el("div", { class: "node-tools" });
  const followBtn = el("button", { class: "btn small" }, "+ Follow-up action");
  followBtn.addEventListener("click", () => toggleForm(tools, (close) =>
    actionForm({ parentFindingId: f.id, done: (id) => reload(`node-A${id}`), close })));
  const editBtn = el("button", { class: "btn small ghost" }, "Edit");
  editBtn.addEventListener("click", () => toggleForm(tools, (close) =>
    findingForm({ existing: f, done: (id) => reload(`node-F${id}`), close })));
  tools.append(followBtn, editBtn,
    shotButton("finding", f.id, "exhibit", () => reload(`node-F${f.id}`)));
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

function hostCountChip(f) {
  const names = (f.affected_hosts || []).map((h) => h.name).join(", ");
  const chip = el("span", { class: "host-count-chip", title: names },
    `🖥 ${f.stack} host${f.stack > 1 ? "s" : ""}`);
  chip.addEventListener("click", () => {
    state.tab = "hosts";
    render();
  });
  return chip;
}

/* ---------- stack view (cross-host, rare-first) ---------- */

async function renderStack(view) {
  const rows = await api("/api/stack");
  view.replaceChildren(el("p", { class: "hint" },
    "Cross-host findings, rarest first — least-frequency-of-occurrence puts the " +
    "most suspicious (few-host) indicators at the top. Add affected hosts on any " +
    "finding to stack it here."));
  if (!rows.length) {
    view.append(el("div", { class: "empty" },
      el("p", { class: "empty-title" }, "No cross-host findings yet"),
      el("p", { class: "empty-hint" },
        "Give a finding an ‘Affected hosts’ set and it appears here.")));
    return;
  }
  const table = el("table", {},
    el("thead", {}, el("tr", {},
      ["Ref", "Hosts", "Title", "Type", "Affected hosts"].map((h) => el("th", {}, h)))),
    el("tbody", {}, rows.map((f) => el("tr", {},
      el("td", {}, refLink(`F${f.id}`, `node-F${f.id}`)),
      el("td", { class: "mono stack-n" }, String(f.stack)),
      el("td", {}, (f.starred ? "★ " : "") + f.title),
      el("td", {}, typeInfo(f.ftype).label),
      el("td", {}, (f.affected_hosts || []).map((h) => h.name).join(", "))))));
  view.append(el("div", { class: "table-wrap" }, table));
}

/* ---------- hosts registry ---------- */

async function renderHosts(view) {
  const hosts = await api("/api/hosts");
  view.replaceChildren();
  view.append(el("div", { class: "toolbar" },
    el("span", { class: "hint" },
      "Edit any field inline — changes save as you tab out. Use the blank row at " +
      "the bottom to add a host; ✕ removes one (kept in the record, just hidden). " +
      "Paste a newline/comma list into the bottom Host cell to add many at once.")));

  const err = el("div", { class: "form-error" });
  const cols = [
    { key: "name", ph: "host name", cls: "" },
    { key: "ip", ph: "IP", cls: "mono" },
    { key: "os", ph: "Windows 11 / Ubuntu 22.04 …", cls: "" },
    { key: "status", select: true },
    { key: "system_type", ph: "segment / type", cls: "" },
    { key: "aliases", ph: "comma-separated", cls: "" },
    { key: "notes", ph: "notes", cls: "" },
  ];

  const tbody = el("tbody", {});
  const table = el("table", { class: "host-grid" },
    el("thead", {}, el("tr", {},
      el("th", {}, "Ref"),
      ...cols.map((c) => el("th", {},
        { system_type: "Segment / Type", os: "OS", status: "Status" }[c.key]
        || c.key[0].toUpperCase() + c.key.slice(1))),
      el("th", {}, "Findings"),
      el("th", {}, ""))),
    tbody);

  const statusSelect = (value) => el("select", { class: "cell cell-select" },
    STATUS_OPTS.map(([v, label]) =>
      el("option", { value: v, selected: (value || "") === v ? "" : null }, label)));

  const cellVal = (h, key) => key === "aliases" ? (h.aliases || []).join(", ")
    : (h[key] || "");
  const parseVal = (key, raw) => key === "aliases"
    ? raw.split(",").map((s) => s.trim()).filter(Boolean) : raw.trim();

  function liveRow(h) {
    const tr = el("tr", { class: "host-row" + statusClass(h.status) });
    const inputs = {};
    tr.append(el("td", { class: "mono host-ref" }, `H${h.id}`));
    for (const c of cols) {
      const inp = c.select ? statusSelect(h[c.key])
        : el("input", { class: "cell " + c.cls, value: cellVal(h, c.key),
            placeholder: c.ph, autocomplete: "off" });
      inputs[c.key] = inp;
      inp.addEventListener("change", async () => {
        const val = c.select ? inp.value : parseVal(c.key, inp.value);
        if (c.key === "name" && !String(val).trim()) {
          inp.value = h.name; return;  // don't allow blanking the name
        }
        err.textContent = "";
        try {
          await api(`/api/hosts/${h.id}`, { method: "PATCH", body: { [c.key]: val } });
          h[c.key] = val;
          if (c.key === "status") tr.className = "host-row" + statusClass(val);
          flashSaved(inp);
        } catch (e) { err.textContent = String(e.message || e); inp.value = cellVal(h, c.key); }
      });
      tr.append(el("td", {}, inp));
    }
    tr.append(el("td", {}, h.finding_count
      ? hostFindingsLink(h) : el("span", { class: "meta" }, "0")));
    tr.append(el("td", {}, el("button", { class: "row-del", title: "delete host",
      onclick: async () => {
        if (!confirm(`Delete ${h.name}? It stays in the record (soft-delete), just hidden.`)) return;
        try {
          await api(`/api/hosts/${h.id}`, { method: "DELETE" });
          tr.remove();
          await refreshInfo();
          updateCounts();
        } catch (e) { err.textContent = String(e.message || e); }
      } }, "✕")));
    return tr;
  }

  function newRow() {
    const tr = el("tr", { class: "host-row host-new" });
    const inputs = {};
    tr.append(el("td", { class: "mono host-ref" }, "＋"));
    let committing = false;
    const commit = async () => {
      const name = inputs.name.value.trim();
      if (committing || !name) return;
      committing = true;
      // support pasting a whole list into the name cell
      const names = name.split(/[\n,]/).map((s) => s.trim()).filter(Boolean);
      err.textContent = "";
      try {
        const body = names.length > 1 ? { names }
          : { name: names[0], ip: parseVal("ip", inputs.ip.value),
              os: inputs.os.value.trim(),
              status: inputs.status.value,
              system_type: inputs.system_type.value.trim(),
              aliases: parseVal("aliases", inputs.aliases.value),
              notes: inputs.notes.value.trim() };
        await api("/api/hosts", { method: "POST", body });
        await refreshInfo();
        updateCounts();
        // rebuild rows from fresh state so ids/counts are right
        const fresh = await api("/api/hosts");
        tbody.replaceChildren(...fresh.map(liveRow), newRow());
        const nn = tbody.querySelector(".host-new .cell");
        if (nn) nn.focus();
      } catch (e) { err.textContent = String(e.message || e); committing = false; }
    };
    for (const c of cols) {
      const inp = c.select ? statusSelect("")
        : el("input", { class: "cell " + c.cls,
            placeholder: c.key === "name" ? "add a host…" : c.ph, autocomplete: "off" });
      inputs[c.key] = inp;
      if (c.key === "name") inp.addEventListener("change", commit);
      tr.append(el("td", {}, inp));
    }
    tr.append(el("td", {}, el("span", { class: "meta" }, "")));
    tr.append(el("td", {}, ""));
    return tr;
  }

  tbody.replaceChildren(...hosts.map(liveRow), newRow());
  view.append(el("div", { class: "table-wrap" }, table), err);
  if (!hosts.length) {
    view.append(el("p", { class: "empty-hint", style: "text-align:left" },
      "No hosts yet — type in the blank row above, or from a terminal: ",
      el("code", {}, "vera host add WS01 WS02 … (or --from hosts.txt)")));
  }
}

function flashSaved(inp) {
  inp.classList.add("saved");
  setTimeout(() => inp.classList.remove("saved"), 900);
}

function hostFindingsLink(h) {
  const link = el("a", { class: "ref-link", href: "#" }, String(h.finding_count));
  link.addEventListener("click", async (ev) => {
    ev.preventDefault();
    const detail = await api(`/api/host_detail?id=${h.id}`);
    openHostPanel(h, detail);
  });
  return link;
}

function openHostPanel(h, detail) {
  const jump = (nodeId, overlay) => (ev) => {
    ev.preventDefault(); overlay.remove();
    state.tab = "investigation"; state.jumpTo = nodeId; render();
  };
  const section = (title, rows) => rows.length
    ? el("div", {}, el("h4", { class: "host-panel-h" }, title), ...rows) : null;
  const overlay = el("div", { class: "lightbox", onclick: () => overlay.remove() });
  const findRows = detail.findings.map((f) =>
    el("div", { class: "host-panel-row" },
      el("a", { class: "ref-link", href: "#", onclick: jump(`node-F${f.id}`, overlay) }, `F${f.id}`),
      " ", el("span", {}, `[${typeInfo(f.ftype).label}] ${f.title}`),
      f.stack > 1 ? el("span", { class: "meta" }, ` · 🖥 ${f.stack} hosts`) : null));
  const actRows = detail.actions.map((a) =>
    el("div", { class: "host-panel-row" },
      el("a", { class: "ref-link", href: "#", onclick: jump(`node-A${a.id}`, overlay) }, `A${a.id}`),
      " ", el("span", {}, a.method === "manual" ? `🔧 ${a.tool}: ${a.procedure}` : `$ ${a.command}`)));
  const evRows = detail.evidence.map((e) =>
    el("div", { class: "host-panel-row" },
      el("span", { class: "mono" }, `E${e.id}`), " ",
      el("span", {}, `${e.label}${e.kind ? " [" + e.kind + "]" : ""}`)));
  const total = detail.findings.length + detail.actions.length + detail.evidence.length;
  overlay.append(el("div", { class: "host-panel", onclick: (e) => e.stopPropagation() },
    el("h3", {}, `H${h.id} — ${h.name}`),
    el("p", { class: "hint" },
      h.ip ? `${h.ip} · ` : "", roleSnippet(h) || "",
      total ? "" : " — nothing references this host yet"),
    section("Evidence", evRows),
    section("Actions", actRows),
    section("Findings", findRows),
    el("button", { class: "btn small", onclick: () => overlay.remove() }, "Close")));
  document.body.append(overlay);
}

/* ---------- coverage (hosts × analysis — "did we look at everything?") ---------- */

function statusPill(s) {
  return s ? el("span", { class: "st-pill st-" + s }, s)
           : el("span", { class: "meta" }, "—");
}

async function renderCoverage(view) {
  const cov = await api("/api/coverage");
  if (!cov.hosts.length) {
    emptyState(view, "No hosts registered",
      "Coverage shows what analysis has touched each host — register hosts first.");
    return;
  }
  const gaps = cov.hosts.filter((h) => !h.actions);
  const nOf = (s) => cov.hosts.filter((h) => (h.status || "") === s).length;
  const bits = [];
  for (const [key] of STATUS_OPTS) {
    const n = nOf(key);
    if (key && n) bits.push(`${n} ${key}`);
  }
  if (nOf("")) bits.push(`${nOf("")} not triaged`);

  view.replaceChildren(
    el("p", { class: "hint" },
      "Every registered host × the analysis logged against it (derived from each " +
      "step's host links). Amber rows have no analysis at all — the gaps in your sweep."),
    el("div", { class: "cov-summary" },
      el("span", { class: gaps.length ? "cov-warn" : "cov-ok" },
        gaps.length
          ? `⚠ ${gaps.length} of ${cov.hosts.length} hosts have no analysis logged`
          : `✓ all ${cov.hosts.length} hosts have at least one analysis step`),
      bits.length ? el("span", { class: "meta" }, "  ·  " + bits.join(" · ")) : null));

  const headers = ["Ref", "Host", "Status", "Evidence", "Steps", "Findings",
    "Last examined", ...cov.tools];
  const table = el("table", { class: "cov-table" },
    el("thead", {}, el("tr", {}, headers.map((h) => el("th", {}, h)))),
    el("tbody", {}, cov.hosts.map((h) => el("tr", {
      class: (h.actions ? "" : "cov-gap") + statusClass(h.status) },
      el("td", { class: "mono" }, `H${h.id}`),
      el("td", {}, el("b", {}, h.name),
        h.ip ? el("span", { class: "meta mono" }, ` ${h.ip}`) : null),
      el("td", {}, statusPill(h.status)),
      el("td", { class: "mono cov-n" }, h.evidence ? String(h.evidence) : "·"),
      el("td", { class: "mono cov-n" }, h.actions ? String(h.actions) : "—"),
      el("td", { class: "mono cov-n" }, h.findings ? String(h.findings) : "·"),
      el("td", { class: "mono meta" }, h.last_examined || "never"),
      cov.tools.map((t) => el("td", { class: "mono cov-n" },
        h.tools[t] ? String(h.tools[t]) : "·"))))));
  view.append(el("div", { class: "table-wrap" }, table));
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

function openEvidenceEditor(e) {
  const f = (label, node) => el("label", { class: "field" }, label, node);
  const labelI = el("input", { value: e.label || "", autocomplete: "off" });
  const kindI = el("input", { value: e.kind || "", placeholder: "disk / memory / triage / logs" });
  const shaI = el("input", { class: "mono", value: e.sha256 || "", placeholder: "sha256", spellcheck: "false" });
  const sourceI = el("input", { value: e.source || "", placeholder: "acquisition detail / original path" });
  const notesI = el("textarea", {}, e.notes || "");
  const collections = state.info.collections || [];
  const colSel = collections.length ? el("select", {},
    el("option", { value: "" }, "— none —"),
    ...collections.map((c) => el("option", {
      value: String(c.id), selected: e.collection_id === c.id ? "" : null,
    }, `C${c.id} ${c.name}`))) : null;
  const picker = hostPicker(e.hosts || [],
    "Source host(s) — which system(s) this evidence came from.");
  // hosts are editable only for standalone evidence; in a collection they are
  // managed on the collection (and re-derived if the evidence moves into one)
  const pickerWrap = el("div", {},
    el("h4", { class: "host-panel-h" }, "Source host(s)"), picker.el);
  const colNote = el("div", { class: "hint host-note" });
  const syncHosts = () => {
    const cid = colSel && colSel.value ? Number(colSel.value) : null;
    pickerWrap.style.display = cid ? "none" : "";
    colNote.style.display = cid ? "" : "none";
    if (!cid) return;
    if (cid === e.collection_id) {
      const summary = hostNames(e.hosts);
      colNote.textContent = (summary ? `source hosts — ${summary}. ` : "")
        + `Managed via collection C${cid} — edit the collection to change them.`;
    } else {
      const c = collections.find((x) => x.id === cid);
      const summary = c ? hostNames(c.hosts) : "";
      colNote.textContent = summary
        ? `will inherit from C${cid} on save — ${summary}`
        : `will move into C${cid}, which has no hosts yet`;
    }
  };
  if (colSel) colSel.addEventListener("change", syncHosts);
  const err = el("div", { class: "form-error" });

  const overlay = el("div", { class: "lightbox", onclick: () => overlay.remove() },
    el("div", { class: "host-panel", onclick: (ev) => ev.stopPropagation() },
      el("h3", {}, `Edit E${e.id}`),
      el("div", { class: "form-grid" },
        el("label", { class: "field wide" }, "Label", labelI),
        f("Kind", kindI),
        colSel ? f("Collection", colSel) : null,
        el("label", { class: "field wide" }, "SHA-256", shaI),
        el("label", { class: "field wide" }, "Source", sourceI),
        el("label", { class: "field wide" }, "Notes", notesI)),
      pickerWrap,
      colNote,
      el("div", { class: "form-actions" },
        el("button", { class: "btn primary", onclick: async () => {
          const label = labelI.value.trim();
          if (!label) { err.textContent = "a label is required"; return; }
          err.textContent = "";
          const cid = colSel && colSel.value ? Number(colSel.value) : null;
          try {
            await api(`/api/evidence/${e.id}`, { method: "PATCH", body: {
              label, kind: kindI.value.trim(), sha256: shaI.value.trim(),
              source: sourceI.value.trim(), notes: notesI.value.trim(),
              collection_id: cid,
              // standalone evidence: hosts come from the picker; in a
              // collection the server derives them when the link changes
              ...(cid ? {} : { host_ids: picker.ids() }),
            }});
            overlay.remove();
            await reload();
          } catch (ex) { err.textContent = String(ex.message || ex); }
        } }, "Save"),
        el("button", { class: "btn", onclick: () => overlay.remove() }, "Cancel")),
      err));
  syncHosts();
  document.body.append(overlay);
  setTimeout(() => labelI.focus(), 0);
}

function openCollectionEditor(c) {
  const f = (label, node) => el("label", { class: "field" }, label, node);
  const nameI = el("input", { value: c.name || "", autocomplete: "off" });
  const toolI = el("input", { value: c.tool || "" });
  const opI = el("input", { value: c.operator || "" });
  const scopeI = el("input", { value: c.scope || "" });
  const picker = hostPicker(c.hosts || [],
    "Hosts this collection covers — evidence in it inherits and follows these (per-host items keep their own).");
  const err = el("div", { class: "form-error" });
  const overlay = el("div", { class: "lightbox", onclick: () => overlay.remove() },
    el("div", { class: "host-panel", onclick: (ev) => ev.stopPropagation() },
      el("h3", {}, `Edit C${c.id}`),
      el("div", { class: "form-grid" },
        el("label", { class: "field wide" }, "Name", nameI),
        f("Tool", toolI), f("Operator", opI),
        el("label", { class: "field wide" }, "Scope", scopeI)),
      el("h4", { class: "host-panel-h" }, "Hosts covered"),
      picker.el,
      el("div", { class: "form-actions" },
        el("button", { class: "btn primary", onclick: async () => {
          const name = nameI.value.trim();
          if (!name) { err.textContent = "a name is required"; return; }
          err.textContent = "";
          try {
            await api(`/api/collections/${c.id}`, { method: "PATCH", body: {
              name, tool: toolI.value.trim(), operator: opI.value.trim(),
              scope: scopeI.value.trim(), host_ids: picker.ids(),
            }});
            overlay.remove();
            await reload();
          } catch (ex) { err.textContent = String(ex.message || ex); }
        } }, "Save"),
        el("button", { class: "btn", onclick: () => overlay.remove() }, "Cancel")),
      err));
  document.body.append(overlay);
  setTimeout(() => nameI.focus(), 0);
}

async function renderEvidence(view) {
  view.replaceChildren();

  // Collections (batches) section
  const collections = state.info.collections || [];
  const colBtn = el("button", { class: "btn" }, "+ Add collection");
  const colBar = el("div", { class: "toolbar" }, colBtn,
    el("span", { class: "hint" },
      "A collection is a batch/sweep (e.g. an export from 40 hosts) with its " +
      "provenance and the hosts it covers. Evidence added to it inherits those hosts."));
  colBtn.addEventListener("click", () => toggleForm(colBar, (close) => {
    const picker = hostPicker([],
      "Hosts this collection covers — evidence in it inherits and follows these (per-host items keep their own).");
    return formCard({
      fields: [
        field("Collection name", textInput("name", "Lab2 amcache+shimcache export"), true),
        field("Tool", textInput("tool", "AmcacheParser / KAPE / Velociraptor …")),
        field("Operator", textInput("operator")),
        field("Scope", textInput("scope", "40 hosts, amcache+shimcache"), true),
        field("Hosts covered", picker.el, true),
      ],
      submitLabel: "Add collection",
      oncancel: close,
      onsubmit: async (data) => {
        const name = data.get("name").trim();
        if (!name) throw new Error("a name is required");
        await api("/api/collections", { method: "POST", body: {
          name, tool: data.get("tool").trim(), operator: data.get("operator").trim(),
          scope: data.get("scope").trim(), host_ids: picker.ids(),
        }});
        await reload();
      },
    });
  }));
  view.append(colBar);
  if (state.notice) {
    view.append(el("div", { class: "notice" }, state.notice));
    state.notice = null;
  }
  if (collections.length) {
    const expandBtn = (c) => el("button", { class: "btn small ghost",
      title: "create one evidence item per host in this collection "
        + "(hosts that already have evidence in it are skipped)",
      onclick: async () => {
        if (!confirm(`Create one evidence item per host (${c.hosts.length}) in `
          + `“${c.name}”?\nHosts that already have evidence in this collection `
          + "are skipped, so this is safe to re-run.")) return;
        try {
          const res = await api(`/api/collections/${c.id}/expand`,
            { method: "POST", body: {} });
          state.notice = res.count
            ? `C${c.id}: created ${res.count} per-host evidence item(s)`
            : `C${c.id}: nothing to create — every host already has evidence here`;
          await reload();
        } catch (e) {
          state.notice = `expand failed: ${e.message || e}`;
          render();
        }
      } }, "Expand per host");
    view.append(el("div", { class: "table-wrap", style: "margin-bottom:16px" },
      el("table", {},
        el("thead", {}, el("tr", {},
          ["Ref", "Name", "Tool", "Hosts", "Scope", ""].map((h) => el("th", {}, h)))),
        el("tbody", {}, collections.map((c) => el("tr", {},
          el("td", { class: "mono" }, `C${c.id}`),
          el("td", {}, c.name),
          el("td", {}, c.tool),
          el("td", {}, (c.hosts || []).length
            ? el("span", { class: "host-count-chip" }, `🖥 ${c.hosts.length}`) : ""),
          el("td", {}, c.scope),
          el("td", {},
            el("button", { class: "btn small ghost",
              onclick: () => openCollectionEditor(c) }, "Edit"),
            (c.hosts || []).length ? expandBtn(c) : null)))))));
  }

  const colField = () => {
    if (!collections.length) return null;
    const opts = [el("option", { value: "" }, "— none —"),
      ...collections.map((c) => el("option", { value: String(c.id) }, `C${c.id} ${c.name}`))];
    return el("select", { name: "collection_id" }, opts);
  };

  const addBtn = el("button", { class: "btn primary" }, "+ Add evidence");
  const toolbar = el("div", { class: "toolbar" }, addBtn,
    el("span", { class: "hint" },
      "Register each evidence item (image, memory dump, triage collection) with its hash — " +
      "this is what makes the case reproducible."));
  addBtn.addEventListener("click", () => toggleForm(toolbar, (close) => {
    // hosts are editable here only for standalone evidence; inside a
    // collection they come from (and are edited on) the collection
    const picker = hostPicker([],
      "Source host(s) — which system(s) this evidence came from.");
    const pickerField = field("Source host(s)", picker.el, true);
    const colNote = el("div", { class: "hint host-note" });
    const noteField = el("div", { class: "field wide" }, colNote);
    const cSel = colField();
    const syncHosts = () => {
      const c = cSel && collections.find((x) => String(x.id) === cSel.value);
      pickerField.style.display = c ? "none" : "";
      noteField.style.display = c ? "" : "none";
      if (c) {
        const summary = hostNames(c.hosts);
        colNote.textContent = summary
          ? `source hosts come from C${c.id}: ${summary}`
          : `C${c.id} has no hosts yet — set them on the collection (Edit)`;
      }
    };
    if (cSel) cSel.addEventListener("change", syncHosts);
    syncHosts();
    return formCard({
      fields: [
        field("Label", textInput("label", "WS01 memory dump"), true),
        field("Kind", textInput("kind", "disk / memory / triage / logs")),
        field("SHA-256", textInput("sha256")),
        cSel ? field("Collection", cSel) : null,
        pickerField,
        noteField,
        field("Source / acquisition detail", textInput("source"), true),
        field("Notes", el("textarea", { name: "notes" }), true),
      ],
      submitLabel: "Add evidence",
      oncancel: close,
      onsubmit: async (data) => {
        const label = data.get("label").trim();
        if (!label) throw new Error("a label is required");
        const inCollection = Boolean(data.get("collection_id"));
        await api("/api/evidence", { method: "POST", body: {
          label,
          kind: data.get("kind").trim(),
          sha256: data.get("sha256").trim(),
          source: data.get("source").trim(),
          notes: data.get("notes").trim(),
          collection_id: inCollection ? Number(data.get("collection_id")) : null,
          // in a collection the hosts derive from it (server side)
          ...(inCollection ? {} : { host_ids: picker.ids() }),
        }});
        await reload();
      },
    });
  }));
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
      ["Ref", "Label", "Kind", "Host(s)", "Source", "SHA-256", ""].map((h) => el("th", {}, h)))),
    el("tbody", {}, items.map((e) => el("tr", {},
      el("td", { class: "mono" }, `E${e.id}`),
      el("td", {}, e.label),
      el("td", {}, e.kind),
      el("td", {}, (e.hosts || []).map((h) =>
        el("span", { class: "host-chip mini" }, h.name))),
      el("td", { class: "mono" }, e.source),
      el("td", { class: "mono" }, (e.sha256 || "").slice(0, 16)),
      el("td", {}, el("button", { class: "btn small ghost",
        onclick: () => openEvidenceEditor(e) }, "Edit"))))));
  view.append(el("div", { class: "table-wrap" }, table));

  view.append(el("h3", { style: "margin-top:22px" }, "Exhibits"));
  view.append(el("p", { class: "hint" },
    "Screenshots attached to each evidence item (e.g. the acquisition tool, hash verification)."));
  for (const e of items) {
    const card = el("div", { class: "card" },
      el("div", { class: "node-head" },
        el("span", { class: "ref" , style: "color:var(--muted)" }, `E${e.id}`),
        el("span", { class: "node-title" }, e.label)));
    const strip = attachmentStrip(e.attachments, () => reload());
    if (strip) card.append(strip);
    else card.append(el("div", { class: "hint" }, "no screenshots yet"));
    card.append(el("div", { class: "node-tools" },
      shotButton("evidence", e.id, "exhibit", () => reload())));
    view.append(card);
  }
}

boot().catch((err) => {
  document.getElementById("view").replaceChildren(
    el("div", { class: "form-error" }, `failed to load case: ${err.message || err}`));
});
