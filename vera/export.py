"""Case exports: replayable Markdown report, spreadsheet-compatible CSVs, JSON."""

from __future__ import annotations

import csv
import json
import os
import re

from . import types
from .db import Case, CaseError


def export(case: Case, fmt: str, out_dir: str) -> list[str]:
    os.makedirs(out_dir, exist_ok=True)
    stem = os.path.splitext(os.path.basename(case.path))[0]
    if fmt == "json":
        return [_export_json(case, os.path.join(out_dir, f"{stem}.json"))]
    if fmt == "md":
        return _export_md(case, out_dir, stem)
    if fmt == "csv":
        return _export_csv(case, out_dir, stem)
    raise CaseError(f"unknown export format {fmt!r}")


# -- json ---------------------------------------------------------------------

def case_dump(case: Case) -> dict:
    return {
        "vera_case": case.meta(),
        "hosts": case.hosts(),
        "collections": case.collections(),
        "evidence": case.evidence(),
        "actions": [dict(case.get_action(a["id"]))
                    for a in _flat_actions(case)],
        "findings": case.findings(),  # each carries affected_hosts + stack
        # attachment metadata only; the image bytes live inside the .vera file
        "attachments": case.all_attachments(),
    }


def _flat_actions(case: Case) -> list[dict]:
    return [dict(r) for r in case.conn.execute("SELECT id FROM actions ORDER BY id")]


def _export_json(case: Case, path: str) -> str:
    with open(path, "w") as fh:
        json.dump(case_dump(case), fh, indent=2)
        fh.write("\n")
    return path


# -- csv ----------------------------------------------------------------------

def _export_csv(case: Case, out_dir: str, stem: str) -> list[str]:
    written = []

    def sheet(name: str, headers: tuple, rows: list[list]) -> None:
        path = os.path.join(out_dir, f"{stem}_{name}.csv")
        with open(path, "w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(headers)
            w.writerows(rows)
        written.append(path)

    sheet(types.TIMELINE_CSV_NAME, types.TIMELINE_CSV_HEADERS,
          [types.timeline_csv_row(f) for f in case.timeline()])

    for ft in types.FINDING_TYPES.values():
        if not ft.csv_name:
            continue
        if ft.key == "host":
            continue  # merged with registry dispositions below
        rows = [ft.csv_row(f) for f in case.findings(ft.key)]
        sheet(ft.csv_name, ft.csv_headers, rows)

    hosts = case.hosts()
    if hosts:
        sheet("Hosts", ("Host", "IP", "OS", "Status", "System Type",
                        "Criticality", "Aliases", "Findings"),
              [[h["name"], h["ip"], h["os"], h["status"], h["system_type"],
                h["criticality"], ", ".join(h["aliases"]), h["finding_count"]]
               for h in hosts])

    # CompromisedHosts merges BOTH sources (same as the web view): host-type
    # findings are the narrative rows, then any host flagged compromised on
    # the registry without such a finding gets a derived row — its earliest
    # compromise taken from the earliest-dated finding linked to it.
    host_ft = types.FINDING_TYPES["host"]
    host_findings = case.findings("host")
    comp_rows = [host_ft.csv_row(f) for f in host_findings]
    covered = {h["name"].lower() for f in host_findings
               for h in f.get("affected_hosts", [])}
    earliest: dict[str, str] = {}
    for f in case.findings():
        et = f.get("event_time", "")
        if not et:
            continue
        for h in f.get("affected_hosts", []):
            key = h["name"].lower()
            if key not in earliest or et < earliest[key]:
                earliest[key] = et
    for h in hosts:
        if h["status"] != "compromised" or h["name"].lower() in covered:
            continue
        comp_rows.append([earliest.get(h["name"].lower(), ""), h["name"],
                          h["ip"], h["system_type"],
                          "host registry disposition"
                          f" ({h['finding_count']} linked findings)"])
    if comp_rows:
        sheet(host_ft.csv_name, host_ft.csv_headers, comp_rows)

    stack = case.stack_findings()
    if stack:
        sheet("CrossHostFindings",
              ("Ref", "Title", "Type", "Host Count", "Affected Hosts"),
              [[f"F{f['id']}", f["title"], f["ftype"], f["stack"],
                ", ".join(h["name"] for h in f["affected_hosts"])] for f in stack])
    return written


# -- markdown (the replay document) --------------------------------------------

def _safe_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name) or "file"


class _ApiImageLinker:
    """Link attachments to the running server (for the in-browser md view)."""

    def __call__(self, att: dict) -> str:
        return f"/api/attachments/{att['id']}"


class _FileImageWriter:
    """Write attachment bytes into a sibling folder and link them relatively."""

    def __init__(self, case: Case, out_dir: str, rel_prefix: str):
        self.case = case
        self.dir = os.path.join(out_dir, rel_prefix)
        self.rel = rel_prefix
        self._made = False
        self.written: list[str] = []

    def __call__(self, att: dict) -> str:
        if not self._made:
            os.makedirs(self.dir, exist_ok=True)
            self._made = True
        data, _mime, filename = self.case.attachment_blob(att["id"])
        name = f"{att['id']}_{_safe_name(filename or 'attachment')}"
        path = os.path.join(self.dir, name)
        with open(path, "wb") as fh:
            fh.write(data)
        self.written.append(path)
        return f"{self.rel}/{name}"


def _md_attachments(w, atts: list[dict], linker) -> None:
    for at in atts or []:
        cap = at["caption"] or at["filename"] or f"attachment {at['id']}"
        href = linker(at)
        if at["mime"].startswith("image/"):
            w(f"![{_mdcell(cap)}]({href})")
            w(f"<sub>📎 {_mdcell(cap)} — sha256 <code>{at['sha256'][:16]}…</code></sub>")
        else:
            w(f"- 📎 [{_mdcell(cap)}]({href}) — sha256 `{at['sha256'][:16]}…`")
        w("")


def _export_md(case: Case, out_dir: str, stem: str) -> list[str]:
    writer = _FileImageWriter(case, out_dir, f"{stem}_attachments")
    md = render_md(case, linker=writer)
    path = os.path.join(out_dir, f"{stem}.md")
    with open(path, "w") as fh:
        fh.write(md)
    return [path, *writer.written]


def render_md(case: Case, linker=None) -> str:
    if linker is None:
        linker = _ApiImageLinker()
    meta = case.meta()
    out: list[str] = []
    w = out.append

    w(f"# {meta.get('name') or 'vera case'}")
    w("")
    if meta.get("description"):
        w(meta["description"])
        w("")
    w(f"- **Case file:** `{os.path.basename(case.path)}`")
    if meta.get("investigator"):
        w(f"- **Investigator:** {meta['investigator']}")
    w(f"- **Created:** {meta.get('created_at', '')}")
    n = case.counts()
    w(f"- **Contents:** {n['actions']} actions, {n['findings']} findings, "
      f"{n['evidence']} evidence items, {n['hosts']} hosts, "
      f"{n['collections']} collections")
    w("")

    collections = case.collections()
    if collections:
        w("## Collections")
        w("")
        w("| # | Name | Tool | Operator | Collected | Scope |")
        w("|---|------|------|----------|-----------|-------|")
        for col in collections:
            w(f"| C{col['id']} | {_mdcell(col['name'])} | {_mdcell(col['tool'])} "
              f"| {_mdcell(col['operator'])} | {_mdcell(col['collected_at'])} "
              f"| {_mdcell(col['scope'])} |")
        w("")

    hosts = case.hosts()
    if hosts:
        w("## Hosts")
        w("")
        w("| # | Host | IP | OS | Status | Type | Aliases | Findings |")
        w("|---|------|----|----|--------|------|---------|----------|")
        for h in hosts:
            w(f"| H{h['id']} | {_mdcell(h['name'])} | {_mdcell(h['ip'])} "
              f"| {_mdcell(h['os'])} | {_mdcell(h['status'])} "
              f"| {_mdcell(h['system_type'])} | {_mdcell(', '.join(h['aliases']))} "
              f"| {h['finding_count']} |")
        w("")
        compromised = [h for h in hosts if h["status"] == "compromised"]
        suspicious = [h for h in hosts if h["status"] == "suspicious"]
        if compromised or suspicious:
            w("### Compromised hosts")
            w("")
            if compromised:
                w("**Confirmed compromised:** "
                  + ", ".join(f"`{h['name']}`" for h in compromised))
                w("")
            if suspicious:
                w("**Suspicious:** "
                  + ", ".join(f"`{h['name']}`" for h in suspicious))
                w("")
        untriaged = [h for h in hosts if not h["status"]]
        if untriaged and len(untriaged) < len(hosts):
            w(f"_{len(untriaged)} of {len(hosts)} hosts not yet triaged: "
              + ", ".join(h["name"] for h in untriaged) + "._")
            w("")

    evidence = case.evidence()
    w("## Evidence")
    w("")
    if evidence:
        w("| # | Label | Kind | Host(s) | Source | SHA-256 |")
        w("|---|-------|------|---------|--------|---------|")
        for e in evidence:
            hn = ", ".join(h["name"] for h in e.get("hosts", []))
            sha = f"`{e['sha256']}`" if e["sha256"] else ""
            w(f"| E{e['id']} | {_mdcell(e['label'])} | {_mdcell(e['kind'])} "
              f"| {_mdcell(hn)} | {_mdcell(e['source'])} | {sha} |")
    else:
        w("_No evidence items recorded._")
    w("")
    for e in evidence:
        if e.get("attachments"):
            w(f"**E{e['id']} {_mdcell(e['label'])} — exhibits**")
            w("")
            _md_attachments(w, e["attachments"], linker)

    w("## Investigation (replay in order)")
    w("")
    w("Actions are numbered in the order they were performed. Nested entries "
      "show the findings each action produced and the follow-up actions those "
      "findings prompted.")
    w("")
    for action in case.tree():
        _md_action(w, case, action, depth=3, linker=linker)
    orphans = case.unattached_findings()
    if orphans:
        w("### Unattached findings")
        w("")
        for f in orphans:
            _md_finding(w, f, depth=0, linker=linker)

    timeline = case.timeline()
    w("## Timeline")
    w("")
    if timeline:
        w("| Date / Time | Host | Activity | Ref |")
        w("|-------------|------|----------|-----|")
        for f in timeline:
            _, _, activity = "", "", types.timeline_csv_row(f)[2]
            w(f"| {_mdcell(f['event_time'])} | {_mdcell(f['host'])} "
              f"| {_mdcell(activity)} | F{f['id']} |")
    else:
        w("_No findings carry an event time yet._")
    w("")

    stack = case.stack_findings()
    if stack:
        w("## Cross-host indicators")
        w("")
        w("Findings by number of affected hosts, rarest first — least-frequency-"
          "of-occurrence surfaces the most suspicious indicators at the top.")
        w("")
        w("| Ref | Hosts | Title | Affected hosts |")
        w("|-----|-------|-------|----------------|")
        for f in stack:
            names = ", ".join(h["name"] for h in f["affected_hosts"])
            w(f"| F{f['id']} | {f['stack']} | {_mdcell(f['title'])} "
              f"| {_mdcell(names)} |")
        w("")

    artifacts = [g for g in case.artifact_stacks()
                 if g["count"] > 1 or g["host_count"] > 1]
    if artifacts:
        w("## Artifacts by name")
        w("")
        w("Host-based indicators stacked by artifact name regardless of path — "
          "the same name across directories/hosts is one row, most-spread first.")
        w("")
        w("| Artifact | × | Type | Hosts | Paths |")
        w("|----------|---|------|-------|-------|")
        for g in artifacts:
            hosts = ", ".join(h["name"] for h in g["hosts"])
            paths = "<br>".join(_mdcell(p) for p in g["paths"])
            atype = ", ".join(g["artifact_types"])
            w(f"| {_mdcell(g['name'])} | {g['count']} | {_mdcell(atype)} "
              f"| {_mdcell(hosts)} | {paths} |")
        w("")

    leads = case.leads()
    if leads:
        w("## Leads (triage worklists)")
        w("")
        mark = {"open": "☐", "triaged": "☑", "dismissed": "▨"}
        for L in leads:
            prog = (f" — {L['item_resolved']}/{L['item_total']} triaged"
                    if L["item_total"] else "")
            star = "★ " if L["starred"] else ""
            w(f"### {star}F{L['id']} {_mdcell(L['title'])}{prog}")
            w("")
            if not L["items"]:
                w("_No worklist items._")
                w("")
                continue
            for it in L["items"]:
                link = f" → F{it['finding']['id']}" if it["finding"] else ""
                w(f"- {mark.get(it['status'], '☐')} {_mdcell(it['label'])} "
                  f"(_{it['status']}_){link}")
            w("")

    for ft in types.FINDING_TYPES.values():
        if not ft.csv_name:
            continue
        rows = case.findings(ft.key)
        if not rows:
            continue
        w(f"## {ft.view}")
        w("")
        w("| Ref | " + " | ".join(ft.csv_headers) + " |")
        w("|-----|" + "|".join("---" for _ in ft.csv_headers) + "|")
        for f in rows:
            cells = " | ".join(_mdcell(str(v)) for v in ft.csv_row(f))
            w(f"| F{f['id']} | {cells} |")
        w("")

    return "\n".join(out) + "\n"


def _md_action(w, case: Case, a: dict, depth: int, linker) -> None:
    hdr = "#" * min(depth, 6)
    names = ", ".join(h["name"] for h in a.get("hosts", [])) or a["host"]
    host = f" on `{names}`" if names else ""
    manual = a.get("method") == "manual"
    kind = " (manual step)" if manual else ""
    w(f"{hdr} A{a['id']} — `{a['tool']}`{host}{kind}")
    w("")
    if a["parent_finding_id"]:
        w(f"_Follow-up to finding F{a['parent_finding_id']}._")
        w("")
    w(f"- **When:** {a['performed_at']}")
    if a["evidence_id"]:
        w(f"- **Evidence:** E{a['evidence_id']}")
    if a["exit_code"] is not None:
        w(f"- **Exit code:** {a['exit_code']}")
    w("")
    if manual:
        w(f"**Tool:** {a['tool']}")
        w("")
        if a["procedure"]:
            w("**Procedure (to reproduce):**")
            w("")
            for line in a["procedure"].splitlines():
                w(f"> {line}")
            w("")
    else:
        w("```sh")
        w(a["command"])
        w("```")
        w("")
    if a["notes"]:
        w(a["notes"])
        w("")
    if a["output"]:
        trunc = " (truncated)" if a["output_truncated"] else ""
        w("<details><summary>Captured output" + trunc +
          f" — sha256 <code>{a['output_sha256'][:16]}…</code></summary>")
        w("")
        w("```")
        w(a["output"].rstrip("\n"))
        w("```")
        w("")
        w("</details>")
        w("")
    _md_attachments(w, a.get("attachments"), linker)
    for f in a["findings"]:
        _md_finding(w, f, depth, linker)
        for sub in f["actions"]:
            _md_action(w, case, sub, min(depth + 1, 6), linker)


def _md_finding(w, f: dict, depth: int, linker) -> None:
    ft = types.FINDING_TYPES.get(f["ftype"])
    label = ft.label if ft else f["ftype"]
    star = " ★" if f["starred"] else ""
    w(f"> **F{f['id']} [{label}]{star} — {f['title']}**")
    parts = []
    if f["host"]:
        parts.append(f"host `{f['host']}`")
    if f["event_time"]:
        parts.append(f"event time {f['event_time']}")
    for k, v in f["attrs"].items():
        if v:
            parts.append(f"{k.replace('_', ' ')} `{v}`")
    if parts:
        w("> " + " · ".join(parts))
    if f.get("stack", 0) > 0:
        names = ", ".join(h["name"] for h in f["affected_hosts"])
        w(f">")
        w(f"> 🖥 **Affected hosts ({f['stack']}):** {_mdcell(names)}")
    hashes = f.get("hashes") or {}
    for algo, hlabel in types.HASH_FIELDS:
        if hashes.get(algo):
            w(f"> {hlabel}: `{hashes[algo]}`")
    if f["detail"]:
        for line in f["detail"].splitlines():
            w(f"> {line}")
    w("")
    _md_attachments(w, f.get("attachments"), linker)


def _mdcell(text: str) -> str:
    return (text or "").replace("|", "\\|").replace("\n", " ")
