"""Case exports: replayable Markdown report, spreadsheet-compatible CSVs, JSON."""

from __future__ import annotations

import csv
import json
import os

from . import types
from .db import Case, CaseError


def export(case: Case, fmt: str, out_dir: str) -> list[str]:
    os.makedirs(out_dir, exist_ok=True)
    stem = os.path.splitext(os.path.basename(case.path))[0]
    if fmt == "json":
        return [_export_json(case, os.path.join(out_dir, f"{stem}.json"))]
    if fmt == "md":
        return [_export_md(case, os.path.join(out_dir, f"{stem}.md"))]
    if fmt == "csv":
        return _export_csv(case, out_dir, stem)
    raise CaseError(f"unknown export format {fmt!r}")


# -- json ---------------------------------------------------------------------

def case_dump(case: Case) -> dict:
    return {
        "vera_case": case.meta(),
        "evidence": case.evidence(),
        "actions": [dict(case.get_action(a["id"]))
                    for a in _flat_actions(case)],
        "findings": case.findings(),
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
        rows = [ft.csv_row(f) for f in case.findings(ft.key)]
        sheet(ft.csv_name, ft.csv_headers, rows)
    return written


# -- markdown (the replay document) --------------------------------------------

def _export_md(case: Case, path: str) -> str:
    with open(path, "w") as fh:
        fh.write(render_md(case))
    return path


def render_md(case: Case) -> str:
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
      f"{n['evidence']} evidence items")
    w("")

    evidence = case.evidence()
    w("## Evidence")
    w("")
    if evidence:
        w("| # | Label | Kind | Source | SHA-256 |")
        w("|---|-------|------|--------|---------|")
        for e in evidence:
            w(f"| E{e['id']} | {_mdcell(e['label'])} | {_mdcell(e['kind'])} "
              f"| {_mdcell(e['source'])} | `{e['sha256']}` |"
              if e["sha256"] else
              f"| E{e['id']} | {_mdcell(e['label'])} | {_mdcell(e['kind'])} "
              f"| {_mdcell(e['source'])} |  |")
    else:
        w("_No evidence items recorded._")
    w("")

    w("## Investigation (replay in order)")
    w("")
    w("Actions are numbered in the order they were performed. Nested entries "
      "show the findings each action produced and the follow-up actions those "
      "findings prompted.")
    w("")
    for action in case.tree():
        _md_action(w, case, action, depth=3)
    orphans = case.unattached_findings()
    if orphans:
        w("### Unattached findings")
        w("")
        for f in orphans:
            _md_finding(w, f, depth=0)

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


def _md_action(w, case: Case, a: dict, depth: int) -> None:
    hdr = "#" * min(depth, 6)
    host = f" on `{a['host']}`" if a["host"] else ""
    w(f"{hdr} A{a['id']} — `{a['tool']}`{host}")
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
    for f in a["findings"]:
        _md_finding(w, f, depth)
        for sub in f["actions"]:
            _md_action(w, case, sub, min(depth + 1, 6))


def _md_finding(w, f: dict, depth: int) -> None:
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
    if f["detail"]:
        for line in f["detail"].splitlines():
            w(f"> {line}")
    w("")


def _mdcell(text: str) -> str:
    return (text or "").replace("|", "\\|").replace("\n", " ")
