"""MCP server: expose one case to a local AI assistant over stdio.

MCP (Model Context Protocol) is an open standard; any MCP-capable client can
connect. This module imports cleanly WITHOUT the `mcp` SDK — core vera stays
stdlib-only. The server is available only when the mcp extra is installed
(`pip install vera[mcp]`); `available()` reports which.

Trust model: same as the CLI. The server speaks stdio to a local client
process, serves exactly the case it was started on, and adds no auth layer —
anyone who can launch it could run `vera` themselves. Writes are attributed
via the actor stamp (default `mcp:<username>`) in created_by and the audit log.

stdout is the protocol channel: nothing in this module may print().
Tool functions are plain module-level functions over db.Case (opened per
call, like the web server opens per request) so they stay testable without
the SDK installed.
"""

from __future__ import annotations

import functools
import os

from . import export, types
from .cli import (_action_host_ids, _guess_mime, _parse_host_list, _read_file,
                  _strict_host_ids, _tree_lines)
from .db import OUTPUT_CAP, Case, CaseError, resolve_ref

try:
    from mcp.server.mcpserver import MCPServer as _MCPServer  # mcp >= 2
    from mcp.server.mcpserver.exceptions import ToolError as _ToolError
    _HAVE_MCP = True
except ImportError:
    try:
        from mcp.server.fastmcp import FastMCP as _MCPServer  # mcp 1.x
        from mcp.server.fastmcp.exceptions import ToolError as _ToolError
        _HAVE_MCP = True
    except ImportError:  # optional extra not installed
        _HAVE_MCP = False


def available() -> bool:
    return _HAVE_MCP


def _require_mcp() -> None:
    if not _HAVE_MCP:
        raise CaseError(
            "the MCP server needs the mcp extra: pip install vera[mcp]")


# case path + actor are fixed at launch (like Handler's class attrs in
# server.py); every tool call opens the case fresh so concurrent CLI/web
# edits are always visible
_STATE = {"path": "", "actor": ""}


def _case() -> Case:
    return Case(_STATE["path"], actor=_STATE["actor"])


# -- shared helpers ----------------------------------------------------------

_OWNER_BY_KIND = {"A": "action", "F": "finding", "E": "evidence"}


def _kind_id(ref: str) -> tuple[str, int] | None:
    """('A', 4) for 'A4'/'F2'/'E1'/'H3'/'C2'; None when not that shape."""
    kind = ref[:1].upper()
    if kind in ("A", "F", "E", "H", "C") and ref[1:].isdigit():
        return kind, int(ref[1:])
    return None


def _one(rows: list[dict], row_id: int, label: str) -> dict:
    for r in rows:
        if r["id"] == row_id:
            return r
    raise CaseError(f"{label}{row_id} does not exist")


def _action_ref(case: Case, action: str) -> int | None:
    """Mirror the CLI's --on semantics: 'last' (default), 'none', or 'A4'."""
    if action.lower() == "none":
        return None
    if not action or action.lower() == "last":
        action_id = case.last_action_id()
        if action_id is None:
            raise CaseError("no actions in case yet — log one with log_action,"
                            " or pass action='none' for a standalone finding")
        return action_id
    kind, action_id = resolve_ref(action)
    if kind != "A":
        raise CaseError("action expects an action reference like A4")
    return action_id


# -- read tools --------------------------------------------------------------

def status() -> dict:
    """Case summary: metadata, record counts, and the evidence, host,
    collection, and account registries. Call this first to orient."""
    with _case() as case:
        return {"file": os.path.basename(case.path), "meta": case.meta(),
                "counts": case.counts(), "evidence": case.evidence(),
                "hosts": case.hosts(), "collections": case.collections(),
                "accounts": case.accounts()}


def tree() -> str:
    """The investigation graph as indented text: actions (A#) with the
    findings (F#) they produced, findings with the follow-up actions they
    prompted, unattached findings at the end."""
    with _case() as case:
        lines = _tree_lines(case)
    return "\n".join(lines) if lines else "case is empty — log the first step with log_action"


def show(ref: str) -> dict:
    """Full detail for one record by ref: A4 action (with captured output),
    F2 finding, E1 evidence, C2 collection, or a host (H3, name, or alias —
    includes its findings, evidence, and actions)."""
    with _case() as case:
        parsed = _kind_id(ref)
        if parsed:
            kind, rid = parsed
            if kind == "A":
                return case.get_action(rid)
            if kind == "F":
                return case.get_finding(rid)
            if kind == "E":
                return _one(case.evidence(), rid, "E")
            if kind == "C":
                return _one(case.collections(), rid, "C")
        try:
            hid = case.resolve_host(ref)
        except CaseError:
            raise CaseError(
                f"nothing matches {ref!r} (expected A#, F#, E#, C#, "
                "or a registered host name / alias / H#)") from None
        host = _one(case.hosts(), hid, "H")
        return {**host, "findings": case.findings_for_host(hid),
                "evidence": case.evidence_for_host(hid),
                "actions": case.actions_for_host(hid)}


def list_findings(ftype: str = "") -> dict:
    """All findings, optionally filtered by type (see finding_types)."""
    if ftype and ftype not in types.FINDING_TYPES:
        raise CaseError(f"unknown type {ftype!r} "
                        f"(one of: {', '.join(types.FINDING_TYPES)})")
    with _case() as case:
        return {"findings": case.findings(ftype or None)}


def timeline() -> dict:
    """Findings that carry an event time, in event order — the incident
    timeline as reconstructed so far."""
    with _case() as case:
        return {"events": case.timeline()}


def stacks() -> dict:
    """Least-frequency triage views: findings stacked across hosts (rarest
    first) and host-indicator artifacts stacked by name."""
    with _case() as case:
        return {"cross_host_findings": case.stack_findings(),
                "artifact_stacks": case.artifact_stacks()}


def artifact(query: str) -> dict:
    """Everything known about one artifact (service, task, file, …) by name
    or fragment: the hosts it appears on, findings, and hashes."""
    with _case() as case:
        return case.artifact_detail(query)


def coverage() -> dict:
    """Per-host analysis rollup: which hosts have evidence, actions, and
    findings — where the investigation is thin."""
    with _case() as case:
        return case.coverage()


def worklists() -> dict:
    """Lead findings with their checklist items, plus the case-wide queue of
    open follow-up items on non-lead findings."""
    with _case() as case:
        leads = case.leads()
        for lead in leads:
            lead["items"] = case.lead_items(lead["id"])
        return {"leads": leads, "followups": case.followups()}


def audit_log(ref: str = "", limit: int = 50) -> dict:
    """The case's append-only edit history, optionally for one record
    (A4 / F2 / E1 / H3 / C2)."""
    with _case() as case:
        return {"entries": case.audit(ref or None, limit)}


def finding_types() -> dict:
    """The registered finding types with their type-specific attribute keys
    (use these as `attrs` keys in add_finding), plus valid time kinds and
    host statuses."""
    from .server import _types_payload
    from .db import HOST_STATUSES, TIME_KINDS
    return {"types": _types_payload(),
            "time_kinds": [k for k in TIME_KINDS if k],
            "host_statuses": [s or "unknown" for s in HOST_STATUSES],
            "lead_item_statuses": list(Case.LEAD_ITEM_STATUSES)}


# -- write tools -------------------------------------------------------------

def log_action(command: str = "", tool: str = "", method: str = "command",
               procedure: str = "", notes: str = "", evidence: str = "",
               collection: str = "", hosts: list[str] | None = None,
               parent_finding: str = "", output: str = "",
               exit_code: int | None = None, performed_at: str = "") -> dict:
    """Log an investigative step as an action (A#). method='command' records
    a command line (with its captured output, if any); method='manual'
    records a GUI/tool step (tool + procedure). Give evidence (E1) so the
    step inherits its hosts and collection; parent_finding (F3) marks it as
    a follow-up to that finding."""
    with _case() as case:
        parent = None
        if parent_finding:
            kind, parent = resolve_ref(parent_finding)
            if kind != "F":
                raise CaseError(
                    "parent_finding expects a finding reference like F3")
        evidence_id = case.resolve_evidence(evidence) if evidence else None
        collection_id = (case.resolve_collection(collection)
                         if collection else None)
        host_ids = _action_host_ids(case, hosts, evidence_id)
        a = case.add_action(command, tool=tool, method=method,
                            procedure=procedure, evidence_id=evidence_id,
                            collection_id=collection_id, output=output,
                            exit_code=exit_code, notes=notes,
                            parent_finding_id=parent, host_ids=host_ids,
                            performed_at=performed_at)
        return {"ref": f"A{a}", "output_chars": len(output),
                "output_truncated": len(output) > OUTPUT_CAP}


def add_finding(title: str, ftype: str = "note", action: str = "last",
                detail: str = "", event_time: str = "", time_kind: str = "",
                attrs: dict | None = None, hashes: dict | None = None,
                hosts: list[str] | None = None,
                accounts: list[str] | None = None, starred: bool = False) -> dict:
    """Record a finding (F#) — what an action showed. action defaults to the
    last logged action; pass 'A4' or 'none' (standalone). attrs holds the
    type-specific keys from finding_types; hashes maps md5/sha1/sha256 to
    values. Hosts must already be registered; unknown account names are
    registered automatically."""
    if ftype not in types.FINDING_TYPES:
        raise CaseError(f"unknown type {ftype!r} "
                        f"(one of: {', '.join(types.FINDING_TYPES)})")
    with _case() as case:
        action_id = _action_ref(case, action)
        if _parse_host_list(hosts):
            host_ids = _strict_host_ids(case, hosts)
        elif action_id is not None:
            # inherit the action's host(s) when none are given explicitly
            host_ids = [h["id"] for h in
                        case.get_action(action_id).get("hosts", [])]
        else:
            host_ids = None
        attrs = dict(attrs or {})
        if ftype == "lateral":
            # movement is directional (attrs) but both endpoints also join the
            # affected-hosts set — auto-link names that exist in the registry
            linked = set(host_ids or [])
            for key in ("source_host", "dest_host"):
                name = (attrs.get(key) or "").strip()
                if not name:
                    continue
                try:
                    linked.add(case.resolve_host(name))
                except CaseError:
                    pass  # endpoint outside the registry (e.g. external box)
            host_ids = sorted(linked)
        account_refs = _parse_host_list(accounts)
        account_ids = (case.resolve_accounts(account_refs, create=True)
                       if account_refs else None)
        f = case.add_finding(title, ftype=ftype, action_id=action_id,
                             detail=detail, event_time=event_time,
                             time_kind=time_kind, attrs=attrs, hashes=hashes,
                             starred=starred, host_ids=host_ids or None,
                             account_ids=account_ids)
        return {"ref": f"F{f}"}


def edit(ref: str, fields: dict) -> dict:
    """Amend a record: A4 action (notes, output, command, tool, …), F2
    finding (title, detail, attrs, starred, …), E1 evidence, or H3 host.
    Unknown field names are rejected with the valid set. Every change lands
    in the audit log."""
    with _case() as case:
        parsed = _kind_id(ref)
        if not parsed:
            raise CaseError(f"bad reference {ref!r} "
                            "(expected A<n>, F<n>, E<n>, or H<n>)")
        kind, rid = parsed
        if kind == "A":
            case.update_action(rid, **fields)
        elif kind == "F":
            case.update_finding(rid, **fields)
        elif kind == "E":
            case.update_evidence(rid, **fields)
        elif kind == "H":
            case.update_host(rid, **fields)
        else:
            raise CaseError(f"cannot edit {ref!r} "
                            "(expected A<n>, F<n>, E<n>, or H<n>)")
        return {"ref": ref, "updated": sorted(fields)}


def add_evidence(label: str, kind: str = "", source: str = "",
                 sha256: str = "", notes: str = "", collection: str = "",
                 hosts: list[str] | None = None, acquired_by: str = "",
                 acquired_at: str = "", acquisition: str = "") -> dict:
    """Register an evidence item (E#): a memory image, disk, triage
    collection, log export, …. hosts are the source host(s) it came from
    (must already be registered); a collection ref (C2 or name) groups
    batch-collected evidence."""
    with _case() as case:
        collection_id = (case.resolve_collection(collection)
                         if collection else None)
        host_ids = _strict_host_ids(case, hosts) if hosts else None
        e = case.add_evidence(label, kind=kind, source=source, sha256=sha256,
                              notes=notes, collection_id=collection_id,
                              host_ids=host_ids, acquired_by=acquired_by,
                              acquired_at=acquired_at, acquisition=acquisition)
        return {"ref": f"E{e}"}


def add_hosts(names: list[str], ip: str = "", os: str = "",
              status: str = "", system_type: str = "", criticality: str = "",
              notes: str = "") -> dict:
    """Register host(s) in the registry. A name that already exists (or
    matches an alias) merges into the existing host instead of duplicating.
    status: unknown / clean / suspicious / compromised."""
    if not names:
        raise CaseError("give at least one host name")
    with _case() as case:
        refs = [f"H{case.add_host(n, ip=ip, os=os, status=status, system_type=system_type, criticality=criticality, notes=notes)}"
                for n in names]
        return {"refs": refs}


def add_accounts(names: list[str], domain: str = "", sid: str = "",
                 account_type: str = "", status: str = "",
                 notes: str = "") -> dict:
    """Register account(s). An existing name (case-insensitive) merges
    instead of duplicating."""
    if not names:
        raise CaseError("give at least one account name")
    with _case() as case:
        ids = [case.add_account(n, domain=domain, sid=sid,
                                account_type=account_type, status=status,
                                notes=notes) for n in names]
        return {"ids": ids}


def add_collection(name: str, tool: str = "", operator: str = "",
                   collected_at: str = "", scope: str = "", notes: str = "",
                   hosts: list[str] | None = None) -> dict:
    """Register a collection (C#): a batch acquisition (e.g. a KAPE sweep)
    whose evidence and hosts belong together."""
    with _case() as case:
        host_ids = _strict_host_ids(case, hosts) if hosts else None
        c = case.add_collection(name, tool=tool, operator=operator,
                                collected_at=collected_at, scope=scope,
                                notes=notes, host_ids=host_ids)
        return {"ref": f"C{c}"}


def expand_collection(collection: str, kind: str = "") -> dict:
    """Create one evidence item per collection host (per-host artifacts).
    Idempotent: hosts already covered are skipped."""
    with _case() as case:
        cid = case.resolve_collection(collection)
        created = case.expand_collection(cid, kind=kind)
        return {"created": [{"ref": f"E{it['id']}", "host": it["host"]}
                            for it in created]}


def add_lead_item(lead: str, label: str, note: str = "",
                  finding: str = "") -> dict:
    """Add a checklist item to a finding's worklist (lead is its F# ref).
    On a lead-type finding this builds the triage worklist; on any other
    finding it records a follow-up to do. Linking a finding ref marks the
    item triaged."""
    with _case() as case:
        kind, lead_id = resolve_ref(lead)
        if kind != "F":
            raise CaseError("lead expects a finding reference like F3")
        finding_id = None
        if finding:
            kind, finding_id = resolve_ref(finding)
            if kind != "F":
                raise CaseError("finding expects a reference like F5")
        item = case.add_lead_item(lead_id, label, finding_id=finding_id,
                                  note=note)
        return {"item_id": item}


def set_lead_item(item_id: int, status: str = "", finding: str = "",
                  note: str | None = None, label: str = "") -> dict:
    """Update a checklist item: status open / triaged / dismissed (or
    'removed' to soft-delete it), link a finding (marks it triaged), or
    change its note/label."""
    with _case() as case:
        if status == "removed":
            case.soft_delete_lead_item(item_id)
            return {"item_id": item_id, "removed": True}
        fields: dict = {}
        if status:
            fields["status"] = status
        if finding:
            kind, finding_id = resolve_ref(finding)
            if kind != "F":
                raise CaseError("finding expects a reference like F5")
            fields["finding_id"] = finding_id
        if note is not None:
            fields["note"] = note
        if label:
            fields["label"] = label
        if not fields:
            raise CaseError("nothing to update")
        case.update_lead_item(item_id, **fields)
        return {"item_id": item_id, "updated": sorted(fields)}


def attach_file(ref: str, path: str, caption: str = "",
                role: str = "exhibit") -> dict:
    """Attach a local file (screenshot, tool report, …) to an action,
    finding, or evidence item (A4 / F2 / E1). The bytes are stored inside
    the case file, SHA-256'd. role: exhibit or output."""
    parsed = _kind_id(ref)
    if not parsed or parsed[0] not in _OWNER_BY_KIND:
        raise CaseError(f"bad reference {ref!r} "
                        "(expected A<n>, F<n>, or E<n>)")
    kind, rid = parsed
    data = _read_file(path)
    with _case() as case:
        att = case.add_attachment(_OWNER_BY_KIND[kind], rid, data,
                                  filename=os.path.basename(path),
                                  mime=_guess_mime(path), role=role,
                                  caption=caption)
        return {"attachment_id": att, "bytes": len(data)}


def clone(ref: str, command: str = "", title: str = "") -> dict:
    """Duplicate an action or finding as a template for a similar entry:
    clone('A4', command='…') re-runs a step shape, clone('F2', title='…')
    repeats a finding shape. Output/attachments are not copied."""
    with _case() as case:
        kind, rid = resolve_ref(ref)
        if kind == "A":
            new = case.clone_action(rid, **({"command": command}
                                            if command else {}))
            return {"ref": f"A{new}"}
        if kind == "F":
            new = case.clone_finding(rid, **({"title": title}
                                             if title else {}))
            return {"ref": f"F{new}"}
        raise CaseError(f"can only clone actions or findings, not {ref!r}")


# -- server ------------------------------------------------------------------

_TOOLS = (status, tree, show, list_findings, timeline, stacks, artifact,
          coverage, worklists, audit_log, finding_types,
          log_action, add_finding, edit, add_evidence, add_hosts,
          add_accounts, add_collection, expand_collection,
          add_lead_item, set_lead_item, attach_file, clone)


def case_report() -> str:
    """The whole case rendered as a Markdown report."""
    with _case() as case:
        return export.render_md(case)


def _instructions() -> str:
    type_lines = "\n".join(
        f"- {ft.key}: {ft.label}"
        + (f" (attrs: {', '.join(f.key for f in ft.fields)})" if ft.fields else "")
        for ft in types.FINDING_TYPES.values())
    return (
        "vera tracks a DFIR investigation as a replayable graph: evidence "
        "(E#) is examined by actions (A#), actions produce findings (F#), "
        "findings prompt follow-up actions. Hosts (H#), accounts, and "
        "collections (C#) are registries everything references.\n\n"
        "Workflow: register hosts/evidence first (add_hosts, add_evidence), "
        "log every investigative step as you go (log_action, with the "
        "command and its output), record what each step showed "
        "(add_finding), and queue what still needs doing (add_lead_item). "
        "Call status and tree to orient; nothing is ever hard-deleted.\n\n"
        "Make these reflexive:\n"
        "- When the question is 'does the case already know X?', call "
        "artifact(X) FIRST — it is the un-truncated per-artifact timeline, "
        "so a detail buried in one finding (a timestamp, an authtime) "
        "surfaces at once.\n"
        "- Before proposing new work, check worklists — 'already scoped as "
        "pending' and 'not recorded' are different states, and the query "
        "you are about to suggest may already be a PENDING item.\n"
        "- Never conclude something is ABSENT from a truncated or partial "
        "view (a grep hit, a tree line, a summary row). When a search "
        "surfaces an A#/F#/E#, call show(ref) for the full detail before "
        "deciding.\n\n"
        f"Finding types:\n{type_lines}")


def _tool_wrapper(fn):
    """Re-raise CaseError as the SDK's ToolError so its message reaches the
    model (anything else is treated as a crash and masked). functools.wraps
    keeps the name/doc/annotations the SDK builds the tool schema from."""
    @functools.wraps(fn)
    def wrapped(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except CaseError as exc:
            raise _ToolError(str(exc)) from None
    return wrapped


def build_server():
    _require_mcp()
    server = _MCPServer("vera", instructions=_instructions())
    for fn in _TOOLS:
        server.tool()(_tool_wrapper(fn))
    server.resource("vera://case/report", mime_type="text/markdown")(case_report)
    return server


def serve(case_path: str, actor: str) -> int:
    _STATE.update(path=os.path.abspath(case_path), actor=actor)
    build_server().run()  # stdio transport
    return 0
