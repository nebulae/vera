"""vera command line: fast investigation logging while you work."""

from __future__ import annotations

import argparse
import mimetypes
import os
import subprocess
import sys

from . import __version__, db, types
from .db import Case, CaseError

CONFIG_DIR = os.path.expanduser("~/.config/vera")
ACTIVE_FILE = os.path.join(CONFIG_DIR, "active")


# -- active case handling ----------------------------------------------------

def active_case_path(cli_arg: str | None) -> str:
    if cli_arg:
        return cli_arg
    env = os.environ.get("VERA_CASE")
    if env:
        return env
    if os.path.exists(ACTIVE_FILE):
        with open(ACTIVE_FILE) as fh:
            path = fh.read().strip()
        if path:
            return path
    raise CaseError(
        "no active case. Run 'vera use <case.vera>', set $VERA_CASE, "
        "or pass --case")


def open_case(args) -> Case:
    return Case(active_case_path(getattr(args, "case", None)))


# -- small output helpers ----------------------------------------------------

def _tty() -> bool:
    return sys.stdout.isatty()


def c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _tty() else text


# disposition -> ANSI color for terminal output
_STATUS_COLOR = {"compromised": "1;31", "suspicious": "1;33", "clean": "32"}


def aid(n: int) -> str:
    return c("1;36", f"A{n}")


def fid(n: int) -> str:
    return c("1;33", f"F{n}")


def die(msg: str) -> int:
    print(f"vera: {msg}", file=sys.stderr)
    return 1


# -- commands ----------------------------------------------------------------

def cmd_init(args) -> int:
    path = args.path
    if not os.path.splitext(path)[1]:
        path += ".vera"
    with Case(path, create=True) as case:
        case.set_meta(name=args.name or os.path.splitext(os.path.basename(path))[0],
                      investigator=args.investigator or "",
                      description=args.description or "")
    _set_active(path)
    print(f"created case {path} (now active)")
    return 0


def _set_active(path: str) -> None:
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(ACTIVE_FILE, "w") as fh:
        fh.write(os.path.abspath(path) + "\n")


def cmd_use(args) -> int:
    if not args.path:
        try:
            print(active_case_path(None))
            return 0
        except CaseError:
            print("no active case")
            return 1
    Case(args.path).close()  # validate before switching
    _set_active(args.path)
    print(f"active case: {os.path.abspath(args.path)}")
    return 0


def cmd_status(args) -> int:
    with open_case(args) as case:
        meta, n = case.meta(), case.counts()
        print(f"case:        {case.path}")
        print(f"name:        {meta.get('name', '')}")
        if meta.get("investigator"):
            print(f"investigator: {meta['investigator']}")
        if meta.get("description"):
            print(f"description: {meta['description']}")
        print(f"created:     {meta.get('created_at', '')}")
        print(f"{n['actions']} actions, {n['findings']} findings, "
              f"{n['evidence']} evidence items")
    return 0


def cmd_evidence(args) -> int:
    with open_case(args) as case:
        if args.evidence_cmd == "add":
            collection_id = (case.resolve_collection(args.collection)
                             if args.collection else None)
            if _parse_host_list(args.hosts):
                host_ids = _strict_host_ids(case, args.hosts)
            elif collection_id is not None:
                # inherit the collection's hosts when none given explicitly
                host_ids = case.collection_host_ids(collection_id)
            else:
                host_ids = []
            sha = args.sha256 or ""
            if args.hash_file:
                sha = db.hash_file(args.hash_file)["sha256"]
            eid = case.add_evidence(args.label, kind=args.kind or "",
                                    source=args.source or "",
                                    sha256=sha,
                                    acquired_by=args.acquired_by or "",
                                    acquired_at=args.acquired_at or "",
                                    acquisition=args.acquisition or "",
                                    notes=args.note or "",
                                    collection_id=collection_id,
                                    host_ids=host_ids)
            where = f" (collection C{collection_id})" if collection_id else ""
            on = f" from {len(host_ids)} host(s)" if host_ids else ""
            hashed = f"\n   sha256 {sha}" if args.hash_file else ""
            print(f"E{eid} added — {args.label}{where}{on}{hashed}")
        elif args.evidence_cmd == "edit":
            kind, eid = db.resolve_ref(args.ref)
            if kind != "E":
                raise CaseError("evidence edit expects an evidence ref like E2")
            fields = {}
            for attr, col in (("label", "label"), ("kind", "kind"),
                              ("source", "source"), ("sha256", "sha256"),
                              ("acquired_by", "acquired_by"),
                              ("acquired_at", "acquired_at"),
                              ("acquisition", "acquisition"),
                              ("note", "notes")):
                val = getattr(args, attr)
                if val is not None:
                    fields[col] = val
            if args.hash_file:
                fields["sha256"] = db.hash_file(args.hash_file)["sha256"]
            if args.collection is not None:
                fields["collection_id"] = (None if args.collection.lower() == "none"
                                           else case.resolve_collection(args.collection))
            if fields:
                case.update_evidence(eid, **fields)
            if args.hosts is not None:
                case.set_evidence_hosts(eid, _strict_host_ids(case, args.hosts))
            if not fields and args.hosts is None:
                raise CaseError("nothing to change — pass --label/--kind/--sha256/…")
            print(f"E{eid} updated")
        else:
            items = case.evidence()
            if not items:
                print("no evidence recorded")
            for e in items:
                line = f"E{e['id']}  {e['label']}"
                if e["kind"]:
                    line += f"  [{e['kind']}]"
                if e.get("hosts"):
                    line += "  @" + ",".join(h["name"] for h in e["hosts"])
                if e.get("collection_id"):
                    line += f"  C{e['collection_id']}"
                if e["sha256"]:
                    line += f"  sha256:{e['sha256'][:16]}…"
                print(line)
                if e["source"]:
                    print(f"     source: {e['source']}")
                custody = ", ".join(x for x in (
                    e["acquired_by"] and f"by {e['acquired_by']}",
                    e["acquired_at"] and f"at {e['acquired_at']}",
                    e["acquisition"] and f"via {e['acquisition']}") if x)
                if custody:
                    print(f"     acquired: {custody}")
    return 0


def cmd_host(args) -> int:
    with open_case(args) as case:
        if args.host_cmd == "add":
            names = list(args.names)
            if args.from_file:
                names += _read_host_file(args.from_file)
            if not names:
                raise CaseError("give at least one host name (or --from FILE)")
            added = []
            for name in names:
                hid = case.add_host(name, aliases=args.alias or [],
                                    ip=args.ip or "", os=args.os or "",
                                    status=args.status or "",
                                    system_type=args.type or "",
                                    criticality=args.crit or "", notes=args.note or "")
                added.append((hid, name))
            for hid, name in added:
                print(f"H{hid}  {name}")
            print(f"{len(added)} host(s) registered")
        elif args.host_cmd == "edit":
            hid = case.resolve_host(args.ref)
            fields = {}
            if args.name is not None:
                fields["name"] = args.name
            if args.ip is not None:
                fields["ip"] = args.ip
            if args.os is not None:
                fields["os"] = args.os
            if args.status is not None:
                fields["status"] = args.status
            if args.type is not None:
                fields["system_type"] = args.type
            if args.crit is not None:
                fields["criticality"] = args.crit
            if args.note is not None:
                fields["notes"] = args.note
            if args.alias is not None:
                fields["aliases"] = args.alias  # replaces the alias list
            if args.add_alias:
                cur = next(h for h in case.hosts() if h["id"] == hid)["aliases"]
                lowered = {a.lower() for a in cur}
                fields["aliases"] = cur + [a for a in args.add_alias
                                           if a.lower() not in lowered]
            if not fields:
                raise CaseError("nothing to change — pass --name/--ip/--type/…")
            case.update_host(hid, **fields)
            print(f"H{hid} updated")
        elif args.host_cmd == "show":
            hid = case.resolve_host(args.ref)
            h = next(h for h in case.hosts() if h["id"] == hid)
            print(f"H{h['id']}  {h['name']}")
            if h["aliases"]:
                print(f"  aliases: {', '.join(h['aliases'])}")
            for key, label in (("ip", "ip"), ("os", "os"), ("status", "status"),
                               ("system_type", "type"),
                               ("criticality", "criticality"), ("notes", "notes")):
                if h[key]:
                    print(f"  {label}: {h[key]}")
            findings = case.findings_for_host(hid)
            print(f"  findings affecting this host: {len(findings)}")
            for f in findings:
                print(f"    F{f['id']} [{f['ftype']}] {f['title']}")
        else:
            hosts = case.hosts()
            if not hosts:
                print("no hosts registered — add with 'vera host add WS01 WS02 …'")
            for h in hosts:
                extra = f"  {h['ip']}" if h["ip"] else ""
                extra += f"  {h['os']}" if h["os"] else ""
                extra += f"  [{h['system_type']}]" if h["system_type"] else ""
                if h["status"]:
                    extra += "  " + c(_STATUS_COLOR.get(h["status"], "0"),
                                      h["status"].upper())
                print(f"H{h['id']:>3}  {h['name']:<20}{extra}  "
                      f"({h['finding_count']} findings)")
    return 0


def cmd_collection(args) -> int:
    with open_case(args) as case:
        if args.collection_cmd == "add":
            host_ids = _strict_host_ids(case, args.hosts)
            cid = case.add_collection(args.name, tool=args.tool or "",
                                      operator=args.operator or "",
                                      collected_at=args.at or "",
                                      scope=args.scope or "", notes=args.note or "",
                                      host_ids=host_ids)
            on = f" — {len(host_ids)} host(s)" if host_ids else ""
            print(f"C{cid} added — {args.name}{on}")
        elif args.collection_cmd == "edit":
            cid = case.resolve_collection(args.ref)
            fields = {}
            for attr, col in (("name", "name"), ("tool", "tool"),
                              ("operator", "operator"), ("at", "collected_at"),
                              ("scope", "scope"), ("note", "notes")):
                val = getattr(args, attr)
                if val is not None:
                    fields[col] = val
            if fields:
                case.update_collection(cid, **fields)
            if args.hosts is not None:
                case.set_collection_hosts(cid, _strict_host_ids(case, args.hosts))
            if not fields and args.hosts is None:
                raise CaseError("nothing to change — pass --name/--hosts/…")
            print(f"C{cid} updated")
        elif args.collection_cmd == "expand":
            cid = case.resolve_collection(args.ref)
            created = case.expand_collection(cid, kind=args.kind or "")
            for item in created:
                print(f"E{item['id']}  {item['host']}")
            col = next(x for x in case.collections() if x["id"] == cid)
            skipped = len(col["hosts"]) - len(created)
            note = f" ({skipped} host(s) already covered)" if skipped else ""
            print(f"{len(created)} evidence item(s) created in C{cid}{note}")
        else:
            cols = case.collections()
            if not cols:
                print("no collections — add with 'vera collection add \"name\"'")
            for col in cols:
                line = f"C{col['id']}  {col['name']}"
                if col["tool"]:
                    line += f"  [{col['tool']}]"
                if col.get("hosts"):
                    line += f"  🖥 {len(col['hosts'])} host(s)"
                if col["scope"]:
                    line += f"  — {col['scope']}"
                print(line)
    return 0


def _read_host_file(path: str) -> list[str]:
    try:
        with open(path) as fh:
            return [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
    except OSError as exc:
        raise CaseError(f"cannot read {path}: {exc}") from None


def _parse_host_list(raw: list[str] | None) -> list[str]:
    """Accept repeated --hosts and comma/space-separated values."""
    out: list[str] = []
    for chunk in (raw or []):
        for part in chunk.replace(",", " ").split():
            if part:
                out.append(part)
    return out


def _read_piped_stdin() -> str:
    """Capture piped stdin, but never block when nothing was piped.

    `cmd | vera run "cmd"` should capture the output; a bare `vera run "cmd"`
    in a terminal or a script must not hang waiting on stdin. We only read
    when the stream is non-interactive *and* has data ready to read.
    """
    try:
        if sys.stdin is None or sys.stdin.isatty():
            return ""
        import select
        ready, _, _ = select.select([sys.stdin], [], [], 0.0)
        if not ready:
            return ""
        return sys.stdin.read()
    except (OSError, ValueError):
        return ""


def _guess_mime(path: str) -> str:
    mime, _ = mimetypes.guess_type(path)
    return mime or "application/octet-stream"


def _read_file(path: str) -> bytes:
    try:
        with open(path, "rb") as fh:
            return fh.read()
    except OSError as exc:
        raise CaseError(f"cannot read {path}: {exc}") from None


def _attach_files(case: Case, owner_type: str, owner_id: int,
                  paths: list[str] | None, role: str) -> None:
    for path in paths or []:
        data = _read_file(path)
        att = case.add_attachment(owner_type, owner_id, data,
                                  filename=os.path.basename(path),
                                  mime=_guess_mime(path), role=role)
        print(f"   📎 attached {os.path.basename(path)} "
              f"(#{att}, {len(data)} bytes)")


def _strict_host_ids(case: Case, raw: list[str] | None) -> list[int]:
    """Resolve --hosts refs against the registry; never auto-create."""
    refs = _parse_host_list(raw)
    ids = []
    for ref in refs:
        try:
            ids.append(case.resolve_host(ref, create=False))
        except CaseError:
            raise CaseError(
                f"no host matches {ref!r} — add it first with 'vera host add "
                f"{ref}'") from None
    return ids


def _action_host_ids(case: Case, hosts_arg, evidence_id) -> list[int]:
    """Strict --hosts if given; otherwise inherit the evidence's source hosts."""
    if _parse_host_list(hosts_arg):
        return _strict_host_ids(case, hosts_arg)
    if evidence_id is not None:
        for ev in case.evidence():
            if ev["id"] == evidence_id:
                return [h["id"] for h in ev.get("hosts", [])]
    return []


def cmd_run(args) -> int:
    output, exit_code = "", None
    if args.execute:
        proc = subprocess.run(args.command, shell=True, capture_output=True,
                              text=True, errors="replace")
        output = proc.stdout + (("\n[stderr]\n" + proc.stderr) if proc.stderr else "")
        exit_code = proc.returncode
        if proc.stdout:
            sys.stdout.write(proc.stdout)
        if proc.stderr:
            sys.stderr.write(proc.stderr)
    else:
        output = _read_piped_stdin()

    with open_case(args) as case:
        parent = None
        if args.from_finding:
            kind, parent = db.resolve_ref(args.from_finding)
            if kind != "F":
                raise CaseError("--from expects a finding reference like F3")
        evidence_id = (case.resolve_evidence(args.evidence)
                       if args.evidence else None)
        collection_id = (case.resolve_collection(args.collection)
                         if args.collection else None)
        host_ids = _action_host_ids(case, args.hosts, evidence_id)
        a = case.add_action(args.command, host=args.host or "",
                            tool=args.tool or "", evidence_id=evidence_id,
                            collection_id=collection_id, output=output,
                            exit_code=exit_code, notes=args.note or "",
                            parent_finding_id=parent, host_ids=host_ids)
        where = f" (follow-up to {fid(parent)})" if parent else ""
        captured = f", {len(output)} chars captured" if output else ""
        on = f" on {len(host_ids)} host(s)" if host_ids else ""
        print(f"{aid(a)} recorded{where}{captured}{on}")
        if exit_code not in (None, 0):
            print(f"   exit code {exit_code}")
        _attach_files(case, "action", a, args.shot, "output")
    return 0


def cmd_manual(args) -> int:
    """Log a GUI/tool step (no command line) — reproducible as a procedure."""
    with open_case(args) as case:
        parent = None
        if args.from_finding:
            kind, parent = db.resolve_ref(args.from_finding)
            if kind != "F":
                raise CaseError("--from expects a finding reference like F3")
        evidence_id = (case.resolve_evidence(args.evidence)
                       if args.evidence else None)
        collection_id = (case.resolve_collection(args.collection)
                         if args.collection else None)
        host_ids = _action_host_ids(case, args.hosts, evidence_id)
        a = case.add_action(method="manual", tool=args.tool,
                            procedure=args.procedure, host=args.host or "",
                            evidence_id=evidence_id, collection_id=collection_id,
                            notes=args.note or "", parent_finding_id=parent,
                            host_ids=host_ids)
        where = f" (follow-up to {fid(parent)})" if parent else ""
        on = f" on {len(host_ids)} host(s)" if host_ids else ""
        print(f"{aid(a)} recorded [manual · {args.tool}]{where}{on}")
        _attach_files(case, "action", a, args.shot, "output")
    return 0


def _collect_attrs(args) -> dict:
    attrs = {}
    for key in types.all_attr_fields():
        val = getattr(args, f"attr_{key}", None)
        if val is not None:
            attrs[key] = val
    for pair in (args.attr or []):
        if "=" not in pair:
            raise CaseError(f"--attr expects key=value, got {pair!r}")
        k, v = pair.split("=", 1)
        attrs[k.strip()] = v
    return attrs


def _collect_hashes(args) -> dict:
    """Gather --md5/--sha1/--sha256, or compute all three from --hash-file."""
    hashes = {}
    if getattr(args, "hash_file", None):
        hashes.update(db.hash_file(args.hash_file))
    for algo in db.HASH_SPECS:
        val = getattr(args, algo, None)
        if val:
            hashes[algo] = val
    return db.normalize_hashes(hashes)


def cmd_finding(args) -> int:
    if args.type not in types.FINDING_TYPES:
        known = ", ".join(types.FINDING_TYPES)
        raise CaseError(f"unknown type {args.type!r} (one of: {known})")
    with open_case(args) as case:
        if args.on and args.on.lower() == "none":
            action_id = None
        elif args.on:
            kind, action_id = db.resolve_ref(args.on)
            if kind != "A":
                raise CaseError("--on expects an action reference like A4")
        else:
            action_id = case.last_action_id()
            if action_id is None:
                raise CaseError(
                    "no actions in case yet — log one with 'vera run', "
                    "or use --on none for a standalone finding")
        host_refs = _parse_host_list(args.hosts)
        if host_refs:
            host_ids = _strict_host_ids(case, args.hosts)
        elif action_id is not None:
            # inherit the action's host(s) when none are given explicitly
            host_ids = [h["id"] for h in case.get_action(action_id).get("hosts", [])]
        else:
            host_ids = None
        hashes = _collect_hashes(args)
        f = case.add_finding(args.title, ftype=args.type, action_id=action_id,
                             host=args.host or "", detail=args.detail or "",
                             event_time=args.time or "",
                             time_kind=args.time_kind or "",
                             attrs=_collect_attrs(args), starred=args.star,
                             host_ids=host_ids or None, hashes=hashes)
        label = types.FINDING_TYPES[args.type].label
        under = f" under {aid(action_id)}" if action_id else " (unattached)"
        stack = f" — affects {len(host_ids)} host(s)" if host_ids else ""
        print(f"{fid(f)} [{label}] added{under}{stack}")
        if hashes:
            print("   " + "  ".join(f"{a}:{v[:12]}…" for a, v in hashes.items()))
        _attach_files(case, "finding", f, args.shot, "exhibit")
    return 0


def cmd_coverage(args) -> int:
    """Hosts × analysis rollup — the 'did we look at everything?' view."""
    with open_case(args) as case:
        cov = case.coverage()
        if not cov["hosts"]:
            print("no hosts registered")
            return 0
        gaps = [h for h in cov["hosts"] if h["actions"] == 0]
        print(f"{'':>4} {'Host':<20} {'Status':<12} {'Ev':>3} {'Act':>4} "
              f"{'Fnd':>4}  Last examined")
        for h in cov["hosts"]:
            status = h["status"] or "-"
            line = (f"H{h['id']:>3} {h['name']:<20} "
                    f"{c(_STATUS_COLOR.get(h['status'], '2'), f'{status:<12}')} "
                    f"{h['evidence']:>3} {h['actions']:>4} {h['findings']:>4}  "
                    f"{h['last_examined'] or c('2', 'never')}")
            print(line)
        if gaps:
            names = ", ".join(h["name"] for h in gaps)
            print(c("1;33", f"\n{len(gaps)} of {len(cov['hosts'])} host(s) have "
                            f"no analysis logged yet:"))
            print(f"  {names}")
        else:
            print(c("32", f"\nall {len(cov['hosts'])} hosts have at least one "
                          f"analysis step logged"))
    return 0


def cmd_stack(args) -> int:
    with open_case(args) as case:
        rows = case.stack_findings()
        if not rows:
            print("no cross-host findings yet — add one with "
                  "'vera finding \"…\" --hosts WS01,WS02,…'")
            return 0
        print("Cross-host findings (rarest first — least frequency of occurrence):")
        for f in rows:
            names = ", ".join(h["name"] for h in f["affected_hosts"])
            print(f"  {fid(f['id'])}  ({f['stack']:>2} hosts)  {f['title']}")
            print(f"          {c('2', names)}")
    return 0


def cmd_artifacts(args) -> int:
    with open_case(args) as case:
        groups = case.artifact_stacks()
        if not groups:
            print("no host-based indicators yet — add one with "
                  r"'vera finding \"…\" -t hostindicator --path C:\...\evil.dll'")
            return 0
        print("Host-based indicators stacked by artifact name "
              "(most-spread first):")
        for g in groups:
            atype = "/".join(g["artifact_types"])
            head = f"  {g['name']}  (×{g['count']}"
            if g["host_count"]:
                s = "s" if g["host_count"] != 1 else ""
                head += f", {g['host_count']} host{s}"
            head += ")"
            if atype:
                head += f"  [{atype}]"
            print(head)
            hosts = ", ".join(h["name"] for h in g["hosts"])
            if hosts:
                print(f"      {c('2', 'hosts: ' + hosts)}")
            for p in g["paths"]:
                print(f"      {c('2', p)}")
    return 0


def _resolve_finding_ref(ref: str) -> int:
    kind, fid = db.resolve_ref(ref)
    if kind != "F":
        raise CaseError(f"expected a finding reference like F8, got {ref!r}")
    return fid


_LEAD_ITEM_MARK = {"open": "○", "triaged": "●", "dismissed": "✗"}


def cmd_lead(args) -> int:
    with open_case(args) as case:
        op = getattr(args, "lead_cmd", None)
        if op == "add":
            lead_id = _resolve_finding_ref(args.ref)
            link_fid = _resolve_finding_ref(args.finding) if args.finding else None
            item_id = case.add_lead_item(lead_id, args.label,
                                         status=args.status or "open",
                                         finding_id=link_fid)
            print(f"item {item_id} added to F{lead_id}")
        elif op == "set":
            fields = {}
            if args.status:
                fields["status"] = args.status
            if args.finding:
                fields["finding_id"] = _resolve_finding_ref(args.finding)
            if args.label:
                fields["label"] = args.label
            if not fields:
                raise CaseError("nothing to change — pass --status/--finding/--label")
            case.update_lead_item(args.item, **fields)
            print(f"item {args.item} updated")
        elif op == "rm":
            case.soft_delete_lead_item(args.item)
            print(f"item {args.item} removed")
        else:
            leads = case.leads()
            if not leads:
                print("no leads yet — add one with "
                      "'vera f \"…\" -t lead --on none'")
                return 0
            for L in leads:
                prog = (f"{L['item_resolved']}/{L['item_total']} triaged"
                        if L["item_total"] else "no items")
                star = "★ " if L["starred"] else ""
                print(f"{fid(L['id'])} {star}{L['title']}  ({prog})")
                for it in L["items"]:
                    mark = _LEAD_ITEM_MARK.get(it["status"], "?")
                    link = f"  → F{it['finding']['id']}" if it["finding"] else ""
                    print(f"    [{it['id']}] {mark} {it['label']}"
                          f"{c('2', f' {it['status']}')}{c('2', link)}")
    return 0


def cmd_clone(args) -> int:
    kind, src_id = db.resolve_ref(args.ref)
    if kind not in ("A", "F"):
        raise CaseError("clone expects an action (A#) or finding (F#) reference")
    with open_case(args) as case:
        if kind == "F":
            overrides = {"title": args.title} if args.title else {}
            new_id = case.clone_finding(src_id, **overrides)
            print(f"{fid(new_id)} cloned from F{src_id} — edit it with "
                  f"'vera edit F{new_id} …'")
        else:
            new_id = case.clone_action(src_id)
            print(f"{aid(new_id)} cloned from A{src_id} — edit it with "
                  f"'vera edit A{new_id} …'")
    return 0


def cmd_attach(args) -> int:
    kind, ref_id = db.resolve_ref(args.ref)
    owner = {"A": "action", "F": "finding", "E": "evidence"}[kind]
    data = _read_file(args.file)
    with open_case(args) as case:
        att = case.add_attachment(owner, ref_id, data,
                                  filename=os.path.basename(args.file),
                                  mime=_guess_mime(args.file), role=args.role,
                                  caption=args.caption or "")
        print(f"📎 attached {os.path.basename(args.file)} to {args.ref.upper()} "
              f"(attachment #{att}, {len(data)} bytes, role {args.role})")
    return 0


def _print_attachments(atts: list[dict]) -> None:
    for at in atts:
        cap = f" — {at['caption']}" if at["caption"] else ""
        print(f"  📎 #{at['id']} [{at['role']}] {at['filename']} "
              f"({at['size']} bytes, sha256 {at['sha256'][:16]}…){cap}")


def cmd_show(args) -> int:
    if args.ref[:1].upper() == "H":
        return cmd_host(argparse.Namespace(
            host_cmd="show", ref=args.ref, case=getattr(args, "case", None)))
    kind, ref_id = db.resolve_ref(args.ref)
    with open_case(args) as case:
        if kind == "A":
            a = case.get_action(ref_id)
            print(f"{aid(a['id'])}  {a['performed_at']}")
            if a["method"] == "manual":
                print(f"  tool: {a['tool']}  (manual step)")
                if a["procedure"]:
                    print(f"  procedure: {a['procedure']}")
            else:
                print(f"  command: {a['command']}")
                if a["tool"]:
                    print(f"  tool: {a['tool']}")
            if a.get("hosts"):
                print("  hosts: " + ", ".join(f"{h['name']}(H{h['id']})"
                                               for h in a["hosts"]))
            elif a["host"]:
                print(f"  host: {a['host']}")
            if a["notes"]:
                print(f"  notes: {a['notes']}")
            if a["evidence_id"]:
                print(f"  evidence: E{a['evidence_id']}")
            if a.get("collection_id"):
                print(f"  collection: C{a['collection_id']}")
            if a["parent_finding_id"]:
                print(f"  follow-up to: F{a['parent_finding_id']}")
            if a["exit_code"] is not None:
                print(f"  exit code: {a['exit_code']}")
            if a["output"]:
                trunc = " (truncated)" if a["output_truncated"] else ""
                print(f"  output{trunc}, sha256 {a['output_sha256'][:16]}…:")
                for line in a["output"].splitlines():
                    print(f"    {line}")
            _print_attachments(a["attachments"])
        elif kind == "F":
            f = case.get_finding(ref_id)
            ft = types.FINDING_TYPES.get(f["ftype"])
            star = " ★" if f["starred"] else ""
            print(f"{fid(f['id'])} [{ft.label if ft else f['ftype']}]{star}  {f['title']}")
            for key, label in (("host", "host"), ("event_time", "event time"),
                               ("time_kind", "time means"), ("detail", "detail")):
                if f.get(key):
                    print(f"  {label}: {f[key]}")
            for k, v in f["attrs"].items():
                if v:
                    print(f"  {k}: {v}")
            for algo in db.HASH_SPECS:
                if f.get("hashes", {}).get(algo):
                    print(f"  {algo}: {f['hashes'][algo]}")
            if f.get("affected_hosts"):
                names = ", ".join(h["name"] for h in f["affected_hosts"])
                print(f"  affected hosts ({f['stack']}): {names}")
            if f["action_id"]:
                print(f"  found via: A{f['action_id']}")
            _print_attachments(f["attachments"])
        elif kind == "E":
            items = [e for e in case.evidence() if e["id"] == ref_id]
            if not items:
                raise CaseError(f"E{ref_id} does not exist")
            e = items[0]
            print(f"E{e['id']}  {e['label']}")
            for key, label in (("kind", "kind"), ("source", "source"),
                               ("sha256", "sha256"), ("notes", "notes")):
                if e[key]:
                    print(f"  {label}: {e[key]}")
            if e.get("collection_id"):
                print(f"  collection: C{e['collection_id']}")
            _print_attachments(e["attachments"])
    return 0


def _tree_lines(case: Case) -> list[str]:
    lines: list[str] = []

    def _shots(node: dict, pad: str) -> None:
        n = len(node.get("attachments") or [])
        if n:
            lines.append(f"{pad}   {c('2', f'📎 {n} screenshot(s)')}")

    def emit_action(a: dict, depth: int) -> None:
        pad = "  " * depth
        names = ",".join(h["name"] for h in a.get("hosts", [])) or a["host"]
        host = f" @{names}" if names else ""
        if a.get("method") == "manual":
            body = f"🔧 {a['tool']}: {a['procedure']}"
        else:
            body = f"$ {a['command']}"
        lines.append(f"{pad}{aid(a['id'])}{host}  {body}")
        if a["notes"]:
            lines.append(f"{pad}   {c('2', a['notes'])}")
        _shots(a, pad)
        for f in a["findings"]:
            emit_finding(f, depth + 1)

    def emit_finding(f: dict, depth: int) -> None:
        pad = "  " * depth
        ft = types.FINDING_TYPES.get(f["ftype"])
        tag = ft.label if ft else f["ftype"]
        star = " ★" if f["starred"] else ""
        when = f" ({f['event_time']})" if f["event_time"] else ""
        stack = f" 🖥 {f['stack']} hosts" if f.get("stack", 0) > 1 else ""
        lines.append(f"{pad}{fid(f['id'])} [{tag}]{star} {f['title']}{when}{c('2', stack)}")
        _shots(f, pad)
        for a in f["actions"]:
            emit_action(a, depth + 1)

    for a in case.tree():
        emit_action(a, 0)
    orphans = case.unattached_findings()
    if orphans:
        lines.append("(unattached findings)")
        for f in orphans:
            emit_finding(f, 1)
    return lines


def cmd_log(args) -> int:
    with open_case(args) as case:
        lines = _tree_lines(case)
        if not lines:
            print("case is empty — log your first command with 'vera run'")
            return 0
        for line in lines:
            print(line)
    return 0


def cmd_edit(args) -> int:
    kind, ref_id = db.resolve_ref(args.ref)
    with open_case(args) as case:
        if kind == "A":
            fields = {}
            if args.note is not None:
                fields["notes"] = args.note
            if args.host is not None:
                fields["host"] = args.host
            if args.command is not None:
                fields["command"] = args.command
            if args.tool is not None:
                fields["tool"] = args.tool
            if args.time is not None:
                fields["performed_at"] = args.time
            if args.parent is not None:
                if args.parent.lower() == "none":
                    fields["parent_finding_id"] = None
                else:
                    k, pid = db.resolve_ref(args.parent)
                    if k != "F":
                        raise CaseError("--parent expects F<n> or 'none'")
                    fields["parent_finding_id"] = pid
            if not fields:
                raise CaseError("nothing to change")
            case.update_action(ref_id, **fields)
        elif kind == "F":
            f = case.get_finding(ref_id)
            fields = {}
            if args.title is not None:
                fields["title"] = args.title
            if args.note is not None or args.detail is not None:
                fields["detail"] = args.detail if args.detail is not None else args.note
            if args.host is not None:
                fields["host"] = args.host
            if args.time is not None:
                fields["event_time"] = args.time
            if args.time_kind is not None:
                fields["time_kind"] = ("" if args.time_kind == "none"
                                       else args.time_kind)
            if args.type is not None:
                if args.type not in types.FINDING_TYPES:
                    raise CaseError(f"unknown type {args.type!r}")
                fields["ftype"] = args.type
            if args.star:
                fields["starred"] = 1
            if args.unstar:
                fields["starred"] = 0
            new_attrs = _collect_attrs(args)
            if new_attrs:
                fields["attrs"] = {**f["attrs"], **new_attrs}
            if not fields:
                raise CaseError("nothing to change")
            case.update_finding(ref_id, **fields)
        else:
            raise CaseError("edit expects A<n> or F<n>")
        print(f"{args.ref.upper()} updated")
    return 0


def cmd_export(args) -> int:
    from . import export
    with open_case(args) as case:
        written = export.export(case, args.format, args.out)
    for path in written:
        print(f"wrote {path}")
    return 0


def cmd_serve(args) -> int:
    from . import server
    path = None
    if not args.new:
        try:
            path = active_case_path(getattr(args, "case", None))
            Case(path).close()  # fail fast on a bad path before binding the port
        except CaseError:
            path = None  # no active case -> start on the New Investigation screen
    case_dir = args.dir or (os.path.dirname(path) if path else os.getcwd())
    return server.serve(path, port=args.port, open_browser=not args.no_browser,
                        case_dir=case_dir)


# -- parser ------------------------------------------------------------------

def _add_attr_flags(p: argparse.ArgumentParser) -> None:
    for key, fld in types.all_attr_fields().items():
        p.add_argument(f"--{key.replace('_', '-')}", dest=f"attr_{key}",
                       metavar="VAL", help=fld.label.lower())
    p.add_argument("--attr", action="append", metavar="KEY=VAL",
                   help="arbitrary extra attribute (repeatable)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vera",
        description="Verified Evidence Record and Annotations — track a DFIR "
                    "investigation as a replayable chain of commands and findings.")
    parser.add_argument("--version", action="version",
                        version=f"vera {__version__}")
    parser.add_argument("--case", metavar="PATH",
                        help="case file (default: $VERA_CASE or 'vera use' selection)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("init", help="create a new case file")
    p.add_argument("path", help="case file to create, e.g. lab1.vera")
    p.add_argument("--name", help="case name (default: file name)")
    p.add_argument("--investigator")
    p.add_argument("--description")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("use", help="set (or show) the active case")
    p.add_argument("path", nargs="?", help="case file to make active")
    p.set_defaults(func=cmd_use)

    p = sub.add_parser("status", help="case summary")
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("evidence", help="manage evidence items")
    esub = p.add_subparsers(dest="evidence_cmd", required=True)
    pa = esub.add_parser("add", help="register an evidence item")
    pa.add_argument("label", help="e.g. 'WS01 memory dump'")
    pa.add_argument("--kind", help="disk / memory / triage / logs ...")
    pa.add_argument("--source", help="original path or acquisition detail")
    pa.add_argument("--sha256")
    pa.add_argument("--hash-file", metavar="PATH",
                    help="compute the sha256 from a local copy of the evidence")
    pa.add_argument("--acquired-by", help="who collected/acquired it")
    pa.add_argument("--acquired-at", help="when it was acquired (UTC)")
    pa.add_argument("--acquisition",
                    help="how it was acquired — tool/method, e.g. 'KAPE triage'")
    pa.add_argument("--collection", metavar="REF",
                    help="collection/batch this evidence belongs to (C2 or name)")
    pa.add_argument("--hosts", action="append", metavar="LIST",
                    help="source host(s) this evidence came from — registry refs "
                         "(RD03 / H3), comma/space list, must already exist")
    pa.add_argument("--note")
    pe = esub.add_parser("edit", help="edit an evidence item")
    pe.add_argument("ref", help="E2")
    pe.add_argument("--label")
    pe.add_argument("--kind")
    pe.add_argument("--source")
    pe.add_argument("--sha256")
    pe.add_argument("--hash-file", metavar="PATH",
                    help="compute the sha256 from a local copy of the evidence")
    pe.add_argument("--acquired-by", help="who collected/acquired it")
    pe.add_argument("--acquired-at", help="when it was acquired (UTC)")
    pe.add_argument("--acquisition", help="how it was acquired — tool/method")
    pe.add_argument("--note", help="notes")
    pe.add_argument("--collection", metavar="REF",
                    help="collection ref (C2 / name), or 'none' to detach")
    pe.add_argument("--hosts", action="append", metavar="LIST",
                    help="replace source host(s) — registry refs, comma/space list")
    esub.add_parser("list", help="list evidence")
    p.set_defaults(func=cmd_evidence)

    p = sub.add_parser("host", help="manage the host registry")
    hsub = p.add_subparsers(dest="host_cmd", required=True)
    ha = hsub.add_parser("add", help="register one or more hosts")
    ha.add_argument("names", nargs="*", help="host name(s), e.g. WS01 WS02 WS03")
    ha.add_argument("--from", dest="from_file", metavar="FILE",
                    help="read host names, one per line, from a file")
    ha.add_argument("--alias", action="append", help="alias (repeatable)")
    ha.add_argument("--ip")
    ha.add_argument("--os", help="operating system, e.g. 'Windows 11'")
    ha.add_argument("--status", choices=("unknown", "clean", "suspicious",
                                         "compromised"),
                    help="disposition (default: unknown)")
    ha.add_argument("--type", help="workstation / DC / server ...")
    ha.add_argument("--crit", help="criticality tag")
    ha.add_argument("--note")
    he = hsub.add_parser("edit", help="edit a host after adding it")
    he.add_argument("ref", help="H3, a host name, or an alias")
    he.add_argument("--name", help="rename the host")
    he.add_argument("--ip")
    he.add_argument("--os", help="operating system, e.g. 'Windows 11'")
    he.add_argument("--status", choices=("unknown", "clean", "suspicious",
                                         "compromised"),
                    help="disposition — drives the Compromised view")
    he.add_argument("--type", help="workstation / DC / server ...")
    he.add_argument("--crit", help="criticality tag")
    he.add_argument("--note", help="notes")
    he.add_argument("--alias", action="append",
                    help="replace the alias list (repeatable)")
    he.add_argument("--add-alias", action="append", dest="add_alias",
                    help="append an alias without dropping existing ones (repeatable)")
    hs = hsub.add_parser("show", help="show a host and the findings affecting it")
    hs.add_argument("ref", help="H3, a host name, or an alias")
    hsub.add_parser("list", help="list registered hosts")
    p.set_defaults(func=cmd_host)

    p = sub.add_parser("collection", help="manage collections/batches (a sweep)")
    csub = p.add_subparsers(dest="collection_cmd", required=True)
    ca = csub.add_parser("add", help="register a collection/batch")
    ca.add_argument("name", help="e.g. 'Lab2 amcache+shimcache export'")
    ca.add_argument("--tool", help="AmcacheParser / KAPE / Velociraptor ...")
    ca.add_argument("--operator")
    ca.add_argument("--at", help="when it was collected")
    ca.add_argument("--scope", help="e.g. '40 hosts, amcache+shimcache'")
    ca.add_argument("--hosts", action="append", metavar="LIST",
                    help="host(s) this collection covers — registry refs, comma/"
                         "space list. Evidence added to it inherits these.")
    ca.add_argument("--note")
    ce = csub.add_parser("edit", help="edit a collection")
    ce.add_argument("ref", help="C1")
    ce.add_argument("--name")
    ce.add_argument("--tool")
    ce.add_argument("--operator")
    ce.add_argument("--at")
    ce.add_argument("--scope")
    ce.add_argument("--note", help="notes")
    ce.add_argument("--hosts", action="append", metavar="LIST",
                    help="replace the collection's host set — registry refs")
    cx = csub.add_parser("expand", help="create one evidence item per collection "
                                        "host (skips hosts already covered)")
    cx.add_argument("ref", help="C1")
    cx.add_argument("--kind", help="kind for the created items, e.g. triage")
    csub.add_parser("list", help="list collections")
    p.set_defaults(func=cmd_collection)

    p = sub.add_parser("stack", help="cross-host findings, rarest first "
                                     "(least-frequency-of-occurrence triage)")
    p.set_defaults(func=cmd_stack)

    p = sub.add_parser("artifacts", help="host-based indicators stacked by "
                                         "artifact name, regardless of path")
    p.set_defaults(func=cmd_artifacts)

    p = sub.add_parser("clone", help="duplicate an action or finding (for similar "
                                     "entries) without re-typing everything")
    p.add_argument("ref", help="the action or finding to clone, e.g. A6 or F9")
    p.add_argument("--title", help="title for a cloned finding (default: same as "
                                   "source; ignored for actions)")
    p.set_defaults(func=cmd_clone)

    p = sub.add_parser("lead", help="triage worklists (leads) and their items")
    lsub = p.add_subparsers(dest="lead_cmd", required=False)
    la = lsub.add_parser("add", help="add a worklist item to a lead")
    la.add_argument("ref", help="the lead finding, e.g. F8")
    la.add_argument("label", help="the item, e.g. 'stun.exe'")
    la.add_argument("--finding", metavar="F#",
                    help="finding from investigating this item (marks it triaged)")
    la.add_argument("--status", choices=("open", "triaged", "dismissed"))
    ls = lsub.add_parser("set", help="update a worklist item")
    ls.add_argument("item", type=int, help="the item id (from 'vera lead')")
    ls.add_argument("--status", choices=("open", "triaged", "dismissed"))
    ls.add_argument("--finding", metavar="F#", help="finding from investigating it")
    ls.add_argument("--label")
    lr = lsub.add_parser("rm", help="remove a worklist item (soft-delete)")
    lr.add_argument("item", type=int, help="the item id")
    lsub.add_parser("list", help="list leads and their items")
    p.set_defaults(func=cmd_lead)

    p = sub.add_parser("coverage", help="per-host analysis rollup — spot hosts "
                                        "nobody has examined yet")
    p.set_defaults(func=cmd_coverage)

    p = sub.add_parser("run", help="log a command/tool you ran "
                                   "(pipe its output in to capture it)")
    p.add_argument("command", help="the exact command line")
    p.add_argument("-x", "--execute", action="store_true",
                   help="have vera execute the command and capture its output")
    p.add_argument("--hosts", action="append", metavar="LIST",
                   help="host(s) examined — registry refs (RD03 / H3), comma/space "
                        "list, must already exist ('vera host add' first)")
    p.add_argument("--host", help=argparse.SUPPRESS)  # deprecated free-text label
    p.add_argument("--tool", help="tool name (default: first word of command)")
    p.add_argument("--evidence", metavar="REF",
                   help="evidence used (E2 or label substring)")
    p.add_argument("--collection", metavar="REF",
                   help="collection/batch this action ran against (C2 or name)")
    p.add_argument("--from", dest="from_finding", metavar="F#",
                   help="finding that prompted this action")
    p.add_argument("--note")
    p.add_argument("--shot", action="append", metavar="FILE",
                   help="screenshot to attach as output (repeatable)")
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("manual", help="log a GUI/tool step with no command line "
                                      "(e.g. Registry Explorer, Timeline Explorer)")
    p.add_argument("procedure", help="what you did in the tool (the reproducible steps)")
    p.add_argument("--tool", required=True,
                   help="the tool used, e.g. 'Registry Explorer'")
    p.add_argument("--hosts", action="append", metavar="LIST",
                   help="host(s) examined — registry refs (RD03 / H3), comma/space "
                        "list, must already exist")
    p.add_argument("--host", help=argparse.SUPPRESS)  # deprecated free-text label
    p.add_argument("--evidence", metavar="REF",
                   help="evidence used (E2 or label substring)")
    p.add_argument("--collection", metavar="REF",
                   help="collection/batch this step ran against (C2 or name)")
    p.add_argument("--from", dest="from_finding", metavar="F#",
                   help="finding that prompted this step")
    p.add_argument("--note")
    p.add_argument("--shot", action="append", metavar="FILE",
                   help="screenshot to attach as output (repeatable)")
    p.set_defaults(func=cmd_manual)

    p = sub.add_parser("attach", help="attach a screenshot/file to A#, F#, or E#")
    p.add_argument("ref", help="A4, F2, or E1")
    p.add_argument("file", help="path to the image/file")
    p.add_argument("--role", choices=("output", "exhibit"), default="exhibit",
                   help="'output' = a step's captured result; 'exhibit' = proof "
                        "(default: exhibit)")
    p.add_argument("--caption")
    p.set_defaults(func=cmd_attach)

    for name in ("finding", "f"):
        p = sub.add_parser(name, help="record a finding "
                           + ("(alias of 'finding')" if name == "f" else
                              "(defaults to the most recent action)"))
        p.add_argument("title")
        p.add_argument("-t", "--type", default="note",
                       help="one of: " + ", ".join(types.FINDING_TYPES))
        p.add_argument("--on", metavar="A#",
                       help="action that produced it (default: last; 'none' to detach)")
        p.add_argument("--host", help=argparse.SUPPRESS)  # deprecated free-text
        p.add_argument("--hosts", action="append", metavar="LIST",
                       help="affected host(s) — registry refs (RD03 / H3), comma/"
                            "space list, must already exist. Omit to inherit the "
                            "action's host(s). 2+ stacks the finding across hosts.")
        p.add_argument("--time", help="when it happened in the incident "
                                      "(drives the timeline; UTC)")
        p.add_argument("--time-kind", dest="time_kind",
                       choices=[k for k in db.TIME_KINDS if k],
                       help="what the time MEANS (a shimcache time is "
                            "'modified', not 'executed')")
        p.add_argument("-d", "--detail", help="longer description")
        p.add_argument("--md5", help="MD5 of the file this finding is about")
        p.add_argument("--sha1", help="SHA-1 of the file")
        p.add_argument("--sha256", help="SHA-256 of the file")
        p.add_argument("--hash-file", dest="hash_file", metavar="PATH",
                       help="compute md5+sha1+sha256 from a local file")
        p.add_argument("--star", action="store_true", help="mark as key finding")
        p.add_argument("--shot", action="append", metavar="FILE",
                       help="screenshot to attach as exhibit (repeatable)")
        _add_attr_flags(p)
        p.set_defaults(func=cmd_finding)

    p = sub.add_parser("log", help="show the investigation tree")
    p.set_defaults(func=cmd_log)

    p = sub.add_parser("show", help="show an action, finding, evidence, or host")
    p.add_argument("ref", help="A4, F2, E1, or H3")
    p.set_defaults(func=cmd_show)

    p = sub.add_parser("edit", help="amend an action or finding")
    p.add_argument("ref", help="A4 or F2")
    p.add_argument("--note", help="notes (action) / detail (finding)")
    p.add_argument("--title")
    p.add_argument("--detail")
    p.add_argument("--host")
    p.add_argument("--time", help="performed-at (action) / event time (finding)")
    p.add_argument("--time-kind", dest="time_kind",
                   choices=[k for k in db.TIME_KINDS if k] + ["none"],
                   help="what a finding's event time means ('none' to clear)")
    p.add_argument("--command")
    p.add_argument("--tool")
    p.add_argument("-t", "--type", help="change finding type")
    p.add_argument("--parent", metavar="F#",
                   help="re-link action under a finding ('none' to unlink)")
    p.add_argument("--on", metavar="A#", help=argparse.SUPPRESS)
    p.add_argument("--star", action="store_true")
    p.add_argument("--unstar", action="store_true")
    _add_attr_flags(p)
    p.set_defaults(func=cmd_edit)

    p = sub.add_parser("export", help="export the case")
    p.add_argument("format", choices=("md", "json", "csv"))
    p.add_argument("--out", metavar="DIR", default=".",
                   help="output directory (default: current)")
    p.set_defaults(func=cmd_export)

    p = sub.add_parser("serve", help="open the web viewer")
    p.add_argument("--port", type=int, default=8845)
    p.add_argument("--no-browser", action="store_true")
    p.add_argument("--dir", metavar="DIR",
                   help="folder of .vera cases for the New Investigation screen "
                        "(default: active case's folder, else current dir)")
    p.add_argument("--new", action="store_true",
                   help="open the New Investigation screen even if a case is active")
    p.set_defaults(func=cmd_serve)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except CaseError as exc:
        return die(str(exc))
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
