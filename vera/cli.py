"""vera command line: fast investigation logging while you work."""

from __future__ import annotations

import argparse
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
            eid = case.add_evidence(args.label, kind=args.kind or "",
                                    source=args.source or "",
                                    sha256=args.sha256 or "",
                                    notes=args.note or "")
            print(f"E{eid} added — {args.label}")
        else:
            items = case.evidence()
            if not items:
                print("no evidence recorded")
            for e in items:
                line = f"E{e['id']}  {e['label']}"
                if e["kind"]:
                    line += f"  [{e['kind']}]"
                if e["sha256"]:
                    line += f"  sha256:{e['sha256'][:16]}…"
                print(line)
                if e["source"]:
                    print(f"     source: {e['source']}")
    return 0


def _read_piped_stdin() -> str:
    try:
        if sys.stdin is not None and not sys.stdin.isatty():
            return sys.stdin.read()
    except (OSError, ValueError):
        pass
    return ""


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
        a = case.add_action(args.command, host=args.host or "",
                            tool=args.tool or "", evidence_id=evidence_id,
                            output=output, exit_code=exit_code,
                            notes=args.note or "", parent_finding_id=parent)
        where = f" (follow-up to {fid(parent)})" if parent else ""
        captured = f", {len(output)} chars captured" if output else ""
        print(f"{aid(a)} recorded{where}{captured}")
        if exit_code not in (None, 0):
            print(f"   exit code {exit_code}")
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
        f = case.add_finding(args.title, ftype=args.type, action_id=action_id,
                             host=args.host or "", detail=args.detail or "",
                             event_time=args.time or "",
                             attrs=_collect_attrs(args), starred=args.star)
        label = types.FINDING_TYPES[args.type].label
        under = f" under {aid(action_id)}" if action_id else " (unattached)"
        print(f"{fid(f)} [{label}] added{under}")
    return 0


def cmd_show(args) -> int:
    kind, ref_id = db.resolve_ref(args.ref)
    with open_case(args) as case:
        if kind == "A":
            a = case.get_action(ref_id)
            print(f"{aid(a['id'])}  {a['performed_at']}")
            print(f"  command: {a['command']}")
            for key, label in (("tool", "tool"), ("host", "host"),
                               ("notes", "notes")):
                if a[key]:
                    print(f"  {label}: {a[key]}")
            if a["evidence_id"]:
                print(f"  evidence: E{a['evidence_id']}")
            if a["parent_finding_id"]:
                print(f"  follow-up to: F{a['parent_finding_id']}")
            if a["exit_code"] is not None:
                print(f"  exit code: {a['exit_code']}")
            if a["output"]:
                trunc = " (truncated)" if a["output_truncated"] else ""
                print(f"  output{trunc}, sha256 {a['output_sha256'][:16]}…:")
                for line in a["output"].splitlines():
                    print(f"    {line}")
        elif kind == "F":
            f = case.get_finding(ref_id)
            ft = types.FINDING_TYPES.get(f["ftype"])
            star = " ★" if f["starred"] else ""
            print(f"{fid(f['id'])} [{ft.label if ft else f['ftype']}]{star}  {f['title']}")
            for key, label in (("host", "host"), ("event_time", "event time"),
                               ("detail", "detail")):
                if f[key]:
                    print(f"  {label}: {f[key]}")
            for k, v in f["attrs"].items():
                if v:
                    print(f"  {k}: {v}")
            if f["action_id"]:
                print(f"  found via: A{f['action_id']}")
        else:
            raise CaseError("show expects A<n> or F<n>")
    return 0


def _tree_lines(case: Case) -> list[str]:
    lines: list[str] = []

    def emit_action(a: dict, depth: int) -> None:
        pad = "  " * depth
        host = f" @{a['host']}" if a["host"] else ""
        lines.append(f"{pad}{aid(a['id'])}{host}  $ {a['command']}")
        if a["notes"]:
            lines.append(f"{pad}   {c('2', a['notes'])}")
        for f in a["findings"]:
            emit_finding(f, depth + 1)

    def emit_finding(f: dict, depth: int) -> None:
        pad = "  " * depth
        ft = types.FINDING_TYPES.get(f["ftype"])
        tag = ft.label if ft else f["ftype"]
        star = " ★" if f["starred"] else ""
        when = f" ({f['event_time']})" if f["event_time"] else ""
        lines.append(f"{pad}{fid(f['id'])} [{tag}]{star} {f['title']}{when}")
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
    path = active_case_path(getattr(args, "case", None))
    Case(path).close()  # fail fast on a bad path before binding the port
    return server.serve(path, port=args.port, open_browser=not args.no_browser)


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
    pa.add_argument("--note")
    esub.add_parser("list", help="list evidence")
    p.set_defaults(func=cmd_evidence)

    p = sub.add_parser("run", help="log a command/tool you ran "
                                   "(pipe its output in to capture it)")
    p.add_argument("command", help="the exact command line")
    p.add_argument("-x", "--execute", action="store_true",
                   help="have vera execute the command and capture its output")
    p.add_argument("--host", help="host/system the command targets")
    p.add_argument("--tool", help="tool name (default: first word of command)")
    p.add_argument("--evidence", metavar="REF",
                   help="evidence used (E2 or label substring)")
    p.add_argument("--from", dest="from_finding", metavar="F#",
                   help="finding that prompted this action")
    p.add_argument("--note")
    p.set_defaults(func=cmd_run)

    for name in ("finding", "f"):
        p = sub.add_parser(name, help="record a finding "
                           + ("(alias of 'finding')" if name == "f" else
                              "(defaults to the most recent action)"))
        p.add_argument("title")
        p.add_argument("-t", "--type", default="note",
                       help="one of: " + ", ".join(types.FINDING_TYPES))
        p.add_argument("--on", metavar="A#",
                       help="action that produced it (default: last; 'none' to detach)")
        p.add_argument("--host")
        p.add_argument("--time", help="when it happened in the incident "
                                      "(drives the timeline)")
        p.add_argument("-d", "--detail", help="longer description")
        p.add_argument("--star", action="store_true", help="mark as key finding")
        _add_attr_flags(p)
        p.set_defaults(func=cmd_finding)

    p = sub.add_parser("log", help="show the investigation tree")
    p.set_defaults(func=cmd_log)

    p = sub.add_parser("show", help="show one action or finding in full")
    p.add_argument("ref", help="A4 or F2")
    p.set_defaults(func=cmd_show)

    p = sub.add_parser("edit", help="amend an action or finding")
    p.add_argument("ref", help="A4 or F2")
    p.add_argument("--note", help="notes (action) / detail (finding)")
    p.add_argument("--title")
    p.add_argument("--detail")
    p.add_argument("--host")
    p.add_argument("--time", help="performed-at (action) / event time (finding)")
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
