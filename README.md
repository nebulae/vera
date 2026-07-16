# vera — Verified Evidence Record and Annotations

Track a DFIR investigation as a **replayable graph** instead of a flat
spreadsheet: every command or tool you run is logged in order, findings hang
off the action that produced them, and follow-up actions hang off the finding
that prompted them. Anyone with the same evidence can open your case and
recreate the entire investigation, step by step.

Built to replace the classic FOR508 IR tracking spreadsheet — and it still
exports spreadsheet-compatible CSVs of all six classic sheets.

## Install

Zero runtime dependencies (Python ≥ 3.10 stdlib only):

```sh
pip install -e .        # or: pipx install .
```

Or run straight from the repo without installing: `python3 -m vera ...`

## Quickstart

```sh
vera init lab1.vera --name "FOR508 Lab 1" --investigator you
vera evidence add "WS01 memory dump" --kind memory --sha256 <hash>

# log what you ran (pipe output through vera to capture it)
vol.py -f ws01.mem windows.pstree | vera run "vol.py -f ws01.mem windows.pstree" --host WS01 --evidence E1

# record what it showed you (attaches to the last action by default)
vera f "rundll32 spawned by wmiprvse" -t malware --host WS01 \
       --time "2026-07-01 14:22" --filename rundll32.exe --star

# drill down: log the follow-up prompted by that finding
vera run "vol.py -f ws01.mem windows.netscan" --host WS01 --from F1
vera f "beacon to 203.0.113.7:443" -t netindicator --address 203.0.113.7

# a GUI/tool step has no command line — log the procedure + a screenshot
vera manual "Opened NTUSER.DAT → CurrentVersion\Run" --tool "Registry Explorer" \
       --host WS01 --from F1 --shot runkey.png
vera attach F1 proof.png --role exhibit --caption "the smoking gun"

vera log            # the whole investigation tree, in order
vera serve          # browse/annotate in your browser (paste screenshots with Ctrl+V)
vera export md      # replayable report; also: csv (FOR508 sheets), json
```

### At scale — many hosts, one finding

For enterprise triage (e.g. amcache/shimcache across dozens of hosts), register
the hosts once, group evidence into a collection, and stack a single finding
across every host it touches:

```sh
vera host add --from hosts.txt --type workstation      # register 40 hosts at once
vera host add DC01 --type "domain controller" --ip 10.0.0.10
vera collection add "Lab2 amcache+shimcache" --tool AmcacheParser --hosts "WS01,WS02,…"
vera collection expand C1 --kind triage   # one evidence item per collection host

vera manual "Parsed all 40 exports in Timeline Explorer" --tool AmcacheParser --collection C1
# one finding, stacked across the hosts that show the indicator
vera f "svchost.exe anomalous path C:\temp" -t malware --hosts "WS03,WS07,WS11,WS22"

vera stack          # cross-host findings, rarest first (least-frequency triage)
vera coverage       # per-host rollup — which hosts has nobody examined yet?
vera host edit WS03 --status compromised  # disposition: clean/suspicious/compromised
vera host show WS03 # everything affecting one host
```

Evidence and actions link to hosts the same way — `--hosts` on `vera evidence
add`, `vera run`, and `vera manual`. Host references are resolved **against the
registry** (`vera host add` first); an unknown name is an error, not a new host.
The registry is the hub: everything ties back to it by reference, not by
retyping a name.

## Concepts

- **Evidence** (`E#`) — the images/dumps/collections you work from, with
  hashes and the **source host(s)** they came from. The ground truth that makes
  replay meaningful.
- **Action / step** (`A#`) — one investigative step, numbered in execution
  order. Two kinds:
  - a **command** step: exact command line, captured output (hashed, capped at
    256 KB), exit code;
  - a **manual** step (`vera manual`): a GUI/tool action with no command line —
    Timeline Explorer, Registry Explorer, an EDR console — recorded as the tool
    name plus a reproducible procedure, with a screenshot standing in for the
    output.
- **Screenshots / attachments** — pasted (Ctrl+V in the web UI), dropped,
  uploaded, or attached from the CLI (`vera attach`, `--shot`). They hang off
  any action, finding, or evidence item; each is SHA-256 hashed and stored
  **inside the .vera file**, so the case stays a single portable artifact. A
  screenshot's role is either `output` (a step's result) or `exhibit` (proof on
  a finding or evidence item).
- **Finding** (`F#`) — something an action showed you. Typed (`malware`,
  `account`, `host`, `netindicator`, `hostindicator`, `event`, `note`) with
  type-specific fields, an optional **event time** (when it happened in the
  incident — drives the Timeline), optional **file hashes** (MD5 / SHA-1 /
  SHA-256, validated and lowercased; `vera f … --hash-file evil.exe` computes
  all three), and a star for key findings.
- **Host** (`H#`) — a system in the investigation, held in a **registry** with
  aliases (so `WS03`, `ws03`, and `WS03.corp` are one host). The registry is the
  hub: evidence links to its **source host(s)** (inherited from its collection),
  a step's hosts **derive from the evidence it examines** (hosts belong to
  evidence and collections, not individual steps), and a finding links to the
  **host(s) it affects** (inherited from its step, adjustable) — all by
  reference to the registry, never by retyping. A finding on 2+ hosts becomes a
  **cross-host finding** with a *stack count* — the same indicator on 30 hosts
  is one finding, not 30; `vera stack` lists them rarest-first for
  least-frequency-of-occurrence triage. Host links are optional (host-agnostic
  work needs none). Each host also carries a **disposition** (`unknown` /
  `clean` / `suspicious` / `compromised`) — set it as triage progresses and the
  compromised-hosts view derives itself instead of being maintained by hand.
- **Collection** (`C#`) — a batch/sweep (e.g. a 40-host artifact export) with
  its provenance (tool, operator, scope) and the **hosts it covers**. Evidence
  in a collection sources its hosts from the collection — that's where they're
  edited, and edits **follow through** to evidence (and steps) still tracking
  the collection's set, while deliberately narrowed items (e.g. per-host
  expansion) keep their own. Standalone evidence has its own host picker.
  `vera collection expand C1` creates one evidence item per covered host in a
  single step, skipping hosts that already have evidence in it.
- **Coverage** — `vera coverage` (and the web Coverage tab) rolls up, per host,
  the evidence, steps, and findings that reference it, plus which tools were
  used and when it was last examined. Hosts with no analysis logged are called
  out — the answer to "did we look at everything?".
- **Drill-down** — `vera run ... --from F3` links a new action to the finding
  that prompted it. That chain *is* the investigation.

## Capturing output

Three ways, most to least faithful:

1. `vera run -x "cmd"` — vera executes the command and records stdout/stderr
   and the exit code.
2. `cmd | tee /dev/tty | vera run "cmd"` — you watch the output live, vera
   captures it from the pipe.
3. `vera run "cmd"` — records the command only; paste highlights into
   findings.

Captured output is SHA-256 hashed so a replay can be verified against the
original run.

## Web viewer

`vera serve` opens a local-only viewer (127.0.0.1) with:

- **Investigation** — the collapsible action→finding→action tree; add
  actions/findings and edit anything inline
- **Timeline** — every finding with an event time, in incident order
- **Stack** — cross-host findings, rarest first (least-frequency triage)
- **Hosts** — an **inline-editable** registry grid: click any cell, tab between
  fields, changes autosave as you go. The blank row at the bottom adds a host
  (paste a newline/comma list to add many at once); ✕ removes one. Per-host
  finding counts click through to what affects each host. The Status column
  color-codes each row by disposition.
- **Coverage** — the hosts × analysis matrix: evidence/step/finding counts,
  per-tool step counts, and last-examined time for every host, with unexamined
  hosts highlighted.
- **Category tabs** — Compromised Hosts / Accounts, Malware & Tools,
  Network / Host Indicators, generated automatically from finding types
- **Evidence** — items and hashes, plus collections/batches
- **Export .md** button for the replay report

Findings carry an **affected-hosts** tag control; a `🖥 N hosts` chip on any
cross-host finding jumps to the registry.

## Nothing is ever purged

"Deleting" in vera is a soft-delete: the row gets a `deleted_at` timestamp and
is hidden from views, exports, and counts, but the data is never removed from
the case file. This holds for hosts and screenshots/attachments today, and any
future delete follows the same rule — a case file remains a complete record of
everything that was ever entered.

## Exports

- `vera export md` — full replayable report: hosts + collections, evidence +
  hashes, every action in order with commands and captured output, nested
  findings, timeline, a cross-host-indicator appendix (rarest first), and the
  classic category appendices.
- `vera export csv` — one CSV per classic IR-spreadsheet sheet (same column
  headers), plus `Hosts.csv`, `CompromisedHosts.csv` (derived from host
  disposition), and `CrossHostFindings.csv`.
- `vera export json` — complete structured dump (hosts, collections, findings
  with their affected-host sets, and attachment manifest).

## Active case

Commands use, in order of precedence: `--case PATH`, `$VERA_CASE`, or the
case selected with `vera use PATH` (stored in `~/.config/vera/active`).
A case is a single SQLite file — copy it, zip it, hand it to a teammate.

## Development

```sh
pip install -e ".[dev]"
pytest
```
