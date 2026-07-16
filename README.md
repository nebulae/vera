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

vera log            # the whole investigation tree, in order
vera serve          # browse/annotate in your browser
vera export md      # replayable report; also: csv (FOR508 sheets), json
```

## Concepts

- **Evidence** (`E#`) — the images/dumps/collections you work from, with
  hashes. The ground truth that makes replay meaningful.
- **Action** (`A#`) — one command or tool run: exact command line, host,
  evidence used, captured output (hashed, capped at 256 KB), and why you ran
  it. Numbered in execution order.
- **Finding** (`F#`) — something an action showed you. Typed (`malware`,
  `account`, `host`, `netindicator`, `hostindicator`, `event`, `note`) with
  type-specific fields, an optional **event time** (when it happened in the
  incident — drives the Timeline), and a star for key findings.
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
- **Category tabs** — Compromised Hosts / Accounts, Malware & Tools,
  Network / Host Indicators, generated automatically from finding types
- **Evidence** — items and hashes
- **Export .md** button for the replay report

## Exports

- `vera export md` — full replayable report: evidence + hashes, every action
  in order with commands and captured output, nested findings, timeline, and
  category appendices.
- `vera export csv` — one CSV per classic IR-spreadsheet sheet, same column
  headers.
- `vera export json` — complete structured dump.

## Active case

Commands use, in order of precedence: `--case PATH`, `$VERA_CASE`, or the
case selected with `vera use PATH` (stored in `~/.config/vera/active`).
A case is a single SQLite file — copy it, zip it, hand it to a teammate.

## Development

```sh
pip install -e ".[dev]"
pytest
```
