# vera — Verified Evidence Record and Annotations

Track a DFIR investigation as a **replayable graph** instead of a flat
spreadsheet: every command or tool you run is logged in order, findings hang
off the action that produced them, and follow-up actions hang off the finding
that prompted them. Anyone with the same evidence can open your case and
recreate the entire investigation, step by step.

Built to replace the classic FOR508 IR tracking spreadsheet — and it still
exports spreadsheet-compatible CSVs of all six classic sheets.

Works solo from the CLI, or as a shared multi-user server with accounts, roles,
per-case membership, and a chain-of-custody export bundle (see *Collaboration &
access control*).

## Install

Zero runtime dependencies (Python ≥ 3.10 stdlib only):

```sh
pip install -e .        # or: pipx install .
```

Or run straight from the repo without installing: `python3 -m vera ...`

For **cryptographically signed provenance** (Ed25519 — see *Collaboration*),
install the optional extra: `pip install "vera[provenance]"`. Without it, export
bundles are still hash-verified, just unsigned.

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
  `account`, `host`, `netindicator`, `hostindicator`, `lateral`, `filesystem`,
  `event`, `lead`, `note`) with
  type-specific fields. Host-based indicators carry a stackable **artifact
  name** (e.g. `CRYPTBASE.dll`) *and* its **full path** as separate fields — the
  name is what you stack on, the path pins the location; paste a path and the
  name auto-fills from its basename. Findings also carry an optional **event
  time** (when it happened in the
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
- **Account** (a registry, like hosts) — user/service accounts seen in the
  case, held in their own registry with domain, SID, type, and a disposition.
  **Compromised Account** and **Lateral Movement** findings auto-register the
  account they name and link to it (merge-only, never overwriting), and any
  finding can be tied to accounts explicitly via an associated-accounts picker
  (`--accounts` on `vera f`/`vera edit`). The web **Accounts** tab is an
  inline-editable grid like Hosts; each account's panel lists every finding
  naming it. Add suspects up front, or let findings populate it.
- **Lateral Movement** (a finding type) — movement is **directional**, so it
  carries a **source host → destination host**, the **technique** (WMI, PsExec,
  RDP, SMB, …), and the **account used**; both endpoints also join the finding's
  affected-host set. `vera f "…" -t lateral --source-host RD01 --dest-host WS01
  --technique "explicit creds" --account svc-backup`.
- **Follow-ups** — any finding can carry a **follow-up checklist** (same
  machinery as leads): things to chase before the finding is done — "pull
  prefetch on WKSTN01", "check 4624s on the target". Each item is workable in
  place (an **Investigate →** button logs a drill-down step + finding and links
  it back), and the Leads tab shows a case-wide **Open follow-ups** queue.
  `vera followup add F70 "prefetch on WKSTN01"`; `vera followup` lists what's open.
- **Attribution** — every action and finding records **who logged it**
  (`created_by`), shown as a `👤 user` byline on its card and in the Markdown/
  JSON exports; the per-case audit log records **who** made each later edit.
  Attribution is stored as the username string inside the case, so it survives
  export and displays with no user-database lookup. (CLI edits record no user —
  the CLI is unauthenticated; see *Collaboration*.)
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
- **Lead** (a finding type) — a **triage worklist**, not an indicator: e.g. the
  rows an LFO autoruns sweep surfaced. A lead carries a checklist of **items**
  you work through, each markable `open` / `triaged` / `dismissed` and linkable
  to the finding that resolved it (`vera lead`, or the web **Leads** tab, shows
  "N of M triaged"). Leads are deliberately kept **out of the Artifacts and
  cross-host Stack views** — only the concrete indicators you drill down to
  belong there.
- **Indicators vs. Observations** — finding types are grouped into two kinds.
  **Indicators** are IOCs you correlate (Host/Network Indicators, Malware & Tools,
  Compromised Hosts/Accounts); **Observations** are context/scope you record but
  don't correlate (**File / Directory**, notes, timeline events). Only indicators
  feed the Artifacts stack. The two groups are labelled in the "Findings" menu.
- **File / Directory** (a finding type) — a file or folder an artifact touched,
  recorded for **scope**, not correlation (e.g. the contents of a malware staging
  directory). It's deliberately kept **out of the Artifacts stack**; flip a
  finding between this and **Host Indicator** just by changing its Type (they
  share fields, so it's lossless).
- **Artifacts** — `vera artifacts` (and the web **Artifacts** tab) stacks
  host-based indicators by artifact **name regardless of path**: the same planted
  DLL name seen in several app directories across hosts collapses into one entry
  that still lists every distinct full path and host, most-spread first. The
  **Host Indicators** tab defaults to this grouping too (toggle to a flat table).
- **Evidence cascade** — the evidence flows down a drill-down chain so you never
  re-pick it: a finding inherits the **evidence its action examined**, and a
  follow-up action inherits **its finding's evidence** in turn (explicit choice
  always wins). So `E4 → F8 → A7 → F9 …` all point back to the same evidence.
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

`vera serve` opens the viewer (bound to 127.0.0.1 by default; sign-in required
once accounts exist — see *Collaboration & access control*) with:

- **Investigation** — the action→finding→action tree; add actions/findings and
  edit anything. Add/edit/clone open in a **modal dialog** (Esc or click-away to
  close) rather than shoving forms into the tree. Every action and finding
  **collapses in place** (click its header, or Collapse all / Expand all) so a
  large case stays scannable. **Clone** on any action or finding opens a new one
  pre-filled from it — a step keeps its tool/command/evidence (output is a fresh
  capture); a finding keeps its type, attrs, hashes, hosts, and detail — so you
  can enter a batch of similar entries without re-typing. (`vera clone A6` /
  `vera clone F9` from the CLI too.) Affected hosts show the same everywhere — a
  chip with the first few names, "(… and N more)", full list on hover; the ★ on
  any finding/lead toggles the key-finding flag (also a checkbox in the form).
- **Timeline** — every finding with an event time, in incident order, with a
  **date-range filter** (`From` / `To`, date or timestamp) that lives in the URL
  so a filtered view is shareable.
- **Stack** — cross-host findings, rarest first (least-frequency triage)
- **Hosts** — an **inline-editable** registry grid: click any cell, tab between
  fields, changes autosave as you go. The blank row at the bottom adds a host
  (paste a newline/comma list to add many at once); ✕ removes one. Per-host
  finding counts click through to what affects each host. The Status column
  color-codes each row by disposition.
- **Accounts** — the account registry as an inline-editable grid like Hosts;
  each account's finding count opens a panel of every finding naming it.
- **Coverage** — the hosts × analysis matrix: evidence/step/finding counts,
  per-tool step counts, and last-examined time for every host, with unexamined
  hosts highlighted.
- **Artifacts** — host-based indicators stacked by artifact name regardless of
  path; the Host Indicators tab groups by name by default (toggle to flat)
- **Leads** — triage worklists (e.g. an LFO sweep): add/check off items, link
  each to the finding that resolved it, track "N of M triaged"
- **Category tabs** — Compromised Hosts / Accounts, Malware & Tools,
  Network / Host Indicators, Lateral Movement, generated automatically from
  finding types
- **Evidence** — items and hashes, plus collections/batches
- header actions — **Export .md** (any signed-in user), **Bundle** (download a
  chain-of-custody bundle; lead/admin), **Members** (the case roster; lead/admin
  edit it), and **Admin** (user management + access log; admins only)

Findings carry an **affected-hosts** tag control; a `🖥 N hosts` chip on any
cross-host finding jumps to the registry.

**Every tab is a real URL** (`/investigation`, `/timeline`, `/evidence`,
`/accounts`, `/findings/<type>`, …), served so a refresh or a shared link lands
on the right view. A ref jump is a deep link too: `/investigation?F=13` or
`?A=24` opens the tree expanded to that node — click a finding's ref anywhere
(Timeline, a category sheet) and copy the URL straight to a teammate.

## Collaboration & access control

`vera serve` can be a shared, multi-user server. Accounts, roles, and case
membership gate the **web** UI; the **CLI** is unchanged and unauthenticated (it
edits case files directly — see the threat-model note below).

- **First run** — with no users yet, the server shows a one-time screen to
  **create the initial admin**. From then on, signing in is required.
- **Roles** (global, per user):
  - **admin** — everything an investigator can do, plus **user management** and
    full access to every case (an implicit member everywhere);
  - **investigator** — logs actions/findings, but only on cases they're a
    **member** of;
  - **viewer** — read-only across all cases (sees investigations and reports,
    changes nothing).
- **Case membership & lead investigator** — each case has exactly one **lead**
  (the creator becomes lead) plus any number of member investigators. The lead
  (or an admin) manages the roster from the **Members** panel. A global
  investigator can only *modify* a case once they've been added to it.
- **Passwords** — salted and hashed with `scrypt` (stdlib); minimum 12 chars
  with 3 of 4 character classes, or 16+ of anything (passphrase-friendly), with
  a common-password blocklist. Sign-in has failed-attempt lockout. Users change
  their own password from the header; an admin can issue a **one-time reset
  code** for a forgotten one.
- **Admin pages** (admins only) — a **Users** view (create/disable, change
  roles, issue reset codes; the last active admin can't be locked out) and an
  **Access log** view.
- **Two audit trails** — each case carries its own append-only **edit log**
  *inside* the `.vera` (who changed what, part of chain of custody, ships with
  the case). Separately, a **global access log** (`vera-audit.db`) records
  server-wide security events — sign-ins, user administration, and every case
  export — and is **never** part of a case export.

### Provenance & moving cases between servers

Every record stores **which system** wrote it (`created_by_origin`), not just
which user — so a case can move between servers without its attribution
blurring, even if usernames collide.

- **Server identity** — on first run a server gets an identity. With the
  `provenance` extra that's an **Ed25519 keypair**; its **`server_id` is the
  public key's fingerprint**, so the id is unforgeable (you can't claim it
  without the private key, which never leaves the server — a `0600`
  `vera-server-key.pem`). Give the server a human **label** at bootstrap.
- **Signed bundles** — `vera export bundle` (web Download / lead-admin) signs
  the manifest; anyone can `vera verify` it **offline** to prove both integrity
  *and origin*, with no ability to forge. Without the extra, bundles are
  hash-verified but unsigned (the receipt says so).
- **Origin badge** — a record made on a *different* server than the case now
  lives on is badged `👤 user · from <server>` in the UI, with the originating
  `server_id` on hover. Same username, different origin = unmistakably distinct.
- **Import & adopt** — `vera import <bundle>.zip` verifies and extracts the
  `.vera`. An imported case's home server isn't yours, so its **membership is
  inert** (no investigator inherits access by a name match) until an **admin
  adopts** it (an *Adopt to this server* banner, or `POST /api/adopt`): that
  stamps the case's home to your server and resets the roster (the adopter
  becomes lead). **Attribution and history are never rewritten** — only the
  access-granting roster resets.

**Threat model.** This is *web-tier* access control: it governs who can do what
through the browser. Anyone with **filesystem access to a `.vera` file, or the
CLI on the server box, has full access** — that's inherent to the portable
single-file design, and the CLI is intentionally auth-free. Team deployments
should keep case files on the server, have collaborators come in via the web UI,
and terminate **TLS** at a reverse proxy (passwords over plaintext LAN HTTP
would undermine the point). Sessions are `HttpOnly` cookies with a CSRF header
check on writes.

## Nothing is ever purged

"Deleting" in vera is a soft-delete: the row gets a `deleted_at` timestamp and
is hidden from views, exports, and counts, but the data is never removed from
the case file. This holds for hosts and screenshots/attachments today, and any
future delete follows the same rule — a case file remains a complete record of
everything that was ever entered.

## Exports

- `vera export md` — full replayable report: hosts + collections, evidence +
  hashes, every action in order with commands and captured output, nested
  findings, timeline, a cross-host-indicator appendix (rarest first), an
  artifacts-by-name appendix (host indicators stacked by name across paths), and
  the classic category appendices.
- `vera export csv` — one CSV per classic IR-spreadsheet sheet (same column
  headers), plus `Hosts.csv`, `CompromisedHosts.csv` (derived from host
  disposition), and `CrossHostFindings.csv`.
- `vera export json` — complete structured dump (hosts, collections, findings
  with their affected-host sets, and attachment manifest).
- `vera export bundle` — a **chain-of-custody bundle** (`<case>-<date>.bundle.zip`):
  the `.vera` plus the rendered `md`/`csv`/`json` reports, zipped, SHA-256
  hashed, and zipped again with a `MANIFEST.json` + human-readable `RECEIPT.txt`
  so the package is tamper-evident. `--include-evidence DIR` also packs raw
  evidence files whose recorded hash matches (verifying each; off by default —
  otherwise evidence is referenced by hash). In the web UI it's the **Bundle**
  button (lead/admin). Every export is logged to the case's export ledger.
- `vera verify <bundle>.zip` — recompute every hash against the manifest;
  reports intact (green) or tampered (red, naming the offending file). With the
  `provenance` extra it also checks the **signature** and reports which server
  sealed it. Needs no case, no accounts, no network — verification is fully
  offline.
- `vera import <bundle>.zip` — verify a bundle and extract its `.vera` (refuses
  a tampered bundle). See *moving cases between servers* below.

Markdown and JSON exports include **who logged** each action/finding.

## Active case

Commands use, in order of precedence: `--case PATH`, `$VERA_CASE`, or the
case selected with `vera use PATH` (stored in `~/.config/vera/active`).

## Files & where they live

Everything is plain SQLite on disk — no database server to run.

- **`<name>.vera`** — the case itself: one self-contained SQLite file holding
  the whole investigation (actions, findings, evidence, hosts, accounts,
  screenshots, audit log, and — once you have collaborators — the case's member
  list). **This is the file you share:** copy it, zip it, hand it to a
  teammate; its SHA-256 is its chain of custody. It's created wherever you point
  `vera init <path>.vera`. In the browser, `vera serve` lists and creates cases
  in its **case directory** — the `--dir` you pass, else the active case's
  folder, else the current working directory.
- **`vera-users.db`** — the global accounts/sessions database (users, roles,
  salted+hashed passwords, login sessions, reset tokens). Created in the case
  directory the first time you `vera serve` with users. It is **not** part of
  any case and spans all of them — **do not share it or commit it**; it holds
  password hashes and is specific to one server install. (git-ignored by
  default.)
- **`vera-audit.db`** — the global access/security log (sign-ins, user
  administration, and every case export), beside `vera-users.db` in the case
  directory. Also **global, server-private, and never part of a case export** —
  don't share or commit it. View it under Admin → Access log. (git-ignored.)
  This is distinct from each case's own `audit_log` (the data-edit history that
  lives *inside* the `.vera` and ships with it).
- **`vera-server-key.pem`** — the server's Ed25519 **private key** (only with
  the `provenance` extra), beside `vera-users.db`, `0600`. It signs export
  bundles and *is* this server's provenance identity. **Never share or commit
  it** — losing it means you can no longer sign as this server; leaking it lets
  someone forge your seal. (git-ignored.)
- **`<name>.vera-wal` / `<name>.vera-shm`** — SQLite write-ahead-log sidecars,
  created while a case is open so multiple people can read during a write.
  Transient; they fold back into the `.vera` file on a clean close. No need to
  copy them when sharing.
- **`<name>.vera.pre-v<N>`** — an automatic backup vera takes *before* a schema
  migration upgrades an older case, so a bad upgrade can never eat the only
  copy. Safe to archive or delete once you've confirmed the upgraded case opens.

So to hand off an investigation, share only the `.vera` file (or a
`vera export bundle` of it). To move a whole **team server**, copy the case
directory *including* `vera-users.db` and `vera-audit.db` (keep them private —
they're your credential store and security log).

## Development

```sh
pip install -e ".[dev]"
pytest
```
