"""Finding-type registry.

Each finding type declares its extra attribute fields once; the CLI flags,
web forms, category views, and CSV export are all generated from this table.
CSV headers match the classic FOR508 IR spreadsheet so exports stay
column-compatible with it.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Field:
    key: str          # attrs dict key / CLI flag (--key with _ -> -)
    label: str        # human label for forms and terminal output
    hint: str = ""    # placeholder / help text


@dataclass(frozen=True)
class FindingType:
    key: str
    label: str            # singular, e.g. "Compromised Account"
    view: str             # tab/category name, "" = no dedicated category view
    group: str = ""       # "indicator" (an IOC) | "observation" (context) | ""
    fields: tuple[Field, ...] = ()
    csv_name: str = ""    # export file stem, "" = no per-type CSV
    csv_headers: tuple[str, ...] = ()
    # csv_row maps a finding row-dict -> list matching csv_headers
    csv_row: object = None


def _attrs(f: dict) -> dict:
    return f.get("attrs") or {}


def _hash(f: dict, algo: str) -> str:
    return (f.get("hashes") or {}).get(algo, "")


FINDING_TYPES: dict[str, FindingType] = {}


def _register(ft: FindingType) -> None:
    FINDING_TYPES[ft.key] = ft


_register(FindingType(
    key="event",
    label="Timeline Event",
    view="",  # events surface in the Timeline view, shared by all types
    group="observation",
    fields=(Field("activity", "Activity", "what happened"),),
))

_register(FindingType(
    key="host",
    label="Compromised Host",
    view="Compromised Hosts",
    group="indicator",
    fields=(
        Field("ip", "IP Address"),
        Field("system_type", "System Type", "workstation / DC / server ..."),
    ),
    csv_name="CompromisedHosts",
    csv_headers=("Earliest Compromise", "Host Name", "IP Address",
                 "System Type", "Evidence"),
    csv_row=lambda f: [f.get("event_time", ""), f.get("host", ""),
                       _attrs(f).get("ip", ""), _attrs(f).get("system_type", ""),
                       f.get("detail", "") or f.get("title", "")],
))

_register(FindingType(
    key="account",
    label="Compromised Account",
    view="Compromised Accounts",
    group="indicator",
    fields=(
        Field("account", "Account", "defaults to the finding title"),
        Field("account_type", "Account Type", "Admin, Domain Admin, User"),
        Field("sid", "SID"),
    ),
    csv_name="CompromisedAccounts",
    csv_headers=("Date / Time Seen", "Account", "Host System",
                 "Account Type (Admin, Domain Admin, User)", "SID"),
    csv_row=lambda f: [f.get("event_time", ""),
                       _attrs(f).get("account") or f.get("title", ""),
                       f.get("host", ""), _attrs(f).get("account_type", ""),
                       _attrs(f).get("sid", "")],
))

_register(FindingType(
    key="malware",
    label="Malware / Tool",
    view="Malware & Tools",
    group="indicator",
    fields=(
        Field("filename", "File Name", "defaults to the finding title"),
        Field("path", "Path"),
        Field("size", "File Size"),
        Field("created", "Creation Time"),
        Field("modified", "Modification Time"),
    ),
    csv_name="MalwareAndTools",
    csv_headers=("File Name", "Path", "File Size", "Creation Time",
                 "Modification Time", "Host", "Description",
                 "MD5", "SHA-1", "SHA-256"),
    csv_row=lambda f: [_attrs(f).get("filename") or f.get("title", ""),
                       _attrs(f).get("path", ""), _attrs(f).get("size", ""),
                       _attrs(f).get("created", ""), _attrs(f).get("modified", ""),
                       f.get("host", ""), f.get("detail", ""),
                       _hash(f, "md5"), _hash(f, "sha1"), _hash(f, "sha256")],
))

_register(FindingType(
    key="netindicator",
    label="Network Indicator",
    view="Network Indicators",
    group="indicator",
    fields=(
        Field("address", "DNS / IP Address", "defaults to the finding title"),
        Field("source", "Source", "where the indicator was observed"),
    ),
    csv_name="NetworkIndicators",
    csv_headers=("Timestamp (if applicable)", "DNS/IP Address", "Source",
                 "Description"),
    csv_row=lambda f: [f.get("event_time", ""),
                       _attrs(f).get("address") or f.get("title", ""),
                       _attrs(f).get("source", ""), f.get("detail", "")],
))

# Movement is DIRECTIONAL — the affected-hosts set can't say which way it
# went, so source/destination live here as attrs while both hosts are also
# linked (m2m) for stacking. Entry layers auto-link registry hosts matching
# the source/dest names.
_register(FindingType(
    key="lateral",
    label="Lateral Movement",
    view="Lateral Movement",
    group="indicator",
    fields=(
        Field("source_host", "Source Host", "where the movement came FROM"),
        Field("dest_host", "Destination Host", "where it went TO"),
        Field("technique", "Technique",
              "WMI / PsExec / RDP / SMB / WinRM / scheduled task …"),
        Field("account", "Account Used", "account that authenticated"),
    ),
    csv_name="LateralMovement",
    csv_headers=("Date / Time", "Source Host", "Destination Host",
                 "Technique", "Account", "Description"),
    csv_row=lambda f: [f.get("event_time", ""),
                       _attrs(f).get("source_host", ""),
                       _attrs(f).get("dest_host", ""),
                       _attrs(f).get("technique", ""),
                       _attrs(f).get("account", ""),
                       f.get("detail", "") or f.get("title", "")],
))

_register(FindingType(
    key="hostindicator",
    label="Host-Based Indicator",
    view="Host Indicators",
    group="indicator",
    fields=(
        # path first: paste the full location and the name auto-fills from it
        Field("path", "Full Path", r"full location, e.g. C:\Users\...\CRYPTBASE.dll"),
        Field("artifact", "Artifact Name", "e.g. CRYPTBASE.dll — the stackable name (auto-filled from the path)"),
        Field("artifact_type", "Artifact Type", "prefetch, shimcache, service, dll ..."),
    ),
    csv_name="HostBasedIndicators",
    csv_headers=("Artifact Type", "Date/Time", "Artifact", "Path", "Host"),
    csv_row=lambda f: [_attrs(f).get("artifact_type", ""), f.get("event_time", ""),
                       _attrs(f).get("artifact") or f.get("title", ""),
                       _attrs(f).get("path", ""),
                       f.get("host", "")],
))

# A file or directory an artifact touched — an OBSERVATION (scope/context), not
# an indicator to correlate, so it's kept OUT of the Artifacts stack. Shares the
# host-indicator attr keys, so a finding can be flipped between the two types
# losslessly (just change its Type).
_register(FindingType(
    key="filesystem",
    label="File / Directory",
    view="Files & Directories",
    group="observation",
    fields=(
        Field("path", "Full Path", r"full path, e.g. \VOLUME{...}\Windows\Update\evil.exe"),
        Field("artifact", "Name", "file/folder name (auto-filled from the path)"),
        Field("artifact_type", "Kind", "file / directory / executable"),
    ),
    csv_name="FilesAndDirectories",
    csv_headers=("Kind", "Path", "Name", "Host"),
    csv_row=lambda f: [_attrs(f).get("artifact_type", ""), _attrs(f).get("path", ""),
                       _attrs(f).get("artifact") or f.get("title", ""),
                       f.get("host", "")],
))

_register(FindingType(
    key="lead",
    label="Lead",
    view="Leads",
    # a lead is a triage worklist (e.g. an LFO autoruns sweep), not an
    # indicator: it carries `lead_items` you work through, and is deliberately
    # excluded from the Artifacts and cross-host Stack views.
    fields=(Field("source", "Source", "where the worklist came from"),),
))

_register(FindingType(
    key="note",
    label="Note",
    view="",
    group="observation",
    fields=(),
))


TIMELINE_CSV_NAME = "Timeline"
# trailing column added past the FOR508 set: what the timestamp MEANS
# (executed/created/modified/…) — leading columns stay spreadsheet-compatible
TIMELINE_CSV_HEADERS = ("Date / Time", "Host Name", "Activity", "Time Meaning")


def timeline_csv_row(f: dict) -> list:
    activity = _attrs(f).get("activity") or f.get("title", "")
    return [f.get("event_time", ""), f.get("host", ""), activity,
            f.get("time_kind", "")]


def basename(path: str) -> str:
    """Final path component, treating \\ and / alike (Windows or POSIX)."""
    return (path or "").replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]


def artifact_name(f: dict) -> str:
    """The stackable name for a host-based indicator finding: the explicit
    artifact name, else the basename of its full path, else the title."""
    a = _attrs(f)
    return ((a.get("artifact") or "").strip() or basename(a.get("path", ""))
            or f.get("title", ""))


def all_attr_fields() -> dict[str, Field]:
    """Every distinct attr field across types, keyed by attr key (for CLI flags)."""
    out: dict[str, Field] = {}
    for ft in FINDING_TYPES.values():
        for fld in ft.fields:
            out.setdefault(fld.key, fld)
    return out


# Hash algorithms carried on findings, in display order: (attrs key, label).
HASH_FIELDS = (("md5", "MD5"), ("sha1", "SHA-1"), ("sha256", "SHA-256"))


# Common DFIR tools / actions, seeded into the Step modal's Tool autocomplete so
# a fresh case doesn't start with an empty suggestion list. These are only
# suggestions — any tool a case actually uses is merged in on top, and the field
# stays free-text so analysts can always type something not listed here.
DEFAULT_TOOLS: tuple[str, ...] = (
    # Eric Zimmerman suite
    "Registry Explorer", "Timeline Explorer", "MFTECmd", "PECmd", "LECmd",
    "JLECmd", "AmcacheParser", "AppCompatCacheParser", "RECmd", "RBCmd",
    "SBECmd", "SrumECmd", "WxTCmd", "EvtxECmd", "RecentFileCacheParser",
    "bstrings", "Hasher",
    # Memory forensics
    "Volatility", "Volatility 3", "MemProcFS", "Rekall",
    # Triage / collection / IR platforms
    "KAPE", "Velociraptor", "GRR", "CyLR", "FTK Imager", "Arsenal Image Mounter",
    # Full-suite forensics
    "Autopsy", "X-Ways Forensics", "Magnet AXIOM", "EnCase",
    # Timelining
    "log2timeline / Plaso", "Timesketch",
    # Event-log analytics
    "Hayabusa", "Chainsaw", "Zircolite", "DeepBlueCLI", "EvtxECmd",
    "Event Log Explorer", "RegRipper",
    # Network
    "Wireshark", "NetworkMiner", "Zeek", "Suricata", "tshark",
    # Malware / RE
    "YARA", "capa", "PEStudio", "Detect It Easy", "Ghidra", "IDA Pro",
    "x64dbg", "oletools (olevba)", "pdf-parser", "CyberChef",
    # Sysinternals
    "Autoruns", "Process Monitor", "Process Explorer", "TCPView", "Sysmon",
    "Strings",
    # Browser / artifact parsers
    "Hindsight", "BrowsingHistoryView", "ExifTool", "SQLite Browser",
    # Live-response / shells
    "PowerShell", "cmd.exe", "bash",
)
