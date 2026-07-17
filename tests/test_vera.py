import http.client
import json
import os
import sqlite3
import threading

import pytest

from vera import db, export, types
from vera.cli import main
from vera.db import Case, CaseError


@pytest.fixture(autouse=True)
def _isolate_vera_config(tmp_path, monkeypatch):
    """Redirect vera's active-case file and config dir into a temp dir for every
    test, so no test can ever write the user's real ~/.config/vera/active."""
    monkeypatch.setattr("vera.cli.ACTIVE_FILE", str(tmp_path / "_active"), raising=False)
    monkeypatch.setattr("vera.cli.CONFIG_DIR", str(tmp_path), raising=False)


@pytest.fixture
def case(tmp_path):
    with Case(str(tmp_path / "t.vera"), create=True) as c:
        c.set_meta(name="Test Case", investigator="trinity")
        yield c


def build_sample(c: Case) -> None:
    e1 = c.add_evidence("WS01 memory dump", kind="memory", sha256="ab" * 32)
    a1 = c.add_action("vol.py -f ws01.mem windows.pstree", host="WS01",
                      evidence_id=e1, output="PID 4242 rundll32.exe\n")
    f1 = c.add_finding("rundll32 spawned by wmiprvse", ftype="malware",
                       action_id=a1, host="WS01", event_time="2026-07-01 14:22",
                       attrs={"filename": "rundll32.exe",
                              "path": r"C:\Windows\System32"})
    a2 = c.add_action("vol.py -f ws01.mem windows.netscan", host="WS01",
                      parent_finding_id=f1)
    c.add_finding("beacon to 203.0.113.7:443", ftype="netindicator",
                  action_id=a2, event_time="2026-07-01 14:25",
                  attrs={"address": "203.0.113.7", "source": "netscan"})
    c.add_finding("svc-backup used for lateral movement", ftype="account",
                  action_id=a2, host="WS01",
                  attrs={"account": "svc-backup", "account_type": "Domain Admin",
                         "sid": "S-1-5-21-1-2-3-1105"})


# ---- db ----------------------------------------------------------------

PNG = (b"\x89PNG\r\n\x1a\n" + b"\x00\x01\x02\x03" * 64)


def test_migration_v1_to_v2(tmp_path):
    p = str(tmp_path / "old.vera")
    conn = sqlite3.connect(p)
    conn.executescript("""
        CREATE TABLE case_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL DEFAULT '');
        CREATE TABLE evidence(id INTEGER PRIMARY KEY AUTOINCREMENT, label TEXT NOT NULL,
            kind TEXT DEFAULT '', source TEXT DEFAULT '', sha256 TEXT DEFAULT '',
            notes TEXT DEFAULT '', created_at TEXT);
        CREATE TABLE actions(id INTEGER PRIMARY KEY AUTOINCREMENT, performed_at TEXT,
            host TEXT DEFAULT '', evidence_id INTEGER, tool TEXT DEFAULT '',
            command TEXT NOT NULL, output TEXT DEFAULT '', output_sha256 TEXT DEFAULT '',
            output_truncated INTEGER DEFAULT 0, exit_code INTEGER, notes TEXT DEFAULT '',
            parent_finding_id INTEGER);
        CREATE TABLE findings(id INTEGER PRIMARY KEY AUTOINCREMENT, action_id INTEGER,
            created_at TEXT, event_time TEXT DEFAULT '', title TEXT NOT NULL,
            detail TEXT DEFAULT '', ftype TEXT DEFAULT 'note', host TEXT DEFAULT '',
            attrs TEXT DEFAULT '{}', starred INTEGER DEFAULT 0);
        INSERT INTO case_meta VALUES('schema_version', '1');
        INSERT INTO actions(performed_at, command) VALUES('t', 'legacy cmd');
    """)
    conn.commit()
    conn.close()

    with Case(p) as c:
        # a v1 file migrates all the way up to the current schema
        assert c.meta()["schema_version"] == str(db.SCHEMA_VERSION)
        cols = {r[1] for r in c.conn.execute("PRAGMA table_info(actions)")}
        assert {"method", "procedure"} <= cols  # v2 columns
        assert c.get_action(1)["method"] == "command"  # legacy row defaulted
        # attachments table now usable on the upgraded case
        aid = c.add_attachment("action", 1, PNG, filename="x.png", mime="image/png")
        assert c.attachment_blob(aid)[0] == PNG


def test_manual_step(case):
    a = case.add_action(method="manual", tool="Registry Explorer",
                        procedure="opened NTUSER Run key", host="WS01")
    row = case.get_action(a)
    assert row["method"] == "manual"
    assert row["command"] == "" and row["tool"] == "Registry Explorer"
    with pytest.raises(CaseError):
        case.add_action(method="manual", host="WS01")  # no tool
    with pytest.raises(CaseError):
        case.add_action(method="command")  # empty command


def test_attachment_roundtrip_and_graph(case):
    a = case.add_action("vol.py pslist", host="WS01")
    f = case.add_finding("evil dll", ftype="malware", action_id=a)
    e = case.add_evidence("WS01 image")
    ida = case.add_attachment("action", a, PNG, filename="out.png",
                              mime="image/png", role="output", caption="pstree")
    idf = case.add_attachment("finding", f, PNG, filename="proof.png",
                              mime="image/png", role="exhibit")
    case.add_attachment("evidence", e, PNG, filename="disk.png", mime="image/png")

    meta = case.attachments("finding", f)
    assert len(meta) == 1 and meta[0]["sha256"] == db.sha256_bytes(PNG)
    assert "bytes" not in meta[0]  # metadata only, no blob
    assert case.attachment_blob(ida) == (PNG, "image/png", "out.png")

    tree = case.tree()
    node = tree[0]
    assert len(node["attachments"]) == 1
    assert len(node["findings"][0]["attachments"]) == 1
    assert case.evidence()[0]["attachments"][0]["filename"] == "disk.png"

    with pytest.raises(CaseError):
        case.add_attachment("action", a, b"x" * (db.ATTACHMENT_CAP + 1))
    with pytest.raises(CaseError):
        case.add_attachment("action", 999, PNG)  # bad owner

    case.delete_attachment(idf)
    assert case.attachments("finding", f) == []


def test_md_export_embeds_images(case, tmp_path):
    a = case.add_action(method="manual", tool="Timeline Explorer",
                        procedure="filtered on rundll32", host="WS01")
    f = case.add_finding("suspicious exec", ftype="hostindicator", action_id=a)
    case.add_attachment("finding", f, PNG, filename="proof.png", mime="image/png",
                        caption="the smoking gun")
    written = export.export(case, "md", str(tmp_path / "out"))
    md_path = written[0]
    text = open(md_path).read()
    assert "manual step" in text
    assert "filtered on rundll32" in text
    assert "proof.png" in text and "smoking gun" in text
    # the image file was actually written alongside the report
    assert any(p.endswith(".png") for p in written[1:])
    assert os.path.exists(written[1])


def test_migration_v2_to_v3(tmp_path):
    p = str(tmp_path / "v2.vera")
    conn = sqlite3.connect(p)
    conn.executescript("""
        CREATE TABLE case_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL DEFAULT '');
        CREATE TABLE evidence(id INTEGER PRIMARY KEY AUTOINCREMENT, label TEXT NOT NULL,
            kind TEXT DEFAULT '', source TEXT DEFAULT '', sha256 TEXT DEFAULT '',
            notes TEXT DEFAULT '', created_at TEXT);
        CREATE TABLE actions(id INTEGER PRIMARY KEY AUTOINCREMENT, performed_at TEXT,
            host TEXT DEFAULT '', evidence_id INTEGER, tool TEXT DEFAULT '',
            method TEXT DEFAULT 'command', command TEXT DEFAULT '', procedure TEXT DEFAULT '',
            output TEXT DEFAULT '', output_sha256 TEXT DEFAULT '', output_truncated INTEGER DEFAULT 0,
            exit_code INTEGER, notes TEXT DEFAULT '', parent_finding_id INTEGER);
        CREATE TABLE findings(id INTEGER PRIMARY KEY AUTOINCREMENT, action_id INTEGER,
            created_at TEXT, event_time TEXT DEFAULT '', title TEXT NOT NULL,
            detail TEXT DEFAULT '', ftype TEXT DEFAULT 'note', host TEXT DEFAULT '',
            attrs TEXT DEFAULT '{}', starred INTEGER DEFAULT 0);
        INSERT INTO case_meta VALUES('schema_version', '2');
        INSERT INTO actions(performed_at, command) VALUES('t', 'old cmd');
    """)
    conn.commit()
    conn.close()

    with Case(p) as c:
        # migrates all the way to current (this synthetic v2 lacks attachments,
        # which _migrate_v4 tolerates)
        assert c.meta()["schema_version"] == str(db.SCHEMA_VERSION)
        for tbl in ("hosts", "collections", "finding_hosts"):
            assert c.conn.execute(
                "SELECT name FROM sqlite_master WHERE name=?", (tbl,)).fetchone()
        assert "collection_id" in {r[1] for r in c.conn.execute("PRAGMA table_info(evidence)")}
        assert "collection_id" in {r[1] for r in c.conn.execute("PRAGMA table_info(actions)")}
        # new features usable on the upgraded case
        col = c.add_collection("batch")
        h = c.add_host("WS10")
        c.add_finding("x", action_id=1, host_ids=[h])
        assert c.stack_findings()[0]["stack"] == 1


def test_host_registry_and_resolution(case):
    h1 = case.add_host("WS01", ip="10.0.0.1", system_type="workstation")
    case.add_host("WS01")  # dup by name -> reuse
    assert len(case.hosts()) == 1
    assert case.resolve_host("H%d" % h1) == h1
    assert case.resolve_host("ws01") == h1          # case-insensitive
    case.add_host("WS01", aliases=["ws01.corp"])    # merge alias
    assert case.resolve_host("WS01.CORP") == h1
    with pytest.raises(CaseError):
        case.resolve_host("nope")
    created = case.resolve_host("WS02", create=True)  # auto-create
    assert created and case.resolve_host("WS02") == created


def test_cross_host_finding_and_stack(case):
    a = case.add_action("AmcacheParser", host="")
    hids = case.resolve_hosts(["WS01", "WS03", "WS07"], create=True)
    f = case.add_finding("evil.exe in amcache", ftype="malware", action_id=a,
                         host_ids=hids)
    rare = case.add_finding("rare.dll", ftype="hostindicator", action_id=a,
                            host_ids=case.resolve_hosts(["WS03"]))
    gf = case.get_finding(f)
    assert gf["stack"] == 3
    assert [h["name"] for h in gf["affected_hosts"]] == ["WS01", "WS03", "WS07"]
    # tree carries it
    assert case.tree()[0]["findings"][0]["stack"] == 3
    # stack: rarest first
    order = [(x["id"], x["stack"]) for x in case.stack_findings()]
    assert order == [(rare, 1), (f, 3)]
    # per-host rollup
    ws03 = next(h for h in case.hosts() if h["name"] == "WS03")
    assert ws03["finding_count"] == 2
    assert len(case.findings_for_host(ws03["id"])) == 2


def test_host_os_field_and_backfill(case):
    from vera import db
    # explicit os
    h = case.add_host("RD01", os="Windows 11", ip="10.0.0.1")
    assert next(x for x in case.hosts() if x["id"] == h)["os"] == "Windows 11"
    # os derived from notes when not given
    h2 = case.add_host("DC01", notes="Server 2022 Domain Controller")
    assert next(x for x in case.hosts() if x["id"] == h2)["os"] == "Server 2022"
    h3 = case.add_host("SMTP01", notes="Ubuntu 22.04 External MTA")
    assert next(x for x in case.hosts() if x["id"] == h3)["os"] == "Ubuntu 22.04"
    # notes that don't start with an OS keyword -> no false guess
    h4 = case.add_host("MISC", notes="some random note")
    assert next(x for x in case.hosts() if x["id"] == h4)["os"] == ""
    # editable
    case.update_host(h4, os="Debian 12")
    assert next(x for x in case.hosts() if x["id"] == h4)["os"] == "Debian 12"
    # helper direct
    assert db.os_from_notes("Windows 10 - Jane Doe - Analyst") == "Windows 10"
    assert db.os_from_notes("no os here") == ""


def test_migration_v6_to_v7_backfills_os(tmp_path):
    p = str(tmp_path / "v6.vera")
    c = Case(p, create=True)
    c.conn.execute("INSERT INTO hosts(name, notes, created_at) VALUES "
                   "('RD01', 'Windows 11 - Steve Rogers - Analyst', 't')")
    c.conn.execute("INSERT INTO hosts(name, notes, created_at) VALUES "
                   "('DC01', 'Server 2022 Domain Controller', 't')")
    c.conn.execute("ALTER TABLE hosts DROP COLUMN os")
    c.conn.execute("UPDATE case_meta SET value='6' WHERE key='schema_version'")
    c.conn.commit()
    c.close()
    with Case(p) as c2:
        assert c2.meta()["schema_version"] == str(db.SCHEMA_VERSION)
        by_name = {h["name"]: h for h in c2.hosts()}
        assert by_name["RD01"]["os"] == "Windows 11"   # backfilled from notes
        assert by_name["DC01"]["os"] == "Server 2022"


def test_update_host(case):
    h = case.add_host("WS01", ip="10.0.0.1")
    case.add_host("WS02")
    case.update_host(h, name="WS01-RENAMED", system_type="workstation",
                     aliases=["ws01.corp", "old-ws01"], notes="pivot host")
    got = next(x for x in case.hosts() if x["id"] == h)
    assert got["name"] == "WS01-RENAMED"
    assert got["system_type"] == "workstation"
    assert got["aliases"] == ["ws01.corp", "old-ws01"]
    # rename still resolvable by new name and by alias
    assert case.resolve_host("WS01-RENAMED") == h
    assert case.resolve_host("ws01.corp") == h
    # renaming onto another host's name is rejected
    with pytest.raises(CaseError):
        case.update_host(h, name="WS02")
    with pytest.raises(CaseError):
        case.update_host(h, bogus="x")


def test_soft_delete_host(case):
    a = case.add_action("cmd")
    hids = case.resolve_hosts(["WS01", "WS02", "WS03"], create=True)
    f = case.add_finding("evil", ftype="malware", action_id=a, host_ids=hids)
    ws02 = case.resolve_host("WS02")

    case.soft_delete_host(ws02)
    names = [h["name"] for h in case.hosts()]
    assert "WS02" not in names and len(names) == 2      # hidden from registry
    assert case.counts()["hosts"] == 2
    # the finding's link is retained but the deleted host drops out of the stack
    gf = case.get_finding(f)
    assert gf["stack"] == 2
    assert "WS02" not in [h["name"] for h in gf["affected_hosts"]]
    assert case.finding_host_ids(f) == sorted(hids)     # nothing purged
    # the freed name can be registered fresh (new id)
    new = case.add_host("WS02")
    assert new != ws02 and case.resolve_host("WS02") == new


def test_soft_delete_attachment(case):
    a = case.add_action("cmd")
    att = case.add_attachment("action", a, PNG, filename="x.png", mime="image/png")
    assert len(case.attachments("action", a)) == 1
    case.delete_attachment(att)
    assert case.attachments("action", a) == []          # hidden
    with pytest.raises(CaseError):
        case.attachment_blob(att)                        # not served
    # but the bytes are retained, not purged
    row = case.conn.execute(
        "SELECT deleted_at, bytes FROM attachments WHERE id = ?", (att,)).fetchone()
    assert row["deleted_at"] and row["bytes"] == PNG


def test_migration_v3_to_v4(tmp_path):
    # a v3 case (built via a fresh Case then version pinned back) upgrades cleanly
    p = str(tmp_path / "v3.vera")
    c = Case(p, create=True)
    c.conn.execute("UPDATE case_meta SET value='3' WHERE key='schema_version'")
    c.conn.execute("DROP INDEX IF EXISTS idx_hosts_name")
    c.conn.execute("CREATE UNIQUE INDEX idx_hosts_name ON hosts(name COLLATE NOCASE)")
    for tbl in ("hosts", "attachments"):
        c.conn.execute(f"ALTER TABLE {tbl} DROP COLUMN deleted_at")
    c.conn.commit()
    c.close()
    with Case(p) as c2:
        # migrates from the faked v3 up through v4 (deleted_at) to current
        assert c2.meta()["schema_version"] == str(db.SCHEMA_VERSION)
        for tbl in ("hosts", "attachments"):
            assert "deleted_at" in {r[1] for r in c2.conn.execute(
                f"PRAGMA table_info({tbl})")}
        h = c2.add_host("WS01")
        c2.soft_delete_host(h)
        assert c2.add_host("WS01") != h  # freed name reusable via partial index


def test_evidence_and_action_host_links(case):
    rd03 = case.add_host("RD03", ip="172.16.6.13")
    rd07 = case.add_host("RD07")
    e = case.add_evidence("RD03 disk", kind="disk", host_ids=[rd03])
    a = case.add_action("mftecmd -f RD03.mft", host_ids=[rd03, rd07])
    # links enrich the returned dicts
    assert [h["name"] for h in case.evidence()[0]["hosts"]] == ["RD03"]
    assert {h["name"] for h in case.get_action(a)["hosts"]} == {"RD03", "RD07"}
    assert {h["name"] for h in case.tree()[0]["hosts"]} == {"RD03", "RD07"}
    # reverse lookups
    assert case.evidence_for_host(rd03)[0]["id"] == e
    assert case.actions_for_host(rd07)[0]["id"] == a
    # replace-set
    case.set_action_hosts(a, [rd03])
    assert [h["name"] for h in case.get_action(a)["hosts"]] == ["RD03"]


def test_soft_deleted_host_drops_from_all_links(case):
    rd03 = case.add_host("RD03")
    rd07 = case.add_host("RD07")
    e = case.add_evidence("img", host_ids=[rd03, rd07])
    a = case.add_action("cmd", host_ids=[rd03, rd07])
    f = case.add_finding("x", ftype="malware", action_id=a, host_ids=[rd03, rd07])
    case.soft_delete_host(rd07)
    assert [h["name"] for h in case.evidence()[0]["hosts"]] == ["RD03"]
    assert [h["name"] for h in case.get_action(a)["hosts"]] == ["RD03"]
    assert [h["name"] for h in case.get_finding(f)["affected_hosts"]] == ["RD03"]
    # finding's derived host string also excludes the deleted host
    assert case.get_finding(f)["host"] == "RD03"


def test_finding_host_derived_for_category_views(case):
    rd03 = case.add_host("RD03")
    a = case.add_action("cmd")
    f = case.add_finding("acct", ftype="account", action_id=a, host_ids=[rd03])
    # types.py category CSV reads f["host"]; it now derives from the link
    from vera import types
    row = types.FINDING_TYPES["account"].csv_row(case.get_finding(f))
    assert "RD03" in row  # Host System column populated from the registry link


def test_set_finding_hosts_replaces(case):
    a = case.add_action("cmd")
    f = case.add_finding("x", action_id=a,
                         host_ids=case.resolve_hosts(["WS01", "WS02"], create=True))
    case.set_finding_hosts(f, case.resolve_hosts(["WS03"], create=True))
    assert [h["name"] for h in case.get_finding(f)["affected_hosts"]] == ["WS03"]


def test_finding_hashes(case):
    a = case.add_action("cmd")
    f = case.add_finding(
        "evil.exe", ftype="malware", action_id=a,
        hashes={"md5": "D41D8CD98F00B204E9800998ECF8427E",  # uppercase in
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"})
    got = case.get_finding(f)["hashes"]
    assert got["md5"] == "d41d8cd98f00b204e9800998ecf8427e"  # normalized lower
    assert "sha256" in got and "sha1" not in got  # blank omitted
    # editing hashes
    case.update_finding(f, hashes={"sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709"})
    assert case.get_finding(f)["hashes"]["sha1"].startswith("da39a3")
    # validation
    with pytest.raises(CaseError):
        case.add_finding("x", hashes={"md5": "nothex-nothex-nothex-nothex-not!"})
    with pytest.raises(CaseError):
        case.add_finding("x", hashes={"sha256": "abc"})   # wrong length
    with pytest.raises(CaseError):
        case.add_finding("x", hashes={"crc32": "deadbeef"})  # unknown algo


def test_hash_file(tmp_path):
    from vera import db
    p = tmp_path / "sample.bin"
    p.write_bytes(b"hello")
    h = db.hash_file(str(p))
    assert h["md5"] == "5d41402abc4b2a76b9719d911017c592"
    assert h["sha1"] == "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
    assert set(h) == {"md5", "sha1", "sha256"}


def test_malware_csv_has_hash_columns(case, tmp_path):
    a = case.add_action("cmd")
    case.add_finding("evil.dll", ftype="malware", action_id=a,
                     attrs={"filename": "evil.dll"},
                     hashes={"md5": "0cc175b9c0f1b6a831c399e269772661"})
    written = export.export(case, "csv", str(tmp_path / "out"))
    mal = next(p for p in written if p.endswith("MalwareAndTools.csv"))
    import csv as _csv
    rows = list(_csv.reader(open(mal)))
    assert rows[0][-3:] == ["MD5", "SHA-1", "SHA-256"]
    assert rows[1][-3] == "0cc175b9c0f1b6a831c399e269772661"


def test_migration_v5_to_v6(tmp_path):
    p = str(tmp_path / "v5.vera")
    c = Case(p, create=True)
    c.conn.execute("ALTER TABLE findings DROP COLUMN hashes")
    c.conn.execute("UPDATE case_meta SET value='5' WHERE key='schema_version'")
    c.conn.commit()
    c.close()
    with Case(p) as c2:
        assert c2.meta()["schema_version"] == str(db.SCHEMA_VERSION)
        assert "hashes" in {r[1] for r in c2.conn.execute("PRAGMA table_info(findings)")}
        a = c2.add_action("cmd")
        f = c2.add_finding("x", action_id=a,
                           hashes={"md5": "0cc175b9c0f1b6a831c399e269772661"})
        assert c2.get_finding(f)["hashes"]["md5"].startswith("0cc175")


def test_update_evidence(case):
    rd03 = case.add_host("RD03")
    col = case.add_collection("batch")
    e = case.add_evidence("RD03 disk", kind="disk", host_ids=[rd03])
    case.update_evidence(e, label="RD03 disk image (E01)", kind="disk image",
                         sha256="ab" * 32, source="/mnt/evidence/rd03.E01",
                         notes="verified", collection_id=col)
    got = next(x for x in case.evidence() if x["id"] == e)
    assert got["label"] == "RD03 disk image (E01)"
    assert got["kind"] == "disk image" and got["collection_id"] == col
    assert got["sha256"] == "ab" * 32
    # host links survive a field-only edit
    assert [h["name"] for h in got["hosts"]] == ["RD03"]
    # guards
    with pytest.raises(CaseError):
        case.update_evidence(e, label="")
    with pytest.raises(CaseError):
        case.update_evidence(e, bogus="x")
    with pytest.raises(CaseError):
        case.update_evidence(e, collection_id=999)


def test_collection_hosts_and_inheritance(case):
    hs = [case.add_host(f"RD0{i}") for i in range(1, 4)]  # RD01, RD02, RD03
    col = case.add_collection("Lab export", tool="KAPE", host_ids=hs)
    assert [h["name"] for h in case.collections()[0]["hosts"]] == ["RD01", "RD02", "RD03"]
    assert case.collection_host_ids(col) == sorted(hs)
    # editing the collection's host set
    case.set_collection_hosts(col, hs[:2])
    assert len(case.collections()[0]["hosts"]) == 2
    case.update_collection(col, name="Lab export v2", scope="3 hosts")
    assert case.collections()[0]["name"] == "Lab export v2"

    # action derives its collection from the evidence it examines
    e = case.add_evidence("bundle", collection_id=col, host_ids=hs)
    a = case.add_action("hayabusa", evidence_id=e)      # no collection_id given
    assert case.get_action(a)["collection_id"] == col   # inherited from evidence
    # explicit collection still honored
    a2 = case.add_action("x", collection_id=col)
    assert case.get_action(a2)["collection_id"] == col


def test_collection_scoping(case):
    col = case.add_collection("Lab2 export", tool="AmcacheParser", scope="40 hosts")
    e = case.add_evidence("WS03 amcache", kind="amcache", collection_id=col)
    a = case.add_action(method="manual", tool="AmcacheParser", procedure="parsed",
                        collection_id=col)
    assert case.evidence()[0]["collection_id"] == col
    assert case.get_action(a)["collection_id"] == col
    with pytest.raises(CaseError):
        case.add_evidence("bad", collection_id=999)


def test_migration_v4_to_v5(tmp_path):
    # a v4 case (fresh case, tables dropped + version pinned) upgrades cleanly
    p = str(tmp_path / "v4.vera")
    c = Case(p, create=True)
    c.conn.execute("DROP TABLE evidence_hosts")
    c.conn.execute("DROP TABLE action_hosts")
    c.conn.execute("UPDATE case_meta SET value='4' WHERE key='schema_version'")
    c.conn.commit()
    c.close()
    with Case(p) as c2:
        assert c2.meta()["schema_version"] == str(db.SCHEMA_VERSION)
        for tbl in ("evidence_hosts", "action_hosts"):
            assert c2.conn.execute(
                "SELECT name FROM sqlite_master WHERE name=?", (tbl,)).fetchone()
        h = c2.add_host("RD01")
        c2.add_evidence("img", host_ids=[h])
        assert [x["name"] for x in c2.evidence()[0]["hosts"]] == ["RD01"]


def test_create_and_reopen(tmp_path):
    p = str(tmp_path / "a.vera")
    Case(p, create=True).close()
    with Case(p) as c:
        assert c.meta()["schema_version"] == str(db.SCHEMA_VERSION)
    with pytest.raises(CaseError):
        Case(p, create=True)  # refuses overwrite
    with pytest.raises(CaseError):
        Case(str(tmp_path / "missing.vera"))


def test_not_a_case_file(tmp_path):
    p = tmp_path / "junk.vera"
    p.write_text("not sqlite")
    with pytest.raises(CaseError):
        Case(str(p))


def test_tree_structure(case):
    build_sample(case)
    roots = case.tree()
    assert len(roots) == 1
    a1 = roots[0]
    assert a1["tool"] == "vol.py"
    assert len(a1["findings"]) == 1
    f1 = a1["findings"][0]
    assert f1["ftype"] == "malware"
    assert len(f1["actions"]) == 1
    a2 = f1["actions"][0]
    assert a2["parent_finding_id"] == f1["id"]
    assert {f["ftype"] for f in a2["findings"]} == {"netindicator", "account"}


def test_timeline_orders_by_event_time(case):
    build_sample(case)
    tl = case.timeline()
    assert [f["event_time"] for f in tl] == ["2026-07-01 14:22", "2026-07-01 14:25"]


def test_output_capped_and_hashed(case):
    big = "x" * (db.OUTPUT_CAP + 100)
    a = case.add_action("cmd", output=big)
    row = case.get_action(a)
    assert len(row["output"]) == db.OUTPUT_CAP
    assert row["output_truncated"] == 1
    assert row["output_sha256"] == db.sha256_text(big)


def test_bad_refs_rejected(case):
    with pytest.raises(CaseError):
        case.add_action("cmd", parent_finding_id=99)
    with pytest.raises(CaseError):
        case.add_finding("x", action_id=99)
    with pytest.raises(CaseError):
        case.update_finding(1, nonsense="x")
    with pytest.raises(CaseError):
        db.resolve_ref("Z9")
    assert db.resolve_ref("f12") == ("F", 12)


def test_resolve_evidence(case):
    e = case.add_evidence("WS01 memory dump")
    assert case.resolve_evidence(f"E{e}") == e
    assert case.resolve_evidence("memory") == e
    case.add_evidence("WS02 memory dump")
    with pytest.raises(CaseError):
        case.resolve_evidence("memory")  # ambiguous now


def test_update_finding_attrs(case):
    build_sample(case)
    case.update_finding(1, attrs={"filename": "evil.dll"}, starred=1)
    f = case.get_finding(1)
    assert f["attrs"]["filename"] == "evil.dll"
    assert f["starred"] == 1


# ---- export ------------------------------------------------------------

def test_csv_headers_match_ir_spreadsheet(case, tmp_path):
    build_sample(case)
    written = export.export(case, "csv", str(tmp_path / "out"))
    by_name = {os.path.basename(p): p for p in written}
    assert "t_Timeline.csv" in by_name
    import csv as _csv
    with open(by_name["t_CompromisedAccounts.csv"]) as fh:
        rows = list(_csv.reader(fh))
    assert rows[0] == list(types.FINDING_TYPES["account"].csv_headers)
    assert rows[1] == ["", "svc-backup", "WS01", "Domain Admin",
                       "S-1-5-21-1-2-3-1105"]
    with open(by_name["t_MalwareAndTools.csv"]) as fh:
        rows = list(_csv.reader(fh))
    assert rows[1][0] == "rundll32.exe"
    assert rows[1][5] == "WS01"


def test_md_export_is_replayable(case, tmp_path):
    build_sample(case)
    (path,) = export.export(case, "md", str(tmp_path))
    text = open(path).read()
    assert "vol.py -f ws01.mem windows.pstree" in text
    assert "vol.py -f ws01.mem windows.netscan" in text
    assert "Follow-up to finding F1" in text
    assert "beacon to 203.0.113.7:443" in text
    assert "## Timeline" in text


def test_json_export_round_trip(case, tmp_path):
    build_sample(case)
    (path,) = export.export(case, "json", str(tmp_path))
    data = json.load(open(path))
    assert data["vera_case"]["name"] == "Test Case"
    assert len(data["actions"]) == 2
    assert len(data["findings"]) == 3


# ---- cli ---------------------------------------------------------------

@pytest.fixture
def cli_case(tmp_path, monkeypatch):
    monkeypatch.setenv("VERA_CASE", "")
    monkeypatch.setattr("vera.cli.ACTIVE_FILE", str(tmp_path / "active"))
    monkeypatch.setattr("vera.cli.CONFIG_DIR", str(tmp_path))
    path = str(tmp_path / "lab.vera")
    assert main(["init", path, "--name", "Lab 1"]) == 0
    return path


def test_cli_flow(cli_case, capsys):
    assert main(["evidence", "add", "WS01 image", "--kind", "disk"]) == 0
    assert main(["run", "fls -r ws01.E01", "--host", "WS01",
                 "--evidence", "E1"]) == 0
    assert main(["finding", "suspicious prefetch", "-t", "hostindicator",
                 "--artifact-type", "prefetch",
                 "--artifact", "EVIL.EXE-1234.pf",
                 "--time", "2026-07-02 09:00"]) == 0
    assert main(["run", "strings EVIL.EXE", "--from", "F1"]) == 0
    capsys.readouterr()
    assert main(["log"]) == 0
    out = capsys.readouterr().out
    assert "A1" in out and "F1" in out and "A2" in out
    assert main(["show", "F1"]) == 0
    out = capsys.readouterr().out
    assert "EVIL.EXE-1234.pf" in out

    assert main(["edit", "F1", "--star", "--note", "confirmed"]) == 0
    assert main(["show", "F1"]) == 0
    assert "confirmed" in capsys.readouterr().out


def test_cli_errors(cli_case, capsys):
    assert main(["show", "A99"]) == 1
    assert "A99 does not exist" in capsys.readouterr().err
    assert main(["run", "x", "--from", "A1"]) == 1
    assert "--from expects a finding" in capsys.readouterr().err
    assert main(["finding", "orphan", "--on", "none"]) == 0


def test_cli_no_active_case(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("VERA_CASE", raising=False)
    monkeypatch.setattr("vera.cli.ACTIVE_FILE", str(tmp_path / "nope"))
    assert main(["status"]) == 1
    assert "no active case" in capsys.readouterr().err


# ---- server ------------------------------------------------------------

@pytest.fixture
def running_server(case):
    build_sample(case)
    from http.server import ThreadingHTTPServer
    from vera.server import Handler
    Handler.case_path = case.path
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield httpd.server_address[1]
    httpd.shutdown()


def _req(port, method, path, body=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    headers = {"Content-Type": "application/json"} if body is not None else {}
    conn.request(method, path, json.dumps(body) if body is not None else None,
                 headers)
    res = conn.getresponse()
    raw = res.read()
    conn.close()
    return res.status, raw


def test_api_read(running_server):
    port = running_server
    status, raw = _req(port, "GET", "/api/case")
    assert status == 200
    data = json.loads(raw)
    assert data["meta"]["name"] == "Test Case"
    assert any(t["key"] == "malware" for t in data["types"])

    status, raw = _req(port, "GET", "/api/tree")
    tree = json.loads(raw)
    assert len(tree["roots"]) == 1
    assert tree["roots"][0]["findings"][0]["actions"]

    status, raw = _req(port, "GET", "/")
    assert status == 200 and b"vera" in raw

    status, raw = _req(port, "GET", "/api/export/md")
    assert status == 200 and b"windows.pstree" in raw


@pytest.fixture
def blank_server(tmp_path, monkeypatch):
    monkeypatch.setattr("vera.server._set_active_case", lambda p: None)
    from http.server import ThreadingHTTPServer
    from vera.server import Handler
    Handler.case_path = None
    Handler.case_dir = str(tmp_path)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield httpd.server_address[1]
    httpd.shutdown()


def test_create_and_open_case_via_api(blank_server):
    port = blank_server
    status, raw = _req(port, "GET", "/api/case")
    assert status == 200 and json.loads(raw)["active"] is False

    status, raw = _req(port, "POST", "/api/cases", {"name": "FOR508 Lab 9"})
    assert status == 201
    assert json.loads(raw)["file"] == "for508-lab-9.vera"

    status, raw = _req(port, "GET", "/api/case")
    data = json.loads(raw)
    assert data["active"] is True and data["meta"]["name"] == "FOR508 Lab 9"

    status, raw = _req(port, "GET", "/api/cases")
    assert any(c["name"] == "FOR508 Lab 9"
               for c in json.loads(raw)["cases"])

    status, raw = _req(port, "POST", "/api/cases", {"name": ""})
    assert status == 400


def test_api_write(running_server):
    port = running_server
    status, raw = _req(port, "POST", "/api/actions",
                       {"command": "reg query ...", "host": "WS02"})
    assert status == 201
    new_id = json.loads(raw)["id"]

    status, raw = _req(port, "POST", "/api/findings",
                       {"title": "persistence run key", "ftype": "hostindicator",
                        "action_id": new_id,
                        "attrs": {"artifact_type": "runkey"}})
    assert status == 201
    fid = json.loads(raw)["id"]

    status, _ = _req(port, "PATCH", f"/api/findings/{fid}", {"starred": 1})
    assert status == 200

    status, raw = _req(port, "POST", "/api/actions", {"command": ""})
    assert status == 400
    assert "empty" in json.loads(raw)["error"]


def test_api_manual_step_and_attachments(running_server):
    import base64
    port = running_server
    # a GUI/manual step with no command line
    status, raw = _req(port, "POST", "/api/actions",
                       {"method": "manual", "tool": "Registry Explorer",
                        "procedure": "opened Run key", "host": "WS02"})
    assert status == 201
    aid = json.loads(raw)["id"]

    # attach two captioned views to the same step (multiple screenshots)
    b64 = base64.b64encode(PNG).decode()
    status, raw = _req(port, "POST", "/api/attachments",
                       {"owner_type": "action", "owner_id": aid, "role": "output",
                        "filename": "shot.png", "mime": "image/png",
                        "caption": "Run key view", "data_base64": b64})
    assert status == 201
    att_id = json.loads(raw)["id"]
    status, _ = _req(port, "POST", "/api/attachments",
                     {"owner_type": "action", "owner_id": aid, "role": "exhibit",
                      "filename": "shot2.png", "mime": "image/png",
                      "caption": "Services view", "data_base64": b64})
    assert status == 201

    status, raw = _req(port, "GET", f"/api/attachments/{att_id}")
    assert status == 200 and raw == PNG

    # both views show up on the action node, captions preserved
    status, raw = _req(port, "GET", "/api/tree")
    tree = json.loads(raw)
    node = [a for a in tree["roots"] if a["id"] == aid][0]
    assert node["method"] == "manual"
    atts = node["attachments"]
    assert len(atts) == 2
    assert {a["caption"] for a in atts} == {"Run key view", "Services view"}
    assert {a["role"] for a in atts} == {"output", "exhibit"}

    # bad base64 is rejected, delete works
    status, _ = _req(port, "POST", "/api/attachments",
                     {"owner_type": "action", "owner_id": aid,
                      "data_base64": "!!!notbase64!!!"})
    assert status == 400
    status, _ = _req(port, "DELETE", f"/api/attachments/{att_id}")
    assert status == 200
    status, _ = _req(port, "GET", f"/api/attachments/{att_id}")
    assert status == 400  # gone


def test_api_hosts_collections_stack(running_server):
    port = running_server
    # bulk host add
    status, raw = _req(port, "POST", "/api/hosts",
                       {"names": ["WS01", "WS02", "WS03"], "system_type": "workstation"})
    assert status == 201 and json.loads(raw)["count"] == 3

    hid_list = [h["id"] for h in json.loads(_req(port, "GET", "/api/hosts")[1])]
    status, raw = _req(port, "POST", "/api/collections",
                       {"name": "Lab2 export", "tool": "AmcacheParser",
                        "host_ids": hid_list[:2]})
    assert status == 201
    cid = json.loads(raw)["id"]

    # case payload now surfaces hosts + collections (with their hosts)
    status, raw = _req(port, "GET", "/api/case")
    info = json.loads(raw)
    assert len(info["hosts"]) == 3 and len(info["collections"]) == 1
    assert info["counts"]["hosts"] == 3
    col = info["collections"][0]
    assert len(col["hosts"]) == 2
    # PATCH collection name + host set
    status, _ = _req(port, "PATCH", f"/api/collections/{cid}",
                     {"name": "Lab2 export (final)", "host_ids": hid_list})
    assert status == 200
    col = json.loads(_req(port, "GET", "/api/case")[1])["collections"][0]
    assert col["name"] == "Lab2 export (final)" and len(col["hosts"]) == 3

    # cross-host finding via host_names (auto-creates WS09)
    status, raw = _req(port, "POST", "/api/findings",
                       {"title": "evil.exe", "ftype": "malware",
                        "host_names": ["WS01", "WS03", "WS09"]})
    assert status == 201
    fid = json.loads(raw)["id"]

    status, raw = _req(port, "GET", "/api/stack")
    stack = json.loads(raw)
    assert stack and stack[0]["stack"] == 3
    assert {h["name"] for h in stack[0]["affected_hosts"]} == {"WS01", "WS03", "WS09"}

    # a finding carries file hashes (normalized) via the API
    status, raw = _req(port, "POST", "/api/findings",
                       {"title": "dropper.exe", "ftype": "malware",
                        "hashes": {"md5": "0CC175B9C0F1B6A831C399E269772661"}})
    assert status == 201
    hfid = json.loads(raw)["id"]
    tree = json.loads(_req(port, "GET", "/api/tree")[1])
    hf = next(f for f in tree["unattached"] if f["id"] == hfid)
    assert hf["hashes"]["md5"] == "0cc175b9c0f1b6a831c399e269772661"
    # a malformed hash is rejected
    status, _ = _req(port, "POST", "/api/findings",
                     {"title": "bad", "ftype": "malware", "hashes": {"sha1": "xyz"}})
    assert status == 400

    # PATCH replaces the affected-host set
    status, _ = _req(port, "PATCH", f"/api/findings/{fid}", {"host_names": ["WS02"]})
    assert status == 200
    status, raw = _req(port, "GET", "/api/stack")
    assert [h["name"] for h in json.loads(raw)[0]["affected_hosts"]] == ["WS02"]

    # edit a host via PATCH /api/hosts/<id>
    hid = [h["id"] for h in json.loads(_req(port, "GET", "/api/hosts")[1])
           if h["name"] == "WS01"][0]
    status, _ = _req(port, "PATCH", f"/api/hosts/{hid}",
                     {"name": "WS01-DC", "system_type": "domain controller",
                      "aliases": ["ws01.corp"]})
    assert status == 200
    hosts = json.loads(_req(port, "GET", "/api/hosts")[1])
    edited = next(h for h in hosts if h["id"] == hid)
    assert edited["name"] == "WS01-DC" and edited["aliases"] == ["ws01.corp"]

    # evidence + action link to hosts by id (the picker's path)
    ws02 = next(h["id"] for h in hosts if h["name"] == "WS02")
    status, raw = _req(port, "POST", "/api/evidence",
                       {"label": "WS02 disk", "kind": "disk", "host_ids": [ws02]})
    assert status == 201
    eid = json.loads(raw)["id"]
    status, raw = _req(port, "POST", "/api/actions",
                       {"command": "mftecmd", "host_ids": [ws02, hid]})
    assert status == 201
    aid = json.loads(raw)["id"]
    info = json.loads(_req(port, "GET", "/api/case")[1])
    ev = next(e for e in info["evidence"] if e["id"] == eid)
    assert [h["name"] for h in ev["hosts"]] == ["WS02"]
    tree = json.loads(_req(port, "GET", "/api/tree")[1])
    act = next(a for a in tree["roots"] if a["id"] == aid)
    assert {h["name"] for h in act["hosts"]} == {"WS02", "WS01-DC"}
    # PATCH evidence: fields AND host links together
    status, _ = _req(port, "PATCH", f"/api/evidence/{eid}",
                     {"label": "WS02 disk image (E01)", "kind": "disk image",
                      "sha256": "cd" * 32, "host_ids": [hid]})
    assert status == 200
    info = json.loads(_req(port, "GET", "/api/case")[1])
    ev = next(e for e in info["evidence"] if e["id"] == eid)
    assert ev["label"] == "WS02 disk image (E01)" and ev["kind"] == "disk image"
    assert ev["sha256"] == "cd" * 32
    assert [h["name"] for h in ev["hosts"]] == ["WS01-DC"]
    # host detail rolls up evidence + actions
    detail = json.loads(_req(port, "GET", f"/api/host_detail?id={hid}")[1])
    assert detail["actions"] and detail["evidence"]


# ---- v0.9: disposition, coverage, per-host expansion ---------------------

def test_host_status(case):
    h1 = case.add_host("RD01", status="compromised")
    h2 = case.add_host("RD02")
    hosts = {h["id"]: h for h in case.hosts()}
    assert hosts[h1]["status"] == "compromised"
    assert hosts[h2]["status"] == ""
    case.update_host(h2, status="Suspicious")     # normalized to lowercase
    assert next(h for h in case.hosts() if h["id"] == h2)["status"] == "suspicious"
    case.update_host(h2, status="unknown")        # synonym for '' (not triaged)
    assert next(h for h in case.hosts() if h["id"] == h2)["status"] == ""
    with pytest.raises(CaseError):
        case.update_host(h1, status="pwned")
    with pytest.raises(CaseError):
        case.add_host("RD03", status="bad-value")


def test_migration_v8_to_v9_adds_status(tmp_path):
    p = str(tmp_path / "v8.vera")
    c = Case(p, create=True)
    c.add_host("WS01")
    c.conn.execute("UPDATE case_meta SET value='8' WHERE key='schema_version'")
    c.conn.commit()
    c.close()
    with Case(p) as c2:
        assert c2.meta()["schema_version"] == str(db.SCHEMA_VERSION)
        assert next(h for h in c2.hosts() if h["name"] == "WS01")["status"] == ""
        c2.update_host(c2.resolve_host("WS01"), status="compromised")


def test_status_in_exports(case, tmp_path):
    case.add_host("RD01", ip="10.0.0.1", os="Windows 11", status="compromised")
    case.add_host("RD02", status="suspicious")
    case.add_host("RD03")
    out = str(tmp_path / "out")
    written = export.export(case, "csv", out)
    hosts_csv = next(p for p in written if p.endswith("_Hosts.csv"))
    text = open(hosts_csv).read()
    assert "Status" in text and "compromised" in text
    comp_csv = next(p for p in written if p.endswith("_CompromisedHosts.csv"))
    comp = open(comp_csv).read()
    assert "RD01" in comp and "RD02" not in comp
    md = export.render_md(case)
    assert "Compromised hosts" in md
    assert "**Confirmed compromised:** `RD01`" in md
    assert "**Suspicious:** `RD02`" in md
    assert "1 of 3 hosts not yet triaged: RD03" in md


def test_expand_collection(case):
    h1 = case.add_host("RD01")
    h2 = case.add_host("RD02")
    h3 = case.add_host("RD03")
    cid = case.add_collection("Lab2 export", host_ids=[h1, h2, h3])
    # RD02 is already covered by hand-registered evidence in this collection
    case.add_evidence("RD02 amcache", collection_id=cid, host_ids=[h2])
    created = case.expand_collection(cid, kind="triage")
    assert [it["host"] for it in created] == ["RD01", "RD03"]
    ev = {e["label"]: e for e in case.evidence()}
    assert "Lab2 export — RD01" in ev and "Lab2 export — RD03" in ev
    item = ev["Lab2 export — RD01"]
    assert item["kind"] == "triage"
    assert item["collection_id"] == cid
    assert [h["name"] for h in item["hosts"]] == ["RD01"]
    # idempotent: nothing left to create
    assert case.expand_collection(cid) == []


def test_coverage(case):
    h1 = case.add_host("RD01", status="compromised")
    h2 = case.add_host("RD02")
    e1 = case.add_evidence("RD01 triage", host_ids=[h1])
    a1 = case.add_action("amcache.py rd01", tool="amcache.py",
                         evidence_id=e1, host_ids=[h1])
    case.add_action(method="manual", tool="Timeline Explorer",
                    procedure="filtered on .exe", host_ids=[h1])
    case.add_finding("evil.exe in amcache", action_id=a1, host_ids=[h1])
    cov = case.coverage()
    assert set(cov["tools"]) == {"amcache.py", "Timeline Explorer"}
    by_name = {h["name"]: h for h in cov["hosts"]}
    rd01 = by_name["RD01"]
    assert (rd01["evidence"], rd01["actions"], rd01["findings"]) == (1, 2, 1)
    assert rd01["status"] == "compromised"
    assert rd01["tools"] == {"amcache.py": 1, "Timeline Explorer": 1}
    assert rd01["last_examined"]
    rd02 = by_name["RD02"]
    assert (rd02["evidence"], rd02["actions"], rd02["findings"]) == (0, 0, 0)
    assert rd02["last_examined"] == ""
    # soft-deleted hosts drop out of coverage entirely
    case.soft_delete_host(h2)
    assert [h["name"] for h in case.coverage()["hosts"]] == ["RD01"]


def test_cli_status_expand_coverage(tmp_path, monkeypatch, capsys):
    # redirect the active-case file BEFORE init, or `vera init` writes the real
    # ~/.config/vera/active and repoints the user's active case to a temp file
    monkeypatch.setattr("vera.cli.ACTIVE_FILE", str(tmp_path / "active"))
    monkeypatch.setattr("vera.cli.CONFIG_DIR", str(tmp_path))
    monkeypatch.setenv("VERA_CASE", str(tmp_path / "cli9.vera"))
    assert main(["init", str(tmp_path / "cli9.vera"), "--name", "t"]) == 0
    assert main(["host", "add", "RD01", "RD02", "--status", "unknown"]) == 0
    assert main(["host", "edit", "RD01", "--status", "compromised"]) == 0
    capsys.readouterr()
    assert main(["host", "list"]) == 0
    assert "COMPROMISED" in capsys.readouterr().out
    assert main(["collection", "add", "Lab2", "--hosts", "RD01,RD02"]) == 0
    capsys.readouterr()
    assert main(["collection", "expand", "C1", "--kind", "triage"]) == 0
    out = capsys.readouterr().out
    assert "2 evidence item(s) created" in out
    assert main(["run", "amcache.py rd01", "--evidence", "Lab2 — RD01"]) == 0
    capsys.readouterr()
    assert main(["coverage"]) == 0
    out = capsys.readouterr().out
    assert "RD01" in out and "never" in out
    assert "1 of 2 host(s) have no analysis logged yet" in out


def test_api_coverage_and_expand(running_server):
    port = running_server
    status, raw = _req(port, "POST", "/api/hosts",
                       {"names": ["RD01", "RD02"], "status": "suspicious"})
    assert status == 201
    ids = json.loads(raw)["ids"]
    status, raw = _req(port, "POST", "/api/collections",
                       {"name": "Lab2 export", "host_ids": ids})
    assert status == 201
    cid = json.loads(raw)["id"]
    status, raw = _req(port, "POST", f"/api/collections/{cid}/expand",
                       {"kind": "triage"})
    assert status == 201
    data = json.loads(raw)
    assert data["count"] == 2
    assert {it["host"] for it in data["created"]} == {"RD01", "RD02"}
    # re-running creates nothing (idempotent)
    status, raw = _req(port, "POST", f"/api/collections/{cid}/expand", {})
    assert json.loads(raw)["count"] == 0

    status, raw = _req(port, "GET", "/api/coverage")
    assert status == 200
    cov = json.loads(raw)
    rd01 = next(h for h in cov["hosts"] if h["name"] == "RD01")
    assert rd01["evidence"] == 1 and rd01["actions"] == 0
    assert rd01["status"] == "suspicious"


def test_action_hosts_derive_from_evidence(case):
    h1 = case.add_host("RD01")
    h2 = case.add_host("RD02")
    e = case.add_evidence("triage", host_ids=[h1, h2])
    # no host_ids given -> the step inherits the evidence's source hosts
    a = case.add_action("amcache.py", evidence_id=e)
    assert {h["name"] for h in case.get_action(a)["hosts"]} == {"RD01", "RD02"}
    # explicit host_ids still wins
    a2 = case.add_action("x", evidence_id=e, host_ids=[h1])
    assert [h["name"] for h in case.get_action(a2)["hosts"]] == ["RD01"]
    # no evidence -> no hosts
    a3 = case.add_action("y")
    assert case.get_action(a3)["hosts"] == []


def test_api_action_hosts_follow_evidence(running_server):
    port = running_server
    status, raw = _req(port, "POST", "/api/hosts", {"names": ["RD01", "RD02"]})
    ids = json.loads(raw)["ids"]
    status, raw = _req(port, "POST", "/api/evidence",
                       {"label": "RD01 triage", "host_ids": [ids[0]]})
    e1 = json.loads(raw)["id"]
    status, raw = _req(port, "POST", "/api/evidence",
                       {"label": "RD02 triage", "host_ids": [ids[1]]})
    e2 = json.loads(raw)["id"]
    # POST without host_ids -> hosts come from the evidence
    status, raw = _req(port, "POST", "/api/actions",
                       {"command": "amcache.py", "evidence_id": e1})
    assert status == 201
    aid = json.loads(raw)["id"]
    tree = json.loads(_req(port, "GET", "/api/tree")[1])
    act = next(a for a in tree["roots"] if a["id"] == aid)
    assert [h["name"] for h in act["hosts"]] == ["RD01"]
    # PATCH that re-points the evidence re-syncs the step's hosts
    status, _ = _req(port, "PATCH", f"/api/actions/{aid}",
                     {"command": "amcache.py", "evidence_id": e2})
    assert status == 200
    tree = json.loads(_req(port, "GET", "/api/tree")[1])
    act = next(a for a in tree["roots"] if a["id"] == aid)
    assert [h["name"] for h in act["hosts"]] == ["RD02"]
    # detaching the evidence clears the derived hosts
    status, _ = _req(port, "PATCH", f"/api/actions/{aid}",
                     {"command": "amcache.py", "evidence_id": None})
    assert status == 200
    tree = json.loads(_req(port, "GET", "/api/tree")[1])
    act = next(a for a in tree["roots"] if a["id"] == aid)
    assert act["hosts"] == []


def test_evidence_hosts_derive_from_collection(case):
    hs = [case.add_host(f"RD0{i}") for i in range(1, 4)]
    col = case.add_collection("Lab export", host_ids=hs[:2])
    # db-level inheritance: no host_ids -> the collection's set
    e = case.add_evidence("bundle", collection_id=col)
    assert case.evidence_host_ids(e) == sorted(hs[:2])
    # explicit host_ids (per-host expansion path) still wins
    e2 = case.add_evidence("Lab export — RD01", collection_id=col,
                           host_ids=[hs[0]])
    assert case.evidence_host_ids(e2) == [hs[0]]


def test_collection_host_edits_follow_through(case):
    hs = [case.add_host(f"RD0{i}") for i in range(1, 4)]
    col = case.add_collection("Lab export", host_ids=hs[:2])
    tracking = case.add_evidence("bundle", collection_id=col)         # RD01,RD02
    perhost = case.add_evidence("bundle — RD01", collection_id=col,
                                host_ids=[hs[0]])                     # RD01 only
    step = case.add_action("hayabusa", evidence_id=tracking)          # RD01,RD02
    override = case.add_action("x", evidence_id=tracking, host_ids=[hs[1]])
    f = case.add_finding("hit", action_id=step,
                         host_ids=case.action_host_ids(step))
    # growing the collection flows to tracking evidence and its steps…
    case.set_collection_hosts(col, hs)
    assert case.evidence_host_ids(tracking) == sorted(hs)
    assert case.action_host_ids(step) == sorted(hs)
    # …but deliberate subsets and findings are untouched
    assert case.evidence_host_ids(perhost) == [hs[0]]
    assert case.action_host_ids(override) == [hs[1]]
    assert case.finding_host_ids(f) == sorted(hs[:2])


def test_api_evidence_hosts_collection_rules(running_server):
    port = running_server
    ids = json.loads(_req(port, "POST", "/api/hosts",
                          {"names": ["RD01", "RD02"]})[1])["ids"]
    cid = json.loads(_req(port, "POST", "/api/collections",
                          {"name": "Lab", "host_ids": ids})[1])["id"]
    # POST without host_ids inside a collection -> inherits its hosts
    status, raw = _req(port, "POST", "/api/evidence",
                       {"label": "bundle", "collection_id": cid})
    assert status == 201
    eid = json.loads(raw)["id"]
    info = json.loads(_req(port, "GET", "/api/case")[1])
    ev = next(e for e in info["evidence"] if e["id"] == eid)
    assert {h["name"] for h in ev["hosts"]} == {"RD01", "RD02"}
    # PATCH with the SAME collection leaves hosts alone (per-host items safe)
    status, raw = _req(port, "POST", f"/api/collections/{cid}/expand", {})
    assert json.loads(raw)["count"] == 0  # both hosts covered by 'bundle'? no:
    # (bundle covers both, so expand creates nothing — separately narrow one)
    status, raw = _req(port, "POST", "/api/evidence",
                       {"label": "Lab — RD01", "collection_id": cid,
                        "host_ids": [ids[0]]})
    nid = json.loads(raw)["id"]
    status, _ = _req(port, "PATCH", f"/api/evidence/{nid}",
                     {"label": "Lab — RD01 (renamed)", "collection_id": cid})
    assert status == 200
    info = json.loads(_req(port, "GET", "/api/case")[1])
    ev = next(e for e in info["evidence"] if e["id"] == nid)
    assert [h["name"] for h in ev["hosts"]] == ["RD01"]
    # PATCH that moves evidence into a collection re-derives from it
    status, raw = _req(port, "POST", "/api/evidence", {"label": "loose"})
    lid = json.loads(raw)["id"]
    status, _ = _req(port, "PATCH", f"/api/evidence/{lid}",
                     {"collection_id": cid})
    assert status == 200
    info = json.loads(_req(port, "GET", "/api/case")[1])
    ev = next(e for e in info["evidence"] if e["id"] == lid)
    assert {h["name"] for h in ev["hosts"]} == {"RD01", "RD02"}


# ---- artifact stacking (host indicators by name, regardless of path) ----

def test_artifact_name_derived_from_path(case):
    # a bare --path fills the stackable artifact name from the basename
    fid = case.add_finding("forwarded import", ftype="hostindicator",
                           attrs={"artifact_type": "dll",
                                  "path": r"C:\Users\nromanoff\AppData\Local\slack\CRYPTBASE.dll"})
    f = case.get_finding(fid)
    assert f["attrs"]["artifact"] == "CRYPTBASE.dll"
    assert f["attrs"]["path"].endswith(r"slack\CRYPTBASE.dll")
    # an explicit name is never overwritten by the path basename
    fid2 = case.add_finding("x", ftype="hostindicator",
                            attrs={"artifact": "evil.dll", "path": r"C:\a\other.dll"})
    assert case.get_finding(fid2)["attrs"]["artifact"] == "evil.dll"
    # update_finding derives too, using the stored ftype
    case.update_finding(fid2, attrs={"artifact": "", "path": r"D:\x\three.dll"})
    assert case.get_finding(fid2)["attrs"]["artifact"] == "three.dll"


def test_artifact_stacks(case):
    for h in ("RD04", "RD09", "RD01"):
        case.add_host(h)
    a = case.add_action("dllsearch")
    # same name CRYPTBASE.dll, different paths + hosts -> one stack of 2
    case.add_finding("import RD04", ftype="hostindicator", action_id=a,
                     host_ids=[case.resolve_host("RD04")],
                     attrs={"artifact_type": "dll",
                            "path": r"C:\Users\a\AppData\Local\slack\CRYPTBASE.dll"})
    case.add_finding("import RD09", ftype="hostindicator", action_id=a,
                     host_ids=[case.resolve_host("RD09")],
                     attrs={"artifact_type": "dll",
                            "path": r"C:\Users\b\AppData\Local\teams\cryptbase.dll"})
    case.add_finding("task RD01", ftype="hostindicator", action_id=a,
                     host_ids=[case.resolve_host("RD01")],
                     attrs={"artifact_type": "sched", "path": r"c:\windows\stun.exe"})
    groups = case.artifact_stacks()
    assert [g["name"] for g in groups][0] == "CRYPTBASE.dll"  # most-spread first
    top = groups[0]
    assert top["count"] == 2 and top["host_count"] == 2
    assert {h["name"] for h in top["hosts"]} == {"RD04", "RD09"}
    assert len(top["paths"]) == 2  # both distinct full paths retained
    assert top["artifact_types"] == ["dll"]
    stun = next(g for g in groups if g["name"] == "stun.exe")
    assert stun["count"] == 1


def test_migration_v9_to_v10_splits_artifact_path(tmp_path):
    p = str(tmp_path / "v9.vera")
    c = Case(p, create=True)
    # simulate a pre-v10 host indicator: full path jammed into 'artifact'
    fid = c.add_finding("forwarded import", ftype="hostindicator",
                        attrs={"artifact_type": "dll"})
    c.conn.execute(
        "UPDATE findings SET attrs = ? WHERE id = ?",
        (json.dumps({"artifact_type": "dll",
                     "artifact": r"C:\Users\x\AppData\Local\slack\CRYPTBASE.dll"}), fid))
    # a bare-name artifact must be left untouched by the migration
    fid2 = c.add_finding("bat", ftype="hostindicator",
                         attrs={"artifact": "installoffice2019.bat"})
    c.conn.execute("UPDATE case_meta SET value='9' WHERE key='schema_version'")
    c.conn.commit()
    c.close()
    with Case(p) as c2:
        assert c2.meta()["schema_version"] == str(db.SCHEMA_VERSION)
        f = c2.get_finding(fid)
        assert f["attrs"]["artifact"] == "CRYPTBASE.dll"
        assert f["attrs"]["path"].endswith(r"slack\CRYPTBASE.dll")
        f2 = c2.get_finding(fid2)
        assert f2["attrs"]["artifact"] == "installoffice2019.bat"
        assert not f2["attrs"].get("path")


def test_artifact_path_in_exports(case, tmp_path):
    case.add_host("RD04")
    case.add_host("RD09")
    a = case.add_action("dllsearch")
    for h, d in (("RD04", "slack"), ("RD09", "teams")):
        case.add_finding(f"import {h}", ftype="hostindicator", action_id=a,
                         host_ids=[case.resolve_host(h)],
                         attrs={"artifact_type": "dll",
                                "path": rf"C:\Users\u\AppData\Local\{d}\CRYPTBASE.dll"})
    out = str(tmp_path / "out")
    written = export.export(case, "csv", out)
    hbi = next(p for p in written if p.endswith("_HostBasedIndicators.csv"))
    text = open(hbi).read()
    assert "Path" in text and r"slack\CRYPTBASE.dll" in text
    md = export.render_md(case)
    assert "Artifacts by name" in md and "CRYPTBASE.dll" in md


def test_api_artifacts(running_server):
    port = running_server
    # register hosts and add two same-named host indicators on different paths
    for h in ("HXA", "HXB"):
        _req(port, "POST", "/api/hosts", {"name": h})
    info = json.loads(_req(port, "GET", "/api/case")[1])
    ids = {h["name"]: h["id"] for h in info["hosts"]}
    for h, d in (("HXA", "slack"), ("HXB", "teams")):
        _req(port, "POST", "/api/findings",
             {"title": f"imp {h}", "ftype": "hostindicator", "host_ids": [ids[h]],
              "attrs": {"artifact_type": "dll",
                        "path": rf"C:\U\{d}\CRYPTBASE.dll"}})
    status, raw = _req(port, "GET", "/api/artifacts")
    assert status == 200
    groups = json.loads(raw)
    top = groups[0]
    assert top["name"] == "CRYPTBASE.dll"
    assert top["count"] == 2 and top["host_count"] == 2
    assert len(top["paths"]) == 2


def test_cli_artifacts(cli_case, capsys):
    assert main(["host", "add", "RD04"]) == 0
    assert main(["finding", "imp", "-t", "hostindicator", "--on", "none",
                 "--attr", "artifact_type=dll",
                 "--path", r"C:\U\slack\CRYPTBASE.dll", "--hosts", "RD04"]) == 0
    capsys.readouterr()
    assert main(["artifacts"]) == 0
    out = capsys.readouterr().out
    assert "CRYPTBASE.dll" in out and r"C:\U\slack\CRYPTBASE.dll" in out


# ---- leads (triage worklists) ------------------------------------------

def test_lead_items_crud_and_counts(case):
    a = case.add_action("sweep", method="manual", tool="TLE",
                        procedure="pull LFO==1")
    lead = case.add_finding("LFO autoruns across workstations", ftype="lead",
                            action_id=a, detail="narrator.exe\ngadget.js")
    real = case.add_finding("narrator.exe WMI", ftype="hostindicator",
                            action_id=a, attrs={"artifact": "narrator.exe"})
    i1 = case.add_lead_item(lead, "narrator.exe", finding_id=real)
    i2 = case.add_lead_item(lead, "gadget.js")
    i3 = case.add_lead_item(lead, "stun.exe")
    # linking a finding auto-resolves the item
    L = case.leads()[0]
    assert L["item_total"] == 3 and L["item_resolved"] == 1
    items = {it["label"]: it for it in L["items"]}
    assert items["narrator.exe"]["status"] == "triaged"
    assert items["narrator.exe"]["finding"]["id"] == real
    # update status + link on an open item
    case.update_lead_item(i2, finding_id=real)
    assert case.leads()[0]["item_resolved"] == 2
    case.update_lead_item(i3, status="dismissed")
    assert case.leads()[0]["item_resolved"] == 3
    # soft-delete never purges but drops from the worklist
    case.soft_delete_lead_item(i2)
    L = case.leads()[0]
    assert L["item_total"] == 2
    row = case.conn.execute("SELECT deleted_at FROM lead_items WHERE id = ?",
                            (i2,)).fetchone()
    assert row["deleted_at"] != ""
    # bad status rejected
    with pytest.raises(CaseError):
        case.update_lead_item(i1, status="bogus")


def test_leads_excluded_from_stack_and_artifacts(case):
    for h in ("RD01", "RD02"):
        case.add_host(h)
    a = case.add_action("sweep")
    lead = case.add_finding("worklist", ftype="lead", action_id=a,
                            host_ids=[case.resolve_host("RD01"),
                                      case.resolve_host("RD02")])
    case.add_finding("gadget.js", ftype="hostindicator", action_id=a,
                     host_ids=[case.resolve_host("RD01")],
                     attrs={"artifact": "gadget.js", "path": r"c:\x\gadget.js"})
    # lead has 2 hosts but must NOT appear as a cross-host finding
    assert all(f["id"] != lead for f in case.stack_findings())
    # nor as an artifact
    assert all(g["name"] != "worklist" for g in case.artifact_stacks())


def test_migration_v10_to_v11_adds_lead_items(tmp_path):
    p = str(tmp_path / "v10.vera")
    c = Case(p, create=True)
    lead = c.add_finding("worklist", ftype="lead")
    c.conn.execute("DROP TABLE lead_items")
    c.conn.execute("UPDATE case_meta SET value='10' WHERE key='schema_version'")
    c.conn.commit()
    c.close()
    with Case(p) as c2:
        assert c2.meta()["schema_version"] == str(db.SCHEMA_VERSION)
        iid = c2.add_lead_item(lead, "stun.exe")
        assert c2.leads()[0]["items"][0]["label"] == "stun.exe"
        assert iid


def test_api_leads(running_server):
    port = running_server
    # create a lead finding, then manage its worklist via the API
    status, raw = _req(port, "POST", "/api/findings",
                       {"title": "LFO worklist", "ftype": "lead"})
    lead = json.loads(raw)["id"]
    status, raw = _req(port, "POST", f"/api/leads/{lead}/items",
                       {"label": "narrator.exe"})
    assert status == 201
    item = json.loads(raw)["id"]
    status, raw = _req(port, "GET", "/api/leads")
    L = json.loads(raw)[0]
    assert L["item_total"] == 1 and L["item_resolved"] == 0
    status, _ = _req(port, "PATCH", f"/api/lead_items/{item}",
                     {"status": "triaged"})
    assert status == 200
    assert json.loads(_req(port, "GET", "/api/leads")[1])[0]["item_resolved"] == 1
    status, _ = _req(port, "DELETE", f"/api/lead_items/{item}")
    assert status == 200
    assert json.loads(_req(port, "GET", "/api/leads")[1])[0]["item_total"] == 0


def test_cli_lead(cli_case, capsys):
    assert main(["finding", "LFO sweep", "-t", "lead", "--on", "none"]) == 0
    assert main(["finding", "narrator.exe", "-t", "hostindicator", "--on", "none",
                 "--path", r"c:\windows\update\narrator.exe"]) == 0
    capsys.readouterr()
    assert main(["lead", "add", "F1", "narrator.exe", "--finding", "F2"]) == 0
    assert main(["lead", "add", "F1", "stun.exe"]) == 0
    capsys.readouterr()
    assert main(["lead"]) == 0
    out = capsys.readouterr().out
    assert "LFO sweep" in out and "1/2 triaged" in out
    assert "narrator.exe" in out and "→ F2" in out


def test_lead_in_md_export(case):
    a = case.add_action("sweep")
    lead = case.add_finding("LFO worklist", ftype="lead", action_id=a)
    case.add_lead_item(lead, "narrator.exe", status="triaged")
    case.add_lead_item(lead, "stun.exe")
    md = export.render_md(case)
    assert "Leads (triage worklists)" in md
    assert "narrator.exe" in md and "stun.exe" in md


# ---- clone findings ----------------------------------------------------

def test_clone_finding(case):
    case.add_host("RD04")
    a = case.add_action("grep", host_ids=[case.resolve_host("RD04")])
    src = case.add_finding("Run key gadget.js", ftype="hostindicator",
                           action_id=a, event_time="2026-07-01 14:22",
                           attrs={"artifact": "gadget.js", "artifact_type": "Run key",
                                  "path": r"c:\windows\update\gadget.js"},
                           hashes={"md5": "7b0fe68e9a320f814ee956c7121c86b6"},
                           host_ids=[case.resolve_host("RD04")], starred=True)
    new = case.clone_finding(src)
    a_f = {f["id"]: f for f in case.findings("hostindicator")}
    c = a_f[new]
    assert c["id"] != src
    assert c["ftype"] == "hostindicator"
    assert c["action_id"] == a
    assert c["attrs"]["artifact"] == "gadget.js"
    assert c["attrs"]["path"].endswith(r"gadget.js")
    assert c["hashes"]["md5"] == "7b0fe68e9a320f814ee956c7121c86b6"
    assert c["event_time"] == "2026-07-01 14:22"
    assert [h["name"] for h in c["affected_hosts"]] == ["RD04"]
    assert not c["starred"]           # clone starts un-starred
    # override wins
    new2 = case.clone_finding(src, title="Run key narrator.exe")
    assert case.get_finding(new2)["title"] == "Run key narrator.exe"


def test_cli_clone(cli_case, capsys):
    assert main(["finding", "gadget.js", "-t", "hostindicator", "--on", "none",
                 "--path", r"c:\windows\update\gadget.js"]) == 0
    capsys.readouterr()
    assert main(["clone", "F1", "--title", "narrator.exe"]) == 0
    out = capsys.readouterr().out
    assert "cloned from F1" in out
    # the clone exists with the overridden title and copied attrs
    assert main(["show", "F2"]) == 0
    show = capsys.readouterr().out
    assert "narrator.exe" in show and "gadget.js" in show  # title overridden, path copied


def test_clone_action(case):
    case.add_host("RD08")
    e = case.add_evidence("autoruns csvs", host_ids=[case.resolve_host("RD08")])
    a = case.add_action("Select-String gadget.js *.csv", evidence_id=e,
                        notes="find the host", output="rd08 hit\n")
    f = case.add_finding("gadget.js", action_id=a)
    a2 = case.add_action("Select-String stun.exe *.csv", parent_finding_id=f)
    clone = case.clone_action(a2)
    got = case.get_action(clone)
    assert clone != a2
    assert got["command"] == "Select-String stun.exe *.csv"
    assert got["parent_finding_id"] == f     # keeps the drill-down linkage
    # cloning the evidence-bound step copies evidence + derives hosts, not output
    clone1 = case.get_action(case.clone_action(a))
    assert clone1["evidence_id"] == e
    assert [h["name"] for h in clone1["hosts"]] == ["RD08"]
    assert clone1["output"] == ""            # output is a fresh capture, not copied
    assert clone1["notes"] == "find the host"
    # override wins
    clone2 = case.get_action(case.clone_action(a, command="Select-String x *.csv"))
    assert clone2["command"] == "Select-String x *.csv"


def test_cli_clone_action(cli_case, capsys):
    assert main(["run", "Select-String gadget.js *.csv", "--note", "find host"]) == 0
    capsys.readouterr()
    assert main(["clone", "A1"]) == 0
    out = capsys.readouterr().out
    assert "cloned from A1" in out
    assert main(["show", "A2"]) == 0
    show = capsys.readouterr().out
    assert "Select-String gadget.js" in show


# ---- evidence cascade (action -> finding -> follow-up action) ----------

def test_evidence_cascades_through_the_graph(case):
    case.add_host("RD01")
    e = case.add_evidence("autoruns csv", host_ids=[case.resolve_host("RD01")])
    a = case.add_action("sweep", evidence_id=e)
    f = case.add_finding("lead", ftype="lead", action_id=a)
    assert case.get_finding(f)["evidence_id"] == e          # finding <- action
    sub = case.add_action("Select-String x", parent_finding_id=f)
    assert case.get_action(sub)["evidence_id"] == e          # follow-up <- finding
    ff = case.add_finding("narrator.exe", action_id=sub)
    assert case.get_finding(ff)["evidence_id"] == e          # sub-finding <- sub-action
    # explicit evidence overrides the inherited one
    e2 = case.add_evidence("other")
    f2 = case.add_finding("x", action_id=a, evidence_id=e2)
    assert case.get_finding(f2)["evidence_id"] == e2
    # a finding with no action has no evidence
    f3 = case.add_finding("standalone", ftype="note")
    assert case.get_finding(f3)["evidence_id"] is None
    # clone copies the evidence; update can change it
    assert case.get_finding(case.clone_finding(f))["evidence_id"] == e
    case.update_finding(f2, evidence_id=e)
    assert case.get_finding(f2)["evidence_id"] == e
    with pytest.raises(CaseError):
        case.add_finding("bad", action_id=a, evidence_id=999)


def test_migration_v11_to_v12_adds_finding_evidence(tmp_path):
    p = str(tmp_path / "v11.vera")
    c = Case(p, create=True)
    e = c.add_evidence("disk")
    a = c.add_action("x", evidence_id=e)
    on_action = c.add_finding("has action", action_id=a)   # should backfill to e
    standalone = c.add_finding("no action", ftype="note")  # stays NULL
    # roll back to a v11-shaped findings table (no evidence_id column)
    c.conn.execute("ALTER TABLE findings DROP COLUMN evidence_id")
    c.conn.execute("UPDATE case_meta SET value='11' WHERE key='schema_version'")
    c.conn.commit()
    c.close()
    with Case(p) as c2:
        assert c2.meta()["schema_version"] == str(db.SCHEMA_VERSION)
        assert c2.get_finding(on_action)["evidence_id"] == e   # backfilled
        assert c2.get_finding(standalone)["evidence_id"] is None
        # and new work cascades
        f2 = c2.add_finding("y", action_id=a)
        assert c2.get_finding(f2)["evidence_id"] == e


def test_api_finding_evidence(running_server):
    port = running_server
    status, raw = _req(port, "POST", "/api/evidence", {"label": "triage E"})
    eid = json.loads(raw)["id"]
    status, raw = _req(port, "POST", "/api/actions", {"command": "x", "evidence_id": eid})
    aid = json.loads(raw)["id"]
    # a finding on that action inherits the evidence
    status, raw = _req(port, "POST", "/api/findings", {"title": "f", "action_id": aid})
    fid = json.loads(raw)["id"]
    info = json.loads(_req(port, "GET", "/api/tree")[1])
    fin = next(f for a in info["roots"] for f in a["findings"] if f["id"] == fid)
    assert fin["evidence_id"] == eid
    # PATCH can change it
    status, raw = _req(port, "POST", "/api/evidence", {"label": "other E"})
    eid2 = json.loads(raw)["id"]
    status, _ = _req(port, "PATCH", f"/api/findings/{fid}", {"evidence_id": eid2})
    assert status == 200


# ---- filesystem observations (excluded from Artifacts, flippable) ------

def test_filesystem_observations_excluded_from_artifacts(case):
    case.add_host("RD01")
    a = case.add_action("enum")
    fs = case.add_finding("dir", ftype="filesystem", action_id=a,
                          attrs={"artifact_type": "directory",
                                 "path": r"\VOLUME{x}\WINDOWS\UPDATE"})
    assert case.get_finding(fs)["attrs"]["artifact"] == "UPDATE"   # name auto-derives
    case.add_finding("dll", ftype="hostindicator", action_id=a,
                     attrs={"path": r"c:\x\evil.dll"})
    names = [g["name"] for g in case.artifact_stacks()]
    assert "evil.dll" in names and "UPDATE" not in names          # fs stays out
    # flipping the type is lossless and moves it in/out of the stack
    case.update_finding(fs, ftype="hostindicator")
    assert "UPDATE" in [g["name"] for g in case.artifact_stacks()]
    assert case.get_finding(fs)["attrs"]["path"] == r"\VOLUME{x}\WINDOWS\UPDATE"
