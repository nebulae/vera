import http.client
import json
import os
import sqlite3
import threading

import pytest

from vera import db, export, types
from vera.cli import main
from vera.db import Case, CaseError


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
