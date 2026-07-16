import http.client
import json
import os
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

def test_create_and_reopen(tmp_path):
    p = str(tmp_path / "a.vera")
    Case(p, create=True).close()
    with Case(p) as c:
        assert c.meta()["schema_version"] == "1"
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
