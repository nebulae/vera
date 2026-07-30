"""Case export bundles: a chain-of-custody package.

Layout (zip → hash → zip):
    <case>-<UTCdate>.bundle.zip        (outer)
      ├─ <case>.inner.zip              the sealed payload (case + reports [+ evidence])
      ├─ MANIFEST.json                 per-file hashes + the inner-zip hash
      └─ RECEIPT.txt                   the same, human-readable

The manifest lives OUTSIDE the sealed inner archive, so anyone can recompute
the inner zip's SHA-256 and confirm it matches without trusting the transport.

Signing is deferred to a later phase: the manifest already carries `signed`
and `signature` fields (false / null here) so a signed bundle is the same
format with those populated. Everything here is stdlib-only.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import io
import json
import os
import shutil
import tempfile
import zipfile

from . import export
from .db import Case, CaseError

MANIFEST_NAME = "MANIFEST.json"
RECEIPT_NAME = "RECEIPT.txt"


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _utc_now() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def _zip_dir(src_dir: str, zip_path: str) -> None:
    """Zip a directory's contents (relative paths), sorted for stability."""
    files = []
    for root, _dirs, names in os.walk(src_dir):
        for n in sorted(names):
            full = os.path.join(root, n)
            files.append((full, os.path.relpath(full, src_dir)))
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for full, rel in sorted(files, key=lambda t: t[1]):
            zf.write(full, rel)


def _gather_evidence(case: Case, src_dir: str, dest_dir: str) -> list[dict]:
    """Copy raw evidence files whose recorded SHA-256 matches a file in
    `src_dir` into `dest_dir/`, verifying each hash. Returns a per-item status
    list (found / missing / mismatch) for the receipt — never silently drops."""
    # hash every file in src_dir once, map digest -> path
    by_hash: dict[str, str] = {}
    for root, _dirs, names in os.walk(src_dir):
        for n in names:
            p = os.path.join(root, n)
            try:
                by_hash.setdefault(_sha256_file(p), p)
            except OSError:
                continue
    os.makedirs(dest_dir, exist_ok=True)
    status = []
    for e in case.evidence():
        sha = (e.get("sha256") or "").strip().lower()
        label = e.get("label", "")
        if not sha:
            status.append({"evidence": f"E{e['id']}", "label": label,
                           "result": "no-hash-recorded"})
            continue
        match = by_hash.get(sha)
        if match:
            name = f"E{e['id']}_{os.path.basename(match)}"
            shutil.copy2(match, os.path.join(dest_dir, name))
            status.append({"evidence": f"E{e['id']}", "label": label,
                           "file": name, "sha256": sha, "result": "included"})
        else:
            status.append({"evidence": f"E{e['id']}", "label": label,
                           "sha256": sha, "result": "not-found-in-dir"})
    return status


def _signable(manifest: dict) -> dict:
    """The part of the manifest that a signature covers — everything except the
    signature fields themselves. Reconstructed identically at verify time."""
    return {k: v for k, v in manifest.items()
            if k not in ("signed", "signature")}


def build_bundle(case: Case, out_dir: str,
                 include_evidence_dir: str | None = None,
                 signer=None) -> tuple[str, dict]:
    """Build a chain-of-custody bundle for `case`. Returns (bundle_path,
    manifest). If `signer` is given, the manifest is Ed25519-signed. Appends an
    export record to the LIVE case afterwards."""
    from . import __version__
    os.makedirs(out_dir, exist_ok=True)
    case.checkpoint()  # fold WAL so the copied .vera is complete
    stem = os.path.splitext(os.path.basename(case.path))[0]
    now = _utc_now()
    date_tag = now.strftime("%Y%m%dT%H%M%SZ")

    with tempfile.TemporaryDirectory() as work:
        payload = os.path.join(work, "payload")
        os.makedirs(payload)
        # 1) the case file itself
        shutil.copy2(case.path, os.path.join(payload, f"{stem}.vera"))
        # 2) rendered reports (open-it AND read-it)
        export.export(case, "md", payload)
        export.export(case, "csv", payload)
        export.export(case, "json", payload)
        # 3) optional raw evidence, verified by hash
        evidence_status = []
        if include_evidence_dir:
            evidence_status = _gather_evidence(
                case, include_evidence_dir, os.path.join(payload, "evidence"))

        # inner zip + its hash
        inner_name = f"{stem}.inner.zip"
        inner_path = os.path.join(work, inner_name)
        _zip_dir(payload, inner_path)
        inner_sha = _sha256_file(inner_path)

        # per-file hashes (of the payload, for granular verification)
        file_hashes = []
        for root, _dirs, names in os.walk(payload):
            for n in sorted(names):
                full = os.path.join(root, n)
                file_hashes.append({"name": os.path.relpath(full, payload),
                                    "sha256": _sha256_file(full)})
        file_hashes.sort(key=lambda d: d["name"])

        manifest = {
            "format": "vera-bundle/1",
            "vera_version": __version__,
            "schema": case.conn.execute(
                "SELECT value FROM case_meta WHERE key='schema_version'"
            ).fetchone()["value"],
            "case_name": case.meta().get("name", ""),
            "case_file": f"{stem}.vera",
            "exported_at": now.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "exported_by": case.actor or "(cli)",
            "include_evidence": bool(include_evidence_dir),
            "evidence_status": evidence_status,
            "inner_zip": {"name": inner_name, "sha256": inner_sha},
            "files": file_hashes,
            # signed below when a signer is supplied; unsigned bundles say so
            "signed": False,
            "signature": None,
        }
        if signer is not None:
            manifest["signature"] = signer.signature_block(_signable(manifest))
            manifest["signed"] = True
        manifest_bytes = json.dumps(manifest, indent=2).encode()
        receipt = _receipt_text(manifest)

        # outer zip
        bundle_name = f"{stem}-{date_tag}.bundle.zip"
        bundle_path = os.path.join(out_dir, bundle_name)
        with zipfile.ZipFile(bundle_path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.write(inner_path, inner_name)
            zf.writestr(MANIFEST_NAME, manifest_bytes)
            zf.writestr(RECEIPT_NAME, receipt)
        bundle_sha = _sha256_file(bundle_path)

    # record on the live case (master ledger) — after sealing, so the hash is real
    case.record_export("bundle", inner_sha256=inner_sha,
                       bundle_sha256=bundle_sha,
                       include_evidence=bool(include_evidence_dir),
                       manifest=manifest)
    return bundle_path, manifest


def _receipt_text(m: dict) -> str:
    signed = ("yes" if m["signed"] else
              "NO — integrity only, origin not cryptographically proven")
    lines = [
        "vera case export — chain of custody receipt",
        "=" * 44,
        f"Case:         {m['case_name']}  ({m['case_file']})",
        f"Exported at:  {m['exported_at']}",
        f"Exported by:  {m['exported_by']}",
        f"vera version: {m['vera_version']}   schema {m['schema']}",
        f"Signed:       {signed}",
        "",
        f"Inner archive ({m['inner_zip']['name']}):",
        f"  sha256 {m['inner_zip']['sha256']}",
        "",
        "Payload files:",
    ]
    for f in m["files"]:
        lines.append(f"  {f['sha256'][:16]}…  {f['name']}")
    if m["include_evidence"]:
        lines += ["", "Raw evidence inclusion:"]
        for s in m["evidence_status"]:
            lines.append(f"  {s['evidence']} [{s['result']}] {s.get('label','')}")
    else:
        lines += ["", "Raw evidence: referenced by hash only (not included)."]
    lines += ["", "Verify with:  vera verify <this-bundle>.zip"]
    return "\n".join(lines) + "\n"


def verify_bundle(bundle_path: str) -> dict:
    """Recompute hashes against the manifest. Returns
    {ok, signed, checks:[{name, ok, expected, actual}], problems:[...]}."""
    if not os.path.exists(bundle_path):
        raise CaseError(f"bundle not found: {bundle_path}")
    checks, problems = [], []
    with zipfile.ZipFile(bundle_path, "r") as zf:
        names = set(zf.namelist())
        if MANIFEST_NAME not in names:
            raise CaseError("not a vera bundle: no MANIFEST.json")
        manifest = json.loads(zf.read(MANIFEST_NAME))
        inner = manifest.get("inner_zip", {})
        inner_name = inner.get("name")
        # 1) the inner archive matches its recorded hash
        if inner_name not in names:
            problems.append(f"inner archive {inner_name} missing from bundle")
        else:
            actual = _sha256_bytes(zf.read(inner_name))
            ok = actual == inner.get("sha256")
            checks.append({"name": inner_name, "ok": ok,
                           "expected": inner.get("sha256"), "actual": actual})
            if not ok:
                problems.append(f"inner archive hash mismatch ({inner_name})")
            # 2) each payload file inside the inner archive matches
            else:
                with zipfile.ZipFile(io.BytesIO(zf.read(inner_name))) as inz:
                    inner_names = set(inz.namelist())
                    for f in manifest.get("files", []):
                        if f["name"] not in inner_names:
                            problems.append(f"payload file missing: {f['name']}")
                            checks.append({"name": f["name"], "ok": False,
                                           "expected": f["sha256"],
                                           "actual": None})
                            continue
                        a = _sha256_bytes(inz.read(f["name"]))
                        ok = a == f["sha256"]
                        checks.append({"name": f["name"], "ok": ok,
                                       "expected": f["sha256"], "actual": a})
                        if not ok:
                            problems.append(f"payload file altered: {f['name']}")
    # signature (origin proof) — only when the bundle claims to be signed
    signature = None
    if manifest.get("signed"):
        from . import signing
        block = manifest.get("signature") or {}
        if not signing.available():
            signature = {"ok": None, "server_id": block.get("server_id", ""),
                         "server_label": block.get("server_label", ""),
                         "note": "install vera[provenance] to verify signatures"}
        else:
            signature = signing.verify_signature_block(block, _signable(manifest))
            if not signature["ok"]:
                problems.append("signature does not verify (origin unproven)")
    return {"ok": not problems, "signed": bool(manifest.get("signed")),
            "signature": signature, "manifest": manifest,
            "checks": checks, "problems": problems}


def extract_case(bundle_path: str, out_dir: str) -> tuple[str, dict]:
    """Verify a bundle and extract its `.vera` into `out_dir`. Returns
    (vera_path, verify_result). Refuses to extract a tampered bundle."""
    res = verify_bundle(bundle_path)
    if not res["ok"]:
        raise CaseError("refusing to import a bundle that fails verification: "
                        + "; ".join(res["problems"]))
    os.makedirs(out_dir, exist_ok=True)
    case_file = res["manifest"].get("case_file", "case.vera")
    with zipfile.ZipFile(bundle_path) as zf:
        inner_name = res["manifest"]["inner_zip"]["name"]
        with zipfile.ZipFile(io.BytesIO(zf.read(inner_name))) as inz:
            data = inz.read(case_file)
    dest = os.path.join(out_dir, os.path.basename(case_file))
    if os.path.exists(dest):
        raise CaseError(f"{dest} already exists — move it aside first")
    with open(dest, "wb") as fh:
        fh.write(data)
    return dest, res
