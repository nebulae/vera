"""Optional Ed25519 provenance signing.

This module imports cleanly WITHOUT the `cryptography` library — core vera stays
zero-dependency. Signing/verifying is available only when the `provenance` extra
is installed (`pip install vera[provenance]`); `available()` reports which.

The server identity is an Ed25519 keypair. The private key never leaves the
server (a 0600 key file); the `server_id` is the SHA-256 fingerprint of the
public key, so the id is unforgeable by construction — you cannot claim an id
without holding its matching private key. A signed bundle carries the public
key and signature, so anyone can verify origin + integrity offline, with no
ability to forge (verification material ≠ signing material).
"""

from __future__ import annotations

import hashlib
import json

try:  # the whole crypto surface is optional
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey, Ed25519PublicKey)
    _HAVE = True
except Exception:  # pragma: no cover - exercised only without the extra
    _HAVE = False

ALGO = "ed25519"


def available() -> bool:
    """True when signing/verification is supported (the extra is installed)."""
    return _HAVE


class SigningUnavailable(Exception):
    """Raised if a signing/verify operation is attempted without the extra."""


def _require() -> None:
    if not _HAVE:
        raise SigningUnavailable(
            "signing needs the provenance extra: pip install vera[provenance]")


def generate_keypair() -> tuple[str, str]:
    """Return (private_pem, public_pem) as PEM strings."""
    _require()
    priv = Ed25519PrivateKey.generate()
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()).decode()
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return priv_pem, pub_pem


def fingerprint(public_pem: str) -> str:
    """server_id: sha256 of the DER public key, first 32 hex chars."""
    if _HAVE:
        pub = serialization.load_pem_public_key(public_pem.encode())
        der = pub.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)
    else:  # deterministic fallback so ids stay stable if the lib appears later
        der = public_pem.encode()
    return hashlib.sha256(der).hexdigest()[:32]


def sign(private_pem: str, data: bytes) -> str:
    _require()
    priv = serialization.load_pem_private_key(private_pem.encode(),
                                              password=None)
    return priv.sign(data).hex()


def verify(public_pem: str, data: bytes, signature_hex: str) -> bool:
    _require()
    try:
        pub = serialization.load_pem_public_key(public_pem.encode())
        pub.verify(bytes.fromhex(signature_hex), data)
        return True
    except Exception:
        return False


def canonical(obj: dict) -> bytes:
    """Stable byte form of a dict for signing/verification."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


class Signer:
    """Binds a server identity to signing. `sign_manifest` returns the
    signature block to embed in a bundle manifest."""

    def __init__(self, server_id: str, label: str, public_pem: str,
                 private_pem: str):
        self.server_id = server_id
        self.label = label
        self.public_pem = public_pem
        self._private_pem = private_pem

    def sign_bytes(self, data: bytes) -> str:
        return sign(self._private_pem, data)

    def signature_block(self, signable: dict) -> dict:
        return {"algo": ALGO, "server_id": self.server_id,
                "server_label": self.label, "public_key": self.public_pem,
                "signature": self.sign_bytes(canonical(signable))}


def verify_signature_block(block: dict, signable: dict) -> dict:
    """Check a bundle's signature block against the signed content. Returns
    {ok, server_id, server_label, fingerprint_ok}."""
    pub = block.get("public_key", "")
    sig = block.get("signature", "")
    claimed = block.get("server_id", "")
    # the id must be the fingerprint of the very key that signed — this is what
    # stops someone pasting a trusted id onto their own key
    fp_ok = bool(pub) and fingerprint(pub) == claimed
    sig_ok = bool(pub) and verify(pub, canonical(signable), sig)
    return {"ok": fp_ok and sig_ok, "server_id": claimed,
            "server_label": block.get("server_label", ""),
            "fingerprint_ok": fp_ok, "signature_ok": sig_ok}
