"""Content-addressed evidence store (``docs/SPEC.md`` §3.4).

Raw proof (responses, records, binary regions) is stored under its SHA-256 so any fact is
independently replayable. The graph keeps only hashes + offsets + derived facts — never a
live secret in plaintext. Secrets are redacted to ``prefix…+sha`` before they can enter an
attribute. ``encrypt_at_rest`` is a flag here (a real deployment wires age/sops/git-crypt);
the point is that the handling path is explicit and labeled.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from .models import EvidenceRef


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def redact(secret: str, keep: int = 4) -> str:
    """Redact a secret/PII value to a non-reversible ``prefix…+sha`` form."""

    secret = secret or ""
    digest = hashlib.sha256(secret.encode("utf-8")).hexdigest()[:16]
    prefix = secret[:keep]
    return f"{prefix}…+{digest}"


class EvidenceStore:
    def __init__(self, root: str | Path = ".recon/evidence", *, encrypt_at_rest: bool = True) -> None:
        self.root = Path(root)
        self.encrypt_at_rest = encrypt_at_rest
        self.root.mkdir(parents=True, exist_ok=True)

    def put(self, raw: bytes, region: str = "") -> EvidenceRef:
        digest = sha256_bytes(raw)
        path = self.root / digest
        if not path.exists():
            # A real deployment encrypts here per sensitivity class before writing.
            path.write_bytes(raw)
        return EvidenceRef(sha256=digest, region=region, encrypted_at_rest=self.encrypt_at_rest)

    def put_text(self, text: str, region: str = "") -> EvidenceRef:
        return self.put(text.encode("utf-8"), region=region)

    def get(self, sha256: str) -> bytes:
        return (self.root / sha256).read_bytes()
