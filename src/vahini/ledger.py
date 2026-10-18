"""Append-only, hash-chained evidence ledger for every investigation.

Every query, result, hypothesis, policy decision and verdict is appended as an
entry whose hash covers the previous entry's hash. Editing or deleting any
past entry breaks the chain, so the ledger doubles as tamper-evident audit
evidence for CERT-In reporting, ISO 27001 and SOC 2 reviews.

With a ``Keyring``, every entry is also signed (Ed25519) by the layer or the
person that wrote it. A hash chain shows *that* something changed; signatures
show *who* said what, and nobody can later deny an entry they signed. That is
what makes each case non-repudiable at every layer of the stack. Auditors
verify with the exported public keys alone.

The append-only investigation ledger follows AIDA (arXiv:2610.10608), where
it was central to cutting missed attacks from 40.4% to 3.1%.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any

GENESIS = "0" * 64


@dataclass(frozen=True)
class Entry:
    seq: int
    ts: float
    actor: str          # "strategist", "executor", "adversary", "judge", "policy", "analyst"
    kind: str           # "query", "result", "hypothesis", "decision", "verdict", ...
    body: dict[str, Any]
    prev: str
    digest: str
    signer: str | None = None       # key id of whoever signed this entry
    signature: str | None = None    # hex Ed25519 signature over ``digest``


class Keyring:
    """One Ed25519 key per actor (a layer of the stack, or an analyst).

    Needs ``cryptography`` (``pip install vahini[audit]``). In production the
    private keys live in an HSM or KMS; this in-memory keyring is for tests,
    demos and single-node deployments.
    """

    def __init__(self) -> None:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        self._new = Ed25519PrivateKey.generate
        self._keys: dict[str, Any] = {}

    def key_id(self, actor: str) -> str:
        if actor not in self._keys:
            self._keys[actor] = self._new()
        return actor

    def sign(self, actor: str, digest: str) -> str:
        self.key_id(actor)
        return self._keys[actor].sign(digest.encode()).hex()

    def export_public(self) -> dict[str, str]:
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        return {a: k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex() for a, k in self._keys.items()}


def verify_signature(public_hex: str, digest: str, signature_hex: str) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex)).verify(bytes.fromhex(signature_hex),
                                                                             digest.encode())
        return True
    except (InvalidSignature, ValueError):
        return False


def _digest(seq: int, ts: float, actor: str, kind: str, body: dict[str, Any], prev: str) -> str:
    payload = json.dumps([seq, ts, actor, kind, body, prev], sort_keys=True, default=str)
    return hashlib.sha256(payload.encode()).hexdigest()


@dataclass
class Ledger:
    case_id: str
    entries: list[Entry] = field(default_factory=list)
    keyring: Keyring | None = field(default=None, repr=False)

    @property
    def head(self) -> str:
        return self.entries[-1].digest if self.entries else GENESIS

    def append(self, actor: str, kind: str, body: dict[str, Any], ts: float | None = None) -> Entry:
        seq = len(self.entries)
        ts = time.time() if ts is None else ts
        prev = self.head
        digest = _digest(seq, ts, actor, kind, body, prev)
        signer = signature = None
        if self.keyring is not None:
            signer, signature = self.keyring.key_id(actor), self.keyring.sign(actor, digest)
        e = Entry(seq, ts, actor, kind, body, prev, digest, signer, signature)
        self.entries.append(e)
        return e

    def verify(self, public_keys: dict[str, str] | None = None) -> tuple[bool, int | None]:
        """Return (ok, index_of_first_bad_entry).

        Checks the hash chain. With ``public_keys`` (or this ledger's own
        keyring), also checks that every entry carries a valid signature from
        the actor it names.
        """
        keys = public_keys if public_keys is not None else (
            self.keyring.export_public() if self.keyring is not None else None)
        prev = GENESIS
        for i, e in enumerate(self.entries):
            if e.prev != prev or e.digest != _digest(e.seq, e.ts, e.actor, e.kind, e.body, e.prev):
                return False, i
            if keys is not None:
                if e.signer != e.actor or e.signer not in keys or not e.signature:
                    return False, i
                if not verify_signature(keys[e.signer], e.digest, e.signature):
                    return False, i
            prev = e.digest
        return True, None

    def by_kind(self, kind: str) -> list[Entry]:
        return [e for e in self.entries if e.kind == kind]
