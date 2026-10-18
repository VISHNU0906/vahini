"""Append-only ledger storage on SQLite.

Triggers refuse UPDATE and DELETE, so the database itself enforces what the
hash chain and signatures already prove: entries are only ever added.
Swap for Postgres or an object store with retention lock in production.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from ..ledger import Entry, Ledger

SCHEMA = """
CREATE TABLE IF NOT EXISTS ledger_entries (
    case_id   TEXT    NOT NULL,
    seq       INTEGER NOT NULL,
    ts        TEXT    NOT NULL,   -- JSON, so the value hashes exactly as written
    actor     TEXT    NOT NULL,
    kind      TEXT    NOT NULL,
    body      TEXT    NOT NULL,
    prev      TEXT    NOT NULL,
    digest    TEXT    NOT NULL,
    signer    TEXT,
    signature TEXT,
    PRIMARY KEY (case_id, seq)
);
CREATE TRIGGER IF NOT EXISTS ledger_no_update BEFORE UPDATE ON ledger_entries
BEGIN SELECT RAISE(ABORT, 'ledger is append-only'); END;
CREATE TRIGGER IF NOT EXISTS ledger_no_delete BEFORE DELETE ON ledger_entries
BEGIN SELECT RAISE(ABORT, 'ledger is append-only'); END;
"""


class LedgerStore:
    def __init__(self, path: str | Path = ":memory:") -> None:
        self.db = sqlite3.connect(str(path))
        self.db.executescript(SCHEMA)

    def save(self, ledger: Ledger) -> int:
        """Write entries not yet stored. Returns how many were added."""
        have = self.db.execute("SELECT COALESCE(MAX(seq), -1) FROM ledger_entries WHERE case_id = ?",
                               (ledger.case_id,)).fetchone()[0]
        new = [e for e in ledger.entries if e.seq > have]
        self.db.executemany(
            "INSERT INTO ledger_entries VALUES (?,?,?,?,?,?,?,?,?,?)",
            [(ledger.case_id, e.seq, json.dumps(e.ts), e.actor, e.kind, json.dumps(e.body, sort_keys=True, default=str),
              e.prev, e.digest, e.signer, e.signature) for e in new])
        self.db.commit()
        return len(new)

    def load(self, case_id: str) -> Ledger:
        rows = self.db.execute("SELECT seq, ts, actor, kind, body, prev, digest, signer, signature "
                               "FROM ledger_entries WHERE case_id = ? ORDER BY seq", (case_id,)).fetchall()
        return Ledger(case_id, [Entry(r[0], json.loads(r[1]), r[2], r[3], json.loads(r[4]), r[5], r[6], r[7], r[8])
                                for r in rows])

    def cases(self) -> list[str]:
        return [r[0] for r in self.db.execute("SELECT DISTINCT case_id FROM ledger_entries ORDER BY case_id")]
