"""Privacy plane: keyed pseudonymisation before any model sees telemetry.

Static masking (every IP -> "IP") destroys correlation; unkeyed hashing can
be reversed by guessing and links unrelated tenants. Vahini instead replaces
identifiers with HMAC-SHA256 tokens under a per-tenant key held only in the
tenant's vault, so:

* the same user / host / IP always maps to the same token inside a tenant,
  so the model can still correlate "one account, three hosts";
* tokens differ across tenants, so an MSSP's customers never link up;
* IPv4 tokens keep their /24 grouping, so "ten hosts in one subnet" survives;
* secrets (keys, bearer tokens, card and ID numbers) are replaced with a typed
  marker and are never reversible, because no model needs the secret itself.

Inspired by SOC Prime's LogTotal sanitizer (2026); see docs/research-basis.md.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass, field

_SECRETS: list[tuple[str, re.Pattern[str]]] = [
    ("aws_access_key", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    # Patterns with a group named "s" replace only that group, keeping the field name.
    ("bearer_token", re.compile(r"(?i)\bbearer (?P<s>[A-Za-z0-9._~+/-]{16,}=*)")),
    ("password", re.compile(r"(?i)\b(?:password|passwd|pwd)[=:] ?(?P<s>[^\s&\"']+)")),
    ("api_key", re.compile(r"(?i)\b(?:x-api-key|api[_-]?key)[=:] ?(?P<s>[A-Za-z0-9._-]{12,})")),
    ("in_pan", re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")),               # Indian PAN card
    # 12-digit Aadhaar shape, not part of a longer digit run
    ("aadhaar", re.compile(r"(?<!\d)(?<!\d )[2-9][0-9]{3} ?[0-9]{4} ?[0-9]{4}(?! ?\d)")),
]
_CARD = re.compile(r"\b\d(?:[ -]?\d){12,18}\b")

_IDENTIFIERS: list[tuple[str, re.Pattern[str]]] = [
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("ip", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")),
    ("winuser", re.compile(r"(?i)(?<=\\users\\)[^\\\s\"]+")),
]

# Structured fields whose whole value is an identifier.
FIELD_KINDS = {"user": "user", "username": "user", "host": "host", "hostname": "host",
               "src_ip": "ip", "dst_ip": "ip", "email": "email"}


def _swap(m: re.Match[str], replacement: str) -> str:
    """Replace group "s" if the pattern has one, else the whole match."""
    if "s" not in m.re.groupindex:
        return replacement
    whole, base = m.group(0), m.start()
    return whole[: m.start("s") - base] + replacement + whole[m.end("s") - base:]


def _luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


@dataclass
class Vault:
    """Tenant-side key and reverse map. Never leaves the tenant boundary."""

    tenant: str
    key: bytes
    reverse: dict[str, str] = field(default_factory=dict)

    def _h(self, kind: str, value: str, n: int = 8) -> str:
        mac = hmac.new(self.key, f"{kind}\x00{value}".encode(), hashlib.sha256).hexdigest()
        return mac[:n]

    def token(self, kind: str, value: str) -> str:
        if kind == "ip":
            prefix = ".".join(value.split(".")[:3])
            tok = f"ip-{self._h('net24', prefix, 4)}-{self._h('ip', value, 4)}"
        else:
            tok = f"{kind}-{self._h(kind, value.lower() if kind in ('email', 'user') else value)}"
        self.reverse[tok] = value
        return tok

    def reveal(self, token: str) -> str | None:
        return self.reverse.get(token)


@dataclass
class Sanitized:
    text: str
    secrets_removed: dict[str, int] = field(default_factory=dict)
    identifiers_tokenised: int = 0


def sanitize_text(text: str, vault: Vault) -> Sanitized:
    out = Sanitized(text)
    s = text

    def _secret(kind: str):
        def repl(m: re.Match[str]) -> str:
            out.secrets_removed[kind] = out.secrets_removed.get(kind, 0) + 1
            return _swap(m, f"[SECRET:{kind}]")
        return repl

    # Cards first, so a 16-digit PAN is not half-eaten by the Aadhaar pattern.
    def _card(m: re.Match[str]) -> str:
        digits = re.sub(r"\D", "", m.group(0))
        if 13 <= len(digits) <= 19 and _luhn_ok(digits):
            out.secrets_removed["card_number"] = out.secrets_removed.get("card_number", 0) + 1
            return "[SECRET:card_number]"
        return m.group(0)

    s = _CARD.sub(_card, s)

    for kind, rx in _SECRETS:
        s = rx.sub(_secret(kind), s)

    for kind, rx in _IDENTIFIERS:
        def _ident(m: re.Match[str], kind: str = "user" if kind == "winuser" else kind) -> str:
            out.identifiers_tokenised += 1
            value = m.group("s") if "s" in m.re.groupindex else m.group(0)
            return _swap(m, vault.token(kind, value))
        s = rx.sub(_ident, s)

    out.text = s
    return out


def sanitize_alert(alert: dict, vault: Vault) -> tuple[dict, dict[str, int]]:
    """Pseudonymise a whole alert. Returns (clean_alert, secrets_removed)."""
    clean: dict = {}
    removed: dict[str, int] = {}
    # Identifiers known from structured fields are also replaced wherever they
    # appear in free text ("52 failed logins for ravi.k").
    known = {v: vault.token(FIELD_KINDS[k], v) for k, v in alert.items()
             if k in FIELD_KINDS and isinstance(v, str) and v}
    lower = {k.lower(): t for k, t in known.items()}
    known_rx = (re.compile("|".join(re.escape(x) for x in sorted(known, key=len, reverse=True)), re.IGNORECASE)
                if known else None)
    for k, v in alert.items():
        if k in FIELD_KINDS and isinstance(v, str) and v:
            clean[k] = known[v]
        elif isinstance(v, str):
            if known_rx is not None:
                v = known_rx.sub(lambda m: lower[m.group(0).lower()], v)
            r = sanitize_text(v, vault)
            clean[k] = r.text
            for kind, n in r.secrets_removed.items():
                removed[kind] = removed.get(kind, 0) + n
        else:
            clean[k] = v
    return clean, removed
