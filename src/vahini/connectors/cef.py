"""ArcSight Common Event Format (CEF) lines to Vahini alerts.

``CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension``
Header fields escape ``|`` and ``\\``; extension values escape ``=`` and ``\\``.
Most firewalls, proxies and EDRs can emit CEF over syslog.
"""

from __future__ import annotations

import re
from typing import Any

from .common import category_from_text, clean

_EXT = re.compile(r"(\w+)=((?:\\=|[^=])*?)(?=\s\w+=|$)")


def _split_header(line: str) -> list[str]:
    parts, buf, esc = [], [], False
    for i, ch in enumerate(line):
        if len(parts) == 7:                 # header done: the extension keeps its own escaping
            return parts + [line[i:]]
        if esc:
            buf.append(ch)
            esc = False
        elif ch == "\\":
            esc = True
        elif ch == "|" and len(parts) < 7:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    parts.append("".join(buf))
    return parts


def parse(line: str) -> dict[str, Any] | None:
    start = line.find("CEF:")
    if start < 0:
        return None
    fields = _split_header(line[start + 4:])
    if len(fields) < 8:
        return None
    version, vendor, product, dev_version, sig, name, sev, ext = fields[:8]
    extension = {k: v.replace("\\=", "=").replace("\\\\", "\\").strip() for k, v in _EXT.findall(ext)}
    return {"vendor": vendor, "product": product, "signature": sig, "name": name, "severity": sev,
            "ext": extension}


def cef_severity(raw: str) -> str:
    """CEF scale: 0-3 low, 4-6 medium, 7-8 high, 9-10 very high. Words (Low/High) are allowed too."""
    if raw.strip().isdigit():
        n = int(raw)
        return "low" if n <= 3 else "medium" if n <= 6 else "high" if n <= 8 else "critical"
    return {"low": "low", "medium": "medium", "high": "high", "very-high": "critical"}.get(raw.strip().lower(), "medium")


def from_cef(line: str) -> dict[str, Any] | None:
    ev = parse(line)
    if ev is None:
        return None
    x = ev["ext"]
    try:
        ts = float(x.get("rt", 0)) / 1000 if str(x.get("rt", "")).isdigit() else 0.0
    except ValueError:
        ts = 0.0
    return clean({
        "id": x.get("externalId") or f"cef-{ev['signature']}-{x.get('rt', '')}",
        "ts": ts,
        "source": f"cef:{ev['vendor']}/{ev['product']}",
        "rule_id": ev["signature"],
        "category": category_from_text(ev["name"], x.get("cat")),
        "severity": cef_severity(ev["severity"]),
        "host": x.get("dhost") or x.get("shost"),
        "src_ip": x.get("src"),
        "dst_ip": x.get("dst"),
        "user": x.get("suser") or x.get("duser"),
        "description": ev["name"],
        "message": x.get("msg"),
        "user_agent": x.get("requestClientApplication"),
    })
