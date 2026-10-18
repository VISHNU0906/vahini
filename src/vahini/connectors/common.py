"""Shared normalisation for every connector: tactics, severities, field lookup."""

from __future__ import annotations

import re
from typing import Any

_CAMEL = re.compile(r"(?<!^)(?=[A-Z])")

TACTIC_ALIASES = {
    "credential-access": "credential-access", "credentialaccess": "credential-access",
    "initial-access": "initial-access", "initialaccess": "initial-access",
    "privilege-escalation": "privilege-escalation", "privilegeescalation": "privilege-escalation",
    "defense-evasion": "defense-evasion", "defenseevasion": "defense-evasion",
    "lateral-movement": "lateral-movement", "lateralmovement": "lateral-movement",
    "command-and-control": "command-and-control", "commandandcontrol": "command-and-control",
}


def tactic(value: str | None) -> str | None:
    """'Credential Access', 'CredentialAccess', 'credential_access' -> 'credential-access'."""
    if not value:
        return None
    v = value.strip()
    if " " not in v and "_" not in v and "-" not in v:
        v = _CAMEL.sub(" ", v)
    v = re.sub(r"[\s_]+", "-", v).lower()
    return TACTIC_ALIASES.get(v.replace("-", ""), v)


SEVERITY_WORDS = {
    "informational": "low", "info": "low", "low": "low",
    "medium": "medium", "moderate": "medium",
    "high": "high", "critical": "critical", "urgent": "critical",
}


def severity(value: Any, scale: int = 10) -> str:
    """Accept words ('High') or numbers on a 0..scale range."""
    if isinstance(value, str) and not value.strip().isdigit():
        return SEVERITY_WORDS.get(value.strip().lower(), "medium")
    try:
        n = float(value) / scale
    except (TypeError, ValueError):
        return "medium"
    return "critical" if n >= 0.8 else "high" if n >= 0.55 else "medium" if n >= 0.3 else "low"


def get(doc: dict[str, Any], dotted: str, default: Any = None) -> Any:
    """Read 'a.b.c' from nested dicts or from a flat dict with dotted keys (ECS style)."""
    if dotted in doc:
        return doc[dotted]
    cur: Any = doc
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


def first(value: Any) -> Any:
    return value[0] if isinstance(value, list) and value else value


def clean(alert: dict[str, Any]) -> dict[str, Any]:
    user = alert.get("user")
    if isinstance(user, str) and "\\" in user:
        alert["user"] = user.split("\\")[-1]
    if isinstance(user, str) and "@" in user and alert.get("source") != "email":
        alert["user"] = user.split("@")[0]
    return {k: v for k, v in alert.items() if v not in (None, "", [])}


CATEGORY_HINTS = [
    (("brute", "password spray", "authentication fail", "logon fail", "credential"), "auth.bruteforce"),
    (("malware", "ransom", "powershell", "trojan", "suspicious process", "execution"), "endpoint.malware"),
    (("phish", "mail", "email", "url click"), "email.phishing"),
    (("prompt", "llm", "ai agent", "genai"), "ai.agent"),
]


def category_from_text(*texts: str | None) -> str:
    blob = " ".join(t for t in texts if t).lower()
    return next((cat for keys, cat in CATEGORY_HINTS if any(k in blob for k in keys)), "unknown")
