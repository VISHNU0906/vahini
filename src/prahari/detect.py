"""Layer-1 prompt-injection detection for untrusted text.

Cheap, explainable checks that run on every free-text field before any model
sees it: hidden-character smuggling, instruction-like phrasing aimed at an AI
reader, and chat-template control tokens. Layer 2 (a fine-tuned classifier
such as Llama Prompt Guard 2) and layer 3 (activation-drift probes on the
quarantined model) plug in through the ``Detector`` protocol; see
docs/architecture.md.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Protocol


@dataclass
class Finding:
    detector: str
    score: float           # 0..1, how sure this detector is
    evidence: str


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    revealed: str = ""     # text with hidden characters decoded, for analysts

    @property
    def score(self) -> float:
        # Noisy-OR: independent weak signals add up, one strong signal is enough.
        p = 1.0
        for f in self.findings:
            p *= 1.0 - f.score
        return 1.0 - p

    @property
    def flagged(self) -> bool:
        return self.score >= 0.5


class Detector(Protocol):
    name: str

    def scan(self, text: str) -> list[Finding]: ...


# --- hidden characters -------------------------------------------------------

_TAG_RANGE = range(0xE0000, 0xE0080)        # Unicode "tag" block, ASCII smuggling
_ZERO_WIDTH = {0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF}
_BIDI = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A))


def reveal_hidden(text: str) -> tuple[str, int, int, int]:
    """Decode tag characters to ASCII and drop invisible ones.

    Returns (revealed_text, n_tag, n_zero_width, n_bidi).
    """
    out: list[str] = []
    n_tag = n_zw = n_bidi = 0
    for ch in text:
        cp = ord(ch)
        if cp in _TAG_RANGE:
            n_tag += 1
            inner = cp - 0xE0000
            if 0x20 <= inner < 0x7F:
                out.append(chr(inner))
        elif cp in _ZERO_WIDTH:
            n_zw += 1
        elif cp in _BIDI:
            n_bidi += 1
        else:
            out.append(ch)
    return "".join(out), n_tag, n_zw, n_bidi


class HiddenCharDetector:
    name = "hidden_chars"

    def scan(self, text: str) -> list[Finding]:
        _, n_tag, n_zw, n_bidi = reveal_hidden(text)
        findings = []
        if n_tag:
            findings.append(Finding(self.name, 0.95, f"{n_tag} Unicode tag characters (ASCII smuggling)"))
        if n_bidi:
            findings.append(Finding(self.name, 0.6, f"{n_bidi} bidi override characters"))
        if n_zw >= 3:
            findings.append(Finding(self.name, 0.3, f"{n_zw} zero-width characters"))
        return findings


# --- instruction-like phrasing -------------------------------------------------

_PATTERNS: list[tuple[str, float, str]] = [
    (r"\b(ignore|disregard|forget)\b.{0,30}\b(previous|prior|above|earlier|all)\b.{0,20}\b(instructions?|rules|prompts?|context)\b",
     0.9, "override of prior instructions"),
    (r"\b(you are now|act as|pretend to be|new instructions?)\b", 0.6, "role reassignment"),
    (r"\b(system prompt|developer message|hidden instructions?)\b", 0.5, "reference to model internals"),
    (r"\b(mark|classify|label|treat)\b.{0,40}\b(benign|false[ -]positive|resolved|safe|harmless)\b",
     0.8, "attempt to steer the triage verdict"),
    (r"\b(allow-?list|whitelist|exclude|suppress)\b.{0,40}\b(ip|host|domain|rule|alert|user)\b",
     0.7, "attempt to create a suppression"),
    (r"\b(do not|don't|never)\b.{0,20}\b(escalate|report|alert|notify|page)\b", 0.7, "attempt to block escalation"),
    (r"\b(ai|llm|assistant|copilot|analyst bot|soc agent)\b.{0,15}[:,]", 0.4, "text addressed to an AI reader"),
]
_TEMPLATE_TOKENS = re.compile(r"(<\|im_start\|>|<\|im_end\|>|\[/?INST\]|<<SYS>>|<\|system\|>|^#{2,}\s*system\b)",
                              re.IGNORECASE | re.MULTILINE)


class InstructionDetector:
    name = "instruction_phrasing"

    def __init__(self) -> None:
        self._compiled = [(re.compile(p, re.IGNORECASE | re.DOTALL), s, why) for p, s, why in _PATTERNS]

    def scan(self, text: str) -> list[Finding]:
        norm = unicodedata.normalize("NFKC", text)
        findings = []
        for rx, score, why in self._compiled:
            m = rx.search(norm)
            if m:
                findings.append(Finding(self.name, score, f"{why}: '{m.group(0)[:80]}'"))
        if _TEMPLATE_TOKENS.search(norm):
            findings.append(Finding(self.name, 0.85, "chat-template control token"))
        return findings


class Scanner:
    """Runs every detector over the raw text and over its revealed form."""

    def __init__(self, detectors: list[Detector] | None = None) -> None:
        self.detectors: list[Detector] = detectors or [HiddenCharDetector(), InstructionDetector()]

    def scan(self, text: str) -> ScanResult:
        revealed, *_ = reveal_hidden(text)
        result = ScanResult(revealed=revealed)
        seen: set[str] = set()
        for det in self.detectors:
            for candidate in (text, revealed) if revealed != text else (text,):
                for f in det.scan(candidate):
                    if f.evidence not in seen:
                        seen.add(f.evidence)
                        result.findings.append(f)
        return result
