"""Layer 2 detector: Llama Prompt Guard 2 (``pip install vahini[ml]``).

Plugs into the same ``Detector`` protocol as the layer-1 checks. Its score is
evidence that raises suspicion, never the security boundary: adaptive attacks
get past every classifier, which is why the policy gate exists.
"""

from __future__ import annotations

from .detect import Finding

MODEL_ID = "meta-llama/Llama-Prompt-Guard-2-86M"
MAX_CHARS = 2000          # the model reads 512 tokens; long fields are scanned in windows


class PromptGuardDetector:
    name = "prompt_guard_2"

    def __init__(self, model_id: str = MODEL_ID, threshold: float = 0.5) -> None:
        from transformers import pipeline  # optional dependency

        self.threshold = threshold
        self.clf = pipeline("text-classification", model=model_id, truncation=True)

    @staticmethod
    def _malicious_score(result: dict) -> float:
        label = str(result.get("label", "")).upper()
        score = float(result.get("score", 0.0))
        is_bad = label in {"LABEL_1", "MALICIOUS", "INJECTION", "JAILBREAK"}
        return score if is_bad else 1.0 - score

    def scan(self, text: str) -> list[Finding]:
        windows = [text[i:i + MAX_CHARS] for i in range(0, max(len(text), 1), MAX_CHARS)]
        worst = max(self._malicious_score(r) for r in self.clf(windows))
        if worst < self.threshold:
            return []
        return [Finding(self.name, round(worst, 3), f"classifier flags injection (p={worst:.2f})")]
