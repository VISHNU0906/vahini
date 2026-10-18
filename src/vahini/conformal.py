"""Conformal gate for auto-closing alerts with a bounded miss rate.

The triage model gives each alert a maliciousness score in [0, 1]. We only
auto-close an alert when its score falls below a threshold calibrated on
*known true-positive* alerts, chosen so that, for any new true positive
exchangeable with the calibration set,

    P(score < threshold) <= alpha.

In words: at alpha = 0.01, at most 1% of real attacks get auto-closed, no
matter how badly calibrated the underlying model is. Everything that is not
confidently benign or confidently malicious is routed to a human.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from enum import Enum
from typing import Sequence


class Route(str, Enum):
    AUTO_CLOSE = "auto_close"
    ANALYST = "analyst"
    ESCALATE = "escalate"


def miss_threshold(malicious_scores: Sequence[float], alpha: float) -> float:
    """Largest threshold t with P(new malicious score < t) <= alpha.

    With n calibration scores sorted ascending s_(1) <= ... <= s_(n) and
    k = floor(alpha * (n + 1)), returns s_(k) (and 0.0 when k == 0, which
    disables auto-close). A new exchangeable score is strictly below the
    k-th smallest with probability at most k / (n + 1) <= alpha.
    """
    if not 0 < alpha < 1:
        raise ValueError("alpha must be in (0, 1)")
    n = len(malicious_scores)
    k = math.floor(alpha * (n + 1))
    if k == 0:
        return 0.0
    return sorted(malicious_scores)[k - 1]


def false_alarm_threshold(benign_scores: Sequence[float], beta: float) -> float:
    """Smallest threshold u with P(new benign score > u) <= beta.

    Used for the escalate bin: an alert scoring above u is paged straight to
    on-call, and at most a beta fraction of benign alerts will do so.
    """
    if not 0 < beta < 1:
        raise ValueError("beta must be in (0, 1)")
    n = len(benign_scores)
    k = math.floor(beta * (n + 1))
    if k == 0:
        return 1.0 + 1e-9
    return sorted(benign_scores, reverse=True)[k - 1]


@dataclass
class ConformalGate:
    close_below: float
    escalate_above: float

    @classmethod
    def calibrate(
        cls,
        malicious_scores: Sequence[float],
        benign_scores: Sequence[float],
        alpha: float = 0.01,
        beta: float = 0.05,
    ) -> "ConformalGate":
        lo = miss_threshold(malicious_scores, alpha)
        hi = false_alarm_threshold(benign_scores, beta)
        return cls(close_below=lo, escalate_above=max(hi, lo))

    def route(self, score: float) -> Route:
        if score < self.close_below:
            return Route.AUTO_CLOSE
        if score > self.escalate_above:
            return Route.ESCALATE
        return Route.ANALYST
