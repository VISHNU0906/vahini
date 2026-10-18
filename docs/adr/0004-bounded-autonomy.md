# ADR 0004: Bound the autonomy with a calibrated ceiling

**Status:** accepted

## Context
Nobody lets AI close alerts on its own, because nobody can say how often it gets it wrong. Vendor accuracy claims don't answer that.

## Decision
Alerts auto-close only below a threshold set by split conformal prediction on known attacks. The SOC lead picks the ceiling (for example, at most 1% of real attacks may ever be auto-closed). The threshold is recalibrated per customer and per alert type, every week, and when the score distribution drifts.

## Consequences
- Autonomy comes with a written, checkable promise instead of a vague accuracy number.
- The promise only holds while new alerts look like the calibration data, so recalibration is part of operations, not an afterthought.
