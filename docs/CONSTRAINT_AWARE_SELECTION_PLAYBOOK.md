# Constraint-Aware Selection & Coverage Insurance — Playbook v2
### From empirical thresholds to statistical guarantees

v2 upgrades the v1 pattern (operating point → diverse detectors → temporal evaluation) in six
places. Every upgrade **strengthens** the safety invariants — guarantees instead of estimates,
auto-tightening instead of manual drift handling, deferral instead of forced decisions — so the
pattern stays safe for coding, cybersecurity, applications, games, and other domains.

> **v1 one-liner:** select under a hard constraint, back it with detectors that fail
> differently, prove it over time.
> **v2 one-liner:** the same — but the constraint is now *guaranteed*, the threshold
> *maintains itself conservatively*, and the system can *say "I don't know."*

---

## 0. What changed from v1 (at a glance)

| # | v1 | v2 upgrade | Why it's safer, not just better |
|---|----|------------|--------------------------------|
| 1 | Empirical threshold from backtest | **Conformal risk control**: distribution-free guarantee that the false-selection rate ≤ κ with confidence 1−δ | The constraint becomes provable, not observed |
| 2 | Monthly manual recalibration | **Online drift monitor** (control chart on live BEF) + automatic conservative fallback | System can only tighten itself, never loosen |
| 3 | Binary select/reject | **Abstain/defer** third action via calibrated uncertainty | Uncertain cases go to a human instead of being forced |
| 4 | Overlap measured passively | **Disagreement-first labeling** (active learning on detector disagreement) | Human labels land where they verify the system most |
| 5 | Global min-BEF meta-controller | **Contextual gating** (auditable per-region routing) | Higher precision with an interpretable gate |
| 6 | Fixed-weight policy | **Pareto front** of policies (MORL/D direction) | Tunable trade-offs; gated behind shadow mode |

Deploy in that order. 1–3 are low-risk, high-value, and domain-agnostic. 4–5 are medium.
6 is the research frontier — only after 1–5 are proven.

---

## 1. Upgrade 1 — The conformal operating point (the core of v2)

**Problem with v1:** "largest selection with BEF ≤ κ on the backtest" is a point estimate.
On new data the realized rate can exceed κ, and you have no statement about how often.

**v2:** use **conformal risk control** (Learn-then-Test family). Split off a *calibration set*
(labeled, recent, never used for training). For each candidate threshold λ, test the null
hypothesis "risk(λ) > κ" using the calibration losses; select the most permissive λ that is
rejected at level δ. Result, with no distributional assumptions:

> **P( false-selection rate on future data ≤ κ ) ≥ 1 − δ**

provided calibration data is exchangeable with deployment data (that's what the drift monitor
in Upgrade 2 watches).

Practical notes:
- Works with **any scorer** — classifier, anomaly detector, LLM judge — it only needs scores
  and labels on the calibration set.
- The guarantee weakens under drift. That is not a flaw to hide; it's exactly why Upgrade 2
  exists. Conformal + drift monitor is the complete unit.
- Cost: you must reserve a few hundred to a few thousand labeled calibration points, and
  re-run calibration after each drift trigger.

---

## 2. Upgrade 2 — Self-maintaining threshold (drift monitor + safe fallback)

Monitor the **live false-selection fraction** (from analyst dispositions / ground truth as it
arrives) with a simple control chart:

- **CUSUM** or EWMA on the per-window BEF; alarm when the statistic crosses its limit.
- On alarm: **automatically shrink the selection** (raise the threshold / cut M in half) and
  flag for recalibration. Never auto-relax.
- After recalibration on fresh data (re-run Upgrade 1), restore the new guaranteed threshold.

**Safety invariant:** autonomous changes are monotone-conservative. A human (or a fresh
conformal calibration) is required to loosen; the machine alone can only tighten.

---

## 3. Upgrade 3 — Abstain / defer

Add a third action. With calibrated probabilities (isotonic or Platt scaling on a held-out
split):

- **select** if P(positive) ≥ p_hi
- **reject** if P(positive) ≤ p_lo
- **defer to human** otherwise

Choose (p_lo, p_hi) on calibration data to satisfy two budgets jointly: the κ ceiling on
selected items, and a **deferral budget** (e.g., ≤ 10% of volume goes to humans). Deferral is
inherently safe: the failure mode of uncertainty becomes a review task, not a wrong action.

Domain translations: coding → "senior review this PR"; games → "shadow-restrict pending
review"; moderation → "human queue"; cyber → "Tier-2 analyst".

---

## 4. Upgrade 4 — Disagreement-first labeling (active learning)

v1 measured detector overlap once. v2 *uses* disagreement continuously:

1. Each window, sample for human labeling primarily from **disagreement regions**
   (selected by exactly one detector) plus a small random slice (for unbiased monitoring).
2. Feed labels back into (a) the conformal calibration set and (b) periodic retraining.
3. Track overlap over time: if Jaccard rises toward redundancy, the second detector has
   stopped paying rent — investigate or replace it.

This is the cheapest way to keep verifying that "coverage insurance" is still real, using
label effort you were going to spend anyway.

---

## 5. Upgrade 5 — Contextual gating (auditable meta-controller)

Replace "pick the globally min-risk feasible detector" with **per-region routing**:

- Train a *shallow, interpretable* gate (depth-≤3 tree, or a per-cluster lookup table) that
  predicts which detector is reliable for which region of feature space.
- Constraint: the gate must be explainable row-by-row ("cluster #17 → trust IF because
  historical precision there = 1.00"). No deep gating networks in regulated/SOC settings.
- Evaluate the gated system under the same conformal procedure (Upgrade 1) — the guarantee
  applies to the *composite* selector.

---

## 6. Upgrade 6 — Pareto front (only after 1–5 are boring)

A fixed reward weighting commits to one trade-off at training time. Multi-objective RL
(MORL/D-style decomposition) yields a *front* of policies spanning trade-offs
(coverage vs. false-selection vs. workload), from which the operator picks per quarter.
Treat it as a research-grade addition: it must pass the same shadow-mode gates, and the
selected policy still runs under the conformal threshold and drift monitor.

---

## 7. The v2 reference loop

```
              ┌────────────────────────────────────────────────────┐
              │                  EVERY WINDOW                       │
              │                                                    │
 scores ───►  │  conformal threshold λ̂ (κ, δ guarantee)            │
              │        │                                           │
              │        ▼                                           │
              │  select / DEFER / reject   ──► humans label defers │
              │        │                        + disagreements    │
              │        ▼                                           │
              │  live BEF → CUSUM monitor                          │
              │        │ alarm?                                    │
              │        ├── yes → shrink selection, recalibrate ────┤
              │        └── no  → continue                          │
              └────────────────────────────────────────────────────┘
```

---

## 8. Code-level additions (see the runnable prototype)

The prototype (`conformal_triage_prototype.py`) implements, end to end on realistic
synthetic data:

1. `conformal_lambda()` — Learn-then-Test threshold selection with the (κ, δ) guarantee
   (Hoeffding-bound p-values + fixed-sequence testing).
2. `AbstainPolicy` — calibrated select/defer/reject with a deferral budget.
3. `CusumMonitor` — drift detection on live BEF with monotone-conservative fallback.
4. A **simulation harness**: stationary weeks → guarantee holds; then injected drift →
   monitor fires, selection shrinks, recalibration restores a valid threshold.
5. A **validation experiment**: many repeated trials confirming the empirical violation rate
   of the guarantee is ≤ δ.

---

## 9. Per-domain quick map (v2 edition)

| Domain | Items | κ constraint example | Defer action | Drift trigger example |
|---|---|---|---|---|
| Coding / CI | tests, PRs, vulns | ≤5% wasted senior-review escalations | "senior review" | new framework / refactor wave |
| Cybersecurity | alerts | ≤10% benign escalations | Tier-2 queue | base threat-rate shift |
| Applications | posts, tickets, outputs | reviewer capacity | human queue | product launch / new locale |
| Games | accounts, matches | false-ban ceiling (κ very low) | shadow-review | new patch / meta shift |
| LLM apps | model outputs | ≤X% bad outputs shipped | human approval | model/prompt version change |

---

## 10. Safety invariants (unchanged, now stronger)

1. **Hard constraint κ** — now with a (1−δ) distribution-free guarantee, not a backtest hope.
2. **Temporal discipline** — calibration data must be recent and post-training; never random-split.
3. **Shadow mode first** — all upgrades validate in parallel before acting.
4. **Human-in-the-loop** — deferral is a first-class action; consequential actions need sign-off.
5. **Monotone-conservative autonomy** — the system may tighten itself; only humans/recalibration loosen.
6. **Tested rollback** — one flag back to native behavior.

---

## 11. Glossary additions (v2)

- **Conformal risk control / Learn-then-Test** — distribution-free calibration giving
  P(risk ≤ κ) ≥ 1−δ for a chosen loss, via hypothesis testing on a calibration set.
- **δ (delta)** — the probability budget for the guarantee failing (e.g., 0.05).
- **CUSUM** — cumulative-sum control chart; raises an alarm when small persistent shifts
  accumulate.
- **Deferral budget** — the max fraction of items routed to humans.
- **Monotone-conservative fallback** — automated response to anomalies that can only reduce
  the system's action surface.
