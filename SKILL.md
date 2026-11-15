---
name: counterfactual-premortem-oracle
description: >-
  Zero-dot whitespace skill for pre-execution Counterfactual Pre-Mortem failure
  simulation, hidden assumption extraction, rollback symmetry verification, and
  Epistemic Drift Forensics. Use BEFORE executing mutating scripts, risky diffs,
  deployments, or complex multi-turn plans to simulate silent data corruption,
  race conditions, irreversible side effects, and hallucinated invariants.
---

# Counterfactual Pre-Mortem Oracle (Zero-Dot Void Skill)

While 95%+ of public AI skills teach *how to generate code or call APIs*, almost
none audit the **epistemic safety** of an agent's reasoning before state
mutation occurs. This skill fills that zero-dot void by combining Pearl-style
counterfactual intervention (`What fails if an unverified invariant breaks?`)
with runtime **Epistemic Provenance Auditing**.

## When to Activate

Activate this skill BEFORE:
- Running destructive or state-mutating scripts, migrations, or multi-file diffs.
- Trusting an architectural plan or agent-generated script in production.
- Proceeding into turn 4+ of a multi-step debugging loop (high **Intent Drift**
  and **Local Optimization Trap** risk).

---

## 4-Stage Counterfactual & Epistemic Audit Workflow

### Stage 1: Automated Counterfactual Failure Simulation
Run the bundled counterfactual pre-mortem engine on any target script, diff, or
plan document:

```bash
python ./scripts/counterfactual_engine.py <target_file> --format markdown
```

Optionally pass `--intent "<original user goal>"` to measure **Intent Alignment**
and detect semantic/goal drift between the original request and the artifact:

```bash
python ./scripts/counterfactual_engine.py <target_file> --intent "Read-only AST inspection without network writes"
```

### Stage 2: Epistemic Provenance Ledger
Classify every foundational assumption uncovered in Stage 1 using the strict
tripartite epistemic taxonomy defined in
[Void Epistemic Taxonomy](./references/void_epistemic_taxonomy.md):
- `[GROUND_TRUTH]`: Directly verified via tool output, disk state, or explicit
  user constraint.
- `[WORKING_HYPOTHESIS]`: Plausible deduction requiring an assertion or check
  before mutating state.
- `[HALLUCINATED_INVARIANT]`: Unchecked assumption treated as guaranteed (e.g.,
  assuming network availability, non-null external payloads, atomic file locks,
  or idempotent retries without guards).

### Stage 3: Counterfactual Failure World Inspection & Rollback Symmetry
For each high-severity finding, verify three counterfactual worlds:
1. **Partial Termination World ($t + 500\text{ms}$ Kill)**: If execution halts
   midway, are partial writes/locks orphaned? Does an automated inverse command
   (`rollback_vector`) exist?
2. **Silent Corruption World (`exit code == 0`)**: Could the code report success
   while silently corrupting encodings, dropping records (`except: pass`), or
   mutating global state?
3. **Concurrency / Race World**: If two workers invoke this path simultaneously,
   do TOCTOU (Time-of-Check to Time-of-Use) races or deadlocks emerge?

### Stage 4: Epistemic Safety Gate
- **Score >= 80 (`SAFE_TO_PROCEED`)**: Assumptions are bounded and reversible.
- **Score 55 – 79 (`GUARDED_EXECUTION`)**: Add missing guards, timeouts, or
  snapshot backups before proceeding.
- **Score < 55 (`HALT_PREMORTEM_REQUIRED`)**: Reject execution until
  `[HALLUCINATED_INVARIANT]` items and irreversible side effects are mitigated.
