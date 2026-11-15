# Epistemic Drift & Counterfactual Failure Taxonomy

Reference matrix for the zero-dot whitespace domain identified across
autonomous agent evaluations (NeurIPS / ArXiv / Active Inference research).

## 1. Epistemic Provenance Tags
| Tag | Definition | Required Action |
| :--- | :--- | :--- |
| `[GROUND_TRUTH]` | Observed directly in tool output, AST, filesystem, or user specification. | Safe to rely on. |
| `[WORKING_HYPOTHESIS]` | Inferred from partial context or naming conventions. | Add runtime assertion or pre-flight probe before mutating state. |
| `[HALLUCINATED_INVARIANT]` | Implicit guarantee assumed without verification (e.g., infinite timeout, single-writer lock, non-empty key). | **Block mutation** until hardened with explicit guard or rollback hedge. |

## 2. The Seven Counterfactual Failure Worlds
1. **Irreversible State Mutation (`IRREVERSIBLE_SIDE_EFFECT`)**: Deletes files,
   resets git history, drops tables, or overwrites targets without backups or
   compensating transactions.
2. **Silent Failure & Error Swallowing (`SILENT_CORRUPTION`)**: Broad `except:`
   handlers or ignored return codes allow execution to return `0` after partial
   corruption.
3. **Unbounded External I/O (`UNBOUNDED_NETWORK_OR_IO`)**: HTTP requests,
   subprocesses, or streams without explicit `timeout` or retry bounds.
4. **Concurrency & TOCTOU Races (`CONCURRENCY_RACE_CONDITION`)**: Checking
   `exists()` before creating/writing without atomic locks or `exist_ok`, or
   mutating shared state without synchronization.
5. **Dynamic Execution & Injection Surface (`DYNAMIC_EXECUTION_RISK`)**:
   `shell=True`, `eval()`, `exec()`, or unparameterized string interpolation in
   commands/queries.
6. **Implicit Environment Assumptions (`IMPLICIT_ENV_INVARIANT`)**: Direct
   `os.environ["KEY"]` lookups, hardcoded paths, or unguarded encoding
   assumptions (`open()` without `encoding="utf-8"`).
7. **Intent & Scope Drift (`INTENT_DRIFT_SUSPECT`)**: Capabilities present in
   the artifact (network writes, destructive ops, external pushes) that contradict
   or diverge from the original user mandate.

## 3. Rollback Symmetry Formula
An action is **Rollback-Symmetric** if and only if:
$$\exists\, \text{Inverse}(A) \text{ such that } \text{State}(\text{Inverse}(A(S))) \equiv S$$
without manual forensic reconstruction.
