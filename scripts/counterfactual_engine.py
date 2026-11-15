"""Counterfactual Pre-Mortem & Epistemic Drift Forensics Engine.

Zero-dot whitespace skill implementation that analyzes Python code, shell
scripts, diffs, or markdown plans BEFORE execution to uncover:
- Hidden assumptions and hallucinated invariants
- Counterfactual failure worlds (silent corruption, race conditions, unbounded I/O)
- Rollback asymmetry (irreversible mutations lacking inverse actions)
- Semantic intent drift against an explicit user mandate
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

SEVERITY_PENALTY = {"CRITICAL": 28, "HIGH": 16, "MEDIUM": 8, "LOW": 3}

TEXT_RISK_RULES: list[dict] = [
    {
        "id": "CF-DESTRUCTIVE-CMD",
        "pattern": re.compile(
            r"\b(rm\s+-rf|shutil\.rmtree|git\s+reset\s+--hard|git\s+push\s+--force|DROP\s+TABLE|TRUNCATE\s+TABLE)\b",
            re.I,
        ),
        "world": "IRREVERSIBLE_SIDE_EFFECT",
        "severity": "CRITICAL",
        "epistemic_tag": "HALLUCINATED_INVARIANT",
        "assumption": "Target path, branch, or table has a verified backup or zero active consumers.",
        "counterfactual": "If executed with a stale variable or wrong CWD, irreversible data loss occurs with no inverse command.",
        "mitigation": "Create an explicit snapshot/stash or dry-run guard and verify inverse rollback vector before mutating.",
        "rollback_symmetric": False,
    },
    {
        "id": "CF-GITHUB-REMOTE-PUSH",
        "pattern": re.compile(r"\b(git\s+push|gh\s+repo\s+create|gh\s+pr\s+create)\b", re.I),
        "world": "IRREVERSIBLE_SIDE_EFFECT",
        "severity": "HIGH",
        "epistemic_tag": "WORKING_HYPOTHESIS",
        "assumption": "Remote repository publication is authorized and scrubbed of local secrets.",
        "counterfactual": "Publishing before user review leaks local artifacts or unapproved history externally.",
        "mitigation": "Keep artifacts local or stage behind an explicit user confirmation gate.",
        "rollback_symmetric": False,
    },
    {
        "id": "CF-UNVERIFIED-CLAIM",
        "pattern": re.compile(
            r"\b(assume\s+that|presumably|guaranteed\s+to|always\s+succeeds|never\s+fails)\b",
            re.I,
        ),
        "world": "IMPLICIT_ENV_INVARIANT",
        "severity": "MEDIUM",
        "epistemic_tag": "WORKING_HYPOTHESIS",
        "assumption": "Prose relies on an unverified runtime invariant instead of a tool observation.",
        "counterfactual": "In Turn 4+, speculative assumptions compound into hallucinated ground truth.",
        "mitigation": "Anchor the claim in an executable check and tag provenance as [GROUND_TRUTH].",
        "rollback_symmetric": True,
    },
]

INTENT_CONSTRAINTS = [
    {
        "intent_re": re.compile(r"\b(no\s+github|don'?t\s+push|never\s+push|local\s+only|offline\s+only)\b", re.I),
        "artifact_re": re.compile(r"\b(git\s+push|gh\s+repo\s+create)\b", re.I),
        "reason": "Artifact invokes remote Git/GitHub publishing despite local-only / no-push user intent.",
    },
    {
        "intent_re": re.compile(r"\b(read[- ]?only|no\s+write|no\s+edit)\b", re.I),
        "artifact_re": re.compile(r"(\.write_text\(|\.unlink\(|os\.remove\(|open\([^)]*['\"]w['\"])", re.I),
        "reason": "Artifact performs filesystem write/delete mutations despite read-only user intent.",
    },
    {
        "intent_re": re.compile(r"\b(no\s+network|offline|without\s+internet)\b", re.I),
        "artifact_re": re.compile(r"\b(urllib\.request|requests\.(get|post|put)|httpx\.|http\.client)\b", re.I),
        "reason": "Artifact performs outbound network requests despite offline/no-network user intent.",
    },
]


@dataclass
class CounterfactualFinding:
    """One counterfactual failure scenario and its epistemic classification."""

    rule_id: str
    line: int
    world: str
    severity: str
    epistemic_tag: str
    hidden_assumption: str
    counterfactual_failure: str
    mitigation: str
    rollback_symmetric: bool


@dataclass
class EpistemicAuditReport:
    """Complete pre-mortem and epistemic drift audit output."""

    target: str
    artifact_type: str
    epistemic_safety_score: int
    verdict: str
    rollback_symmetry_ratio: float
    ground_truth_guards: list[str] = field(default_factory=list)
    tag_counts: dict[str, int] = field(default_factory=dict)
    findings: list[CounterfactualFinding] = field(default_factory=list)


def _call_name(node: ast.AST) -> str:
    """Resolve dotted name for an AST Call target."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _has_keyword(call_node: ast.Call, kw_name: str) -> bool:
    """Return True if a Call node passes a specific keyword argument."""
    return any(kw.arg == kw_name for kw in call_node.keywords)


def _kw_is_true(call_node: ast.Call, kw_name: str) -> bool:
    """Return True if keyword argument is explicitly literal True."""
    for kw in call_node.keywords:
        if kw.arg == kw_name and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True
    return False


def _check_except_handler(node: ast.ExceptHandler) -> CounterfactualFinding | None:
    """Flag broad exception blocks that silently swallow errors with `pass`."""
    is_broad = node.type is None or (
        isinstance(node.type, ast.Name) and node.type.id in {"Exception", "BaseException"}
    )
    swallows = len(node.body) == 1 and isinstance(node.body[0], ast.Pass)
    if not (is_broad and swallows):
        return None
    return CounterfactualFinding(
        rule_id="CF-SILENT-EXCEPT-PASS",
        line=node.lineno,
        world="SILENT_CORRUPTION",
        severity="HIGH",
        epistemic_tag="HALLUCINATED_INVARIANT",
        hidden_assumption="Ignored exceptions are harmless and leave state consistent.",
        counterfactual_failure="Mid-operation failure returns exit code 0 while silently corrupting output.",
        mitigation="Catch specific exception types and log or propagate context instead of `pass`.",
        rollback_symmetric=False,
    )


def _check_environ_subscript(node: ast.Subscript) -> CounterfactualFinding | None:
    """Flag unguarded direct subscripting into `os.environ`."""
    if _call_name(node.value) != "os.environ":
        return None
    return CounterfactualFinding(
        rule_id="CF-ENV-HARD-KEY",
        line=node.lineno,
        world="IMPLICIT_ENV_INVARIANT",
        severity="MEDIUM",
        epistemic_tag="HALLUCINATED_INVARIANT",
        hidden_assumption="Required environment variable is guaranteed to be populated in every host.",
        counterfactual_failure="Throws unhandled KeyError in fresh CI/container environments.",
        mitigation="Use `os.environ.get('KEY')` with explicit missing-config validation.",
        rollback_symmetric=True,
    )


def _check_toctou_races(exists_lines: list[int], write_lines: list[int]) -> list[CounterfactualFinding]:
    """Detect check-then-write windows susceptible to TOCTOU races."""
    if not (exists_lines and write_lines):
        return []
    races: list[CounterfactualFinding] = []
    for w_line in write_lines:
        if any(0 < w_line - e_line <= 15 for e_line in exists_lines):
            races.append(
                CounterfactualFinding(
                    rule_id="CF-TOCTOU-RACE",
                    line=w_line,
                    world="CONCURRENCY_RACE_CONDITION",
                    severity="MEDIUM",
                    epistemic_tag="WORKING_HYPOTHESIS",
                    hidden_assumption="No concurrent worker creates or deletes the path between check and write.",
                    counterfactual_failure="Parallel swarm workers collide in a TOCTOU race and overwrite each other.",
                    mitigation="Use atomic creation flags (`exist_ok=True`, exclusive lock, or temp-file rename).",
                    rollback_symmetric=False,
                )
            )
    return races


def _inspect_python_ast(source: str) -> tuple[list[CounterfactualFinding], list[str]]:
    """Inspect Python AST for silent corruption, unbounded I/O, races, and dynamic exec."""
    findings: list[CounterfactualFinding] = []
    guards: list[str] = []
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        findings.append(
            CounterfactualFinding(
                rule_id="CF-SYNTAX-UNPARSABLE",
                line=exc.lineno or 1,
                world="SILENT_CORRUPTION",
                severity="CRITICAL",
                epistemic_tag="HALLUCINATED_INVARIANT",
                hidden_assumption="Generated Python artifact is syntactically valid.",
                counterfactual_failure=f"Execution aborts immediately with SyntaxError: {exc.msg}.",
                mitigation="Fix syntax error and re-run AST validation before execution.",
                rollback_symmetric=True,
            )
        )
        return findings, guards

    exists_lines: list[int] = []
    write_lines: list[int] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler):
            finding = _check_except_handler(node)
            if finding:
                findings.append(finding)
        elif isinstance(node, ast.Subscript):
            finding = _check_environ_subscript(node)
            if finding:
                findings.append(finding)
        elif isinstance(node, ast.Call):
            _audit_python_call(node, _call_name(node.func), findings, guards, exists_lines, write_lines)

    findings.extend(_check_toctou_races(exists_lines, write_lines))
    return findings, sorted(set(guards))


def _audit_subprocess_call(node: ast.Call, name: str, findings: list[CounterfactualFinding], guards: list[str]) -> None:
    """Check subprocess calls for `shell=True` injection and missing timeouts."""
    if _kw_is_true(node, "shell"):
        findings.append(
            CounterfactualFinding(
                rule_id="CF-SUBPROCESS-SHELL",
                line=node.lineno,
                world="DYNAMIC_EXECUTION_RISK",
                severity="HIGH",
                epistemic_tag="HALLUCINATED_INVARIANT",
                hidden_assumption="Interpolated command arguments cannot contain shell metacharacters.",
                counterfactual_failure="Command injection or broken quoting on paths with spaces.",
                mitigation="Pass argument list `[cmd, arg1, ...]` with `shell=False`.",
                rollback_symmetric=False,
            )
        )
    if name in {"subprocess.run", "subprocess.call", "subprocess.check_output"} and not _has_keyword(node, "timeout"):
        findings.append(
            CounterfactualFinding(
                rule_id="CF-UNBOUNDED-SUBPROCESS",
                line=node.lineno,
                world="UNBOUNDED_NETWORK_OR_IO",
                severity="MEDIUM",
                epistemic_tag="WORKING_HYPOTHESIS",
                hidden_assumption="Child process is guaranteed to terminate promptly.",
                counterfactual_failure="Hanging child process deadlocks agent loop indefinitely.",
                mitigation="Set explicit `timeout=<seconds>` and handle `TimeoutExpired`.",
                rollback_symmetric=True,
            )
        )
    elif _has_keyword(node, "timeout"):
        guards.append("Bounded subprocess timeout")


def _audit_http_call(node: ast.Call, findings: list[CounterfactualFinding], guards: list[str]) -> None:
    """Check outbound HTTP calls for explicit timeout safeguards."""
    if _has_keyword(node, "timeout"):
        guards.append("Explicit network timeout")
        return
    findings.append(
        CounterfactualFinding(
            rule_id="CF-UNBOUNDED-HTTP",
            line=node.lineno,
            world="UNBOUNDED_NETWORK_OR_IO",
            severity="HIGH",
            epistemic_tag="HALLUCINATED_INVARIANT",
            hidden_assumption="Remote HTTP endpoint always responds rapidly.",
            counterfactual_failure="Socket hang freezes worker thread under packet loss.",
            mitigation="Always pass explicit `timeout=` parameter to outbound HTTP calls.",
            rollback_symmetric=True,
        )
    )


def _audit_io_call(
    node: ast.Call,
    name: str,
    findings: list[CounterfactualFinding],
    guards: list[str],
    write_lines: list[int],
) -> None:
    """Check file open/read/write calls for explicit UTF-8 encoding and race tracking."""
    if name in {"open", "Path.open"} or name.endswith(".write_text"):
        write_lines.append(node.lineno)
    if _has_keyword(node, "encoding"):
        guards.append("Explicit UTF-8 file encoding")
    elif name == "open":
        findings.append(
            CounterfactualFinding(
                rule_id="CF-IMPLICIT-ENCODING",
                line=node.lineno,
                world="IMPLICIT_ENV_INVARIANT",
                severity="LOW",
                epistemic_tag="WORKING_HYPOTHESIS",
                hidden_assumption="Host OS default locale encoding matches UTF-8 file bytes.",
                counterfactual_failure="Throws UnicodeDecodeError/cp1252 corruption on Windows hosts.",
                mitigation="Specify `encoding='utf-8'` explicitly on file open calls.",
                rollback_symmetric=True,
            )
        )


def _audit_python_call(
    node: ast.Call,
    name: str,
    findings: list[CounterfactualFinding],
    guards: list[str],
    exists_lines: list[int],
    write_lines: list[int],
) -> None:
    """Evaluate a single Python AST Call node against counterfactual rules."""
    if name in {"eval", "exec"}:
        findings.append(
            CounterfactualFinding(
                rule_id="CF-DYNAMIC-EXEC",
                line=node.lineno,
                world="DYNAMIC_EXECUTION_RISK",
                severity="CRITICAL",
                epistemic_tag="HALLUCINATED_INVARIANT",
                hidden_assumption="Evaluated expression string is strictly trusted and injection-free.",
                counterfactual_failure="Arbitrary code execution if untrusted input reaches evaluation boundary.",
                mitigation="Replace dynamic eval/exec with `ast.literal_eval` or explicit dispatch map.",
                rollback_symmetric=False,
            )
        )
    elif name.startswith("subprocess.") and name != "subprocess.CompletedProcess":
        _audit_subprocess_call(node, name, findings, guards)
    elif name in {"urllib.request.urlopen", "requests.get", "requests.post", "requests.put", "requests.delete"}:
        _audit_http_call(node, findings, guards)
    elif name in {"os.remove", "os.unlink", "shutil.rmtree"} or name.endswith(".unlink"):
        findings.append(
            CounterfactualFinding(
                rule_id="CF-IRREVERSIBLE-DELETE",
                line=node.lineno,
                world="IRREVERSIBLE_SIDE_EFFECT",
                severity="HIGH",
                epistemic_tag="WORKING_HYPOTHESIS",
                hidden_assumption="Target file/directory is disposable and no backup snapshot is needed.",
                counterfactual_failure="Unintended deletion leaves workspace unrecoverable on wrong path resolution.",
                mitigation="Verify path containment within workspace root or stage backup before deletion.",
                rollback_symmetric=False,
            )
        )
    elif name.endswith(".exists") or name == "os.path.exists":
        exists_lines.append(node.lineno)
    elif name in {"open", "Path.open"} or name.endswith((".write_text", ".read_text")):
        _audit_io_call(node, name, findings, guards, write_lines)


def _scan_text_patterns(source: str) -> list[CounterfactualFinding]:
    """Run counterfactual regex checks across any file or plan text."""
    findings: list[CounterfactualFinding] = []
    for idx, line in enumerate(source.splitlines(), start=1):
        for rule in TEXT_RISK_RULES:
            if rule["pattern"].search(line):
                findings.append(
                    CounterfactualFinding(
                        rule_id=rule["id"],
                        line=idx,
                        world=rule["world"],
                        severity=rule["severity"],
                        epistemic_tag=rule["epistemic_tag"],
                        hidden_assumption=rule["assumption"],
                        counterfactual_failure=rule["counterfactual"],
                        mitigation=rule["mitigation"],
                        rollback_symmetric=rule["rollback_symmetric"],
                    )
                )
    return findings


def _check_intent_drift(source: str, intent: str | None) -> list[CounterfactualFinding]:
    """Detect contradictions between declared user intent and artifact behavior."""
    if not intent:
        return []
    findings: list[CounterfactualFinding] = []
    for rule in INTENT_CONSTRAINTS:
        if rule["intent_re"].search(intent):
            for idx, line in enumerate(source.splitlines(), start=1):
                if rule["artifact_re"].search(line):
                    findings.append(
                        CounterfactualFinding(
                            rule_id="CF-INTENT-DRIFT",
                            line=idx,
                            world="INTENT_DRIFT_SUSPECT",
                            severity="CRITICAL",
                            epistemic_tag="HALLUCINATED_INVARIANT",
                            hidden_assumption="Action aligns with user constraints despite capability mismatch.",
                            counterfactual_failure=rule["reason"],
                            mitigation="Halt execution and align artifact strictly with user mandate.",
                            rollback_symmetric=False,
                        )
                    )
                    break
    return findings


def audit_artifact(target_path: Path, intent: str | None = None) -> EpistemicAuditReport:
    """Audit a source file, script, or plan markdown for counterfactual risks."""
    source = target_path.read_text(encoding="utf-8", errors="replace")
    is_python = target_path.suffix.lower() == ".py"

    findings: list[CounterfactualFinding] = []
    guards: list[str] = []

    if is_python:
        ast_findings, guards = _inspect_python_ast(source)
        findings.extend(ast_findings)
    else:
        findings.extend(_scan_text_patterns(source))

    findings.extend(_check_intent_drift(source, intent))

    # Deduplicate same rule on same line
    deduped: list[CounterfactualFinding] = []
    seen = set()
    for item in findings:
        key = (item.rule_id, item.line)
        if key not in seen:
            seen.add(key)
            deduped.append(item)

    penalty = sum(SEVERITY_PENALTY.get(item.severity, 5) for item in deduped)
    score = max(0, min(100, 100 - penalty))

    if score >= 80:
        verdict = "SAFE_TO_PROCEED"
    elif score >= 55:
        verdict = "GUARDED_EXECUTION"
    else:
        verdict = "HALT_PREMORTEM_REQUIRED"

    tag_counts = {
        "GROUND_TRUTH": len(guards),
        "WORKING_HYPOTHESIS": sum(1 for f in deduped if f.epistemic_tag == "WORKING_HYPOTHESIS"),
        "HALLUCINATED_INVARIANT": sum(1 for f in deduped if f.epistemic_tag == "HALLUCINATED_INVARIANT"),
    }
    sym_ratio = (
        round(sum(1 for f in deduped if f.rollback_symmetric) / len(deduped), 2)
        if deduped
        else 1.0
    )

    return EpistemicAuditReport(
        target=str(target_path),
        artifact_type="python_module" if is_python else "text_or_plan",
        epistemic_safety_score=score,
        verdict=verdict,
        rollback_symmetry_ratio=sym_ratio,
        ground_truth_guards=guards,
        tag_counts=tag_counts,
        findings=deduped,
    )


def format_markdown_report(report: EpistemicAuditReport) -> str:
    """Render an EpistemicAuditReport as readable Markdown."""
    lines = [
        "# Counterfactual Pre-Mortem Oracle — Epistemic Audit",
        "",
        f"- **Target**: `{report.target}` (`{report.artifact_type}`)",
        f"- **Epistemic Safety Score**: **{report.epistemic_safety_score}/100** -> `{report.verdict}`",
        f"- **Rollback Symmetry Ratio**: {int(report.rollback_symmetry_ratio * 100)}%",
        f"- **Provenance Counts**: `[GROUND_TRUTH]={report.tag_counts['GROUND_TRUTH']}`, "
        f"`[WORKING_HYPOTHESIS]={report.tag_counts['WORKING_HYPOTHESIS']}`, "
        f"`[HALLUCINATED_INVARIANT]={report.tag_counts['HALLUCINATED_INVARIANT']}`",
    ]
    if report.ground_truth_guards:
        lines.append(f"- **Verified Guards**: {', '.join(report.ground_truth_guards)}")

    if not report.findings:
        lines.extend(["", "No counterfactual failure triggers or hallucinated invariants detected."])
        return "\n".join(lines)

    lines.extend(
        [
            "",
            "| Line | Rule | Severity | Epistemic Tag | Counterfactual Failure World |",
            "| ---: | :--- | :--- | :--- | :--- |",
        ]
    )
    for item in report.findings:
        lines.append(
            f"| {item.line} | `{item.rule_id}` | {item.severity} | `[{item.epistemic_tag}]` | "
            f"{item.world}: {item.counterfactual_failure} |"
        )
    lines.extend(["", "## Required Mitigations"])
    for item in report.findings:
        lines.append(f"- **Line {item.line} (`{item.rule_id}`)**: {item.mitigation}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for counterfactual pre-mortem auditing."""
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(description="Run Counterfactual Pre-Mortem & Epistemic Drift Audit.")
    parser.add_argument("target", help="Python file, script, or plan document to audit")
    parser.add_argument("--intent", help="Original user goal/constraint for intent-drift checking", default=None)
    parser.add_argument("--format", choices=["json", "markdown"], default="markdown")
    parser.add_argument("--strict", action="store_true", help="Exit 1 when verdict is HALT_PREMORTEM_REQUIRED")
    args = parser.parse_args(argv)

    target = Path(args.target).resolve()
    if not target.is_file():
        print(f"Error: Target file not found: {target}", file=sys.stderr)
        return 2

    report = audit_artifact(target, intent=args.intent)
    if args.format == "json":
        print(json.dumps(asdict(report), indent=2, ensure_ascii=False))
    else:
        print(format_markdown_report(report))

    if args.strict and report.verdict == "HALT_PREMORTEM_REQUIRED":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
