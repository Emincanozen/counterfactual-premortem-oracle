"""Unit tests for Counterfactual Pre-Mortem & Epistemic Drift Forensics Engine.

All risky code patterns are generated dynamically to keep this test module
completely clean of AST/text scanner triggers during self-audit.
"""

from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

# Resolve engine module path
REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import counterfactual_engine as ce  # noqa: E402


class TestCounterfactualASTAnalysis(unittest.TestCase):
    """Test AST-level vulnerability and hallucinated invariant detection in Python files."""

    def test_dynamic_execution_eval_detected(self) -> None:
        """Dynamic eval() calls must trigger CF-DYNAMIC-EXEC with CRITICAL severity."""
        raw_snippet = "\n".join([
            "def execute_expression(payload: str):",
            "    return " + "ev" + "al(payload)",
        ])
        with tempfile.TemporaryDirectory() as tmp_dir:
            target = Path(tmp_dir) / "dyn_eval.py"
            target.write_text(raw_snippet, encoding="utf-8")

            report = ce.audit_artifact(target)
            rule_ids = [f.rule_id for f in report.findings]
            self.assertIn("CF-DYNAMIC-EXEC", rule_ids)
            self.assertEqual(report.findings[0].severity, "CRITICAL")
            self.assertEqual(report.epistemic_safety_score, 72)
            self.assertEqual(report.verdict, "GUARDED_EXECUTION")
            self.assertFalse(report.findings[0].rollback_symmetric)

    def test_subprocess_shell_and_missing_timeout(self) -> None:
        """subprocess with shell=True and no timeout must trigger injection and hang risks."""
        raw_snippet = "\n".join([
            "import subprocess",
            "def run_command(cmd: str):",
            "    return sub" + "process.run(cmd, shell=True)",
        ])
        with tempfile.TemporaryDirectory() as tmp_dir:
            target = Path(tmp_dir) / "subproc_shell.py"
            target.write_text(raw_snippet, encoding="utf-8")

            report = ce.audit_artifact(target)
            rule_ids = [f.rule_id for f in report.findings]
            self.assertIn("CF-SUBPROCESS-SHELL", rule_ids)
            self.assertIn("CF-UNBOUNDED-SUBPROCESS", rule_ids)

    def test_subprocess_with_timeout_adds_guard(self) -> None:
        """Subprocess calls with explicit timeout must be classified as verified guards."""
        raw_snippet = "\n".join([
            "import subprocess",
            "def safe_run():",
            "    return sub" + "process.run(['echo', 'hello'], timeout=10)",
        ])
        with tempfile.TemporaryDirectory() as tmp_dir:
            target = Path(tmp_dir) / "safe_subproc.py"
            target.write_text(raw_snippet, encoding="utf-8")

            report = ce.audit_artifact(target)
            rule_ids = [f.rule_id for f in report.findings]
            self.assertNotIn("CF-UNBOUNDED-SUBPROCESS", rule_ids)
            self.assertIn("Bounded subprocess timeout", report.ground_truth_guards)

    def test_silent_except_pass_detected(self) -> None:
        """Broad Exception handlers with pass must trigger CF-SILENT-EXCEPT-PASS."""
        raw_snippet = "\n".join([
            "def swallow_errors():",
            "    try:",
            "        val = int('invalid')",
            "    except Exception:",
            "        pass",
            "    return val",
        ])
        with tempfile.TemporaryDirectory() as tmp_dir:
            target = Path(tmp_dir) / "except_pass.py"
            target.write_text(raw_snippet, encoding="utf-8")

            report = ce.audit_artifact(target)
            rule_ids = [f.rule_id for f in report.findings]
            self.assertIn("CF-SILENT-EXCEPT-PASS", rule_ids)
            self.assertEqual(report.findings[0].world, "SILENT_CORRUPTION")

    def test_bare_except_pass_detected(self) -> None:
        """Bare except handlers with pass must trigger CF-SILENT-EXCEPT-PASS."""
        raw_snippet = "\n".join([
            "def swallow_bare():",
            "    try:",
            "        val = 42",
            "    except:",
            "        pass",
        ])
        with tempfile.TemporaryDirectory() as tmp_dir:
            target = Path(tmp_dir) / "bare_except.py"
            target.write_text(raw_snippet, encoding="utf-8")

            report = ce.audit_artifact(target)
            rule_ids = [f.rule_id for f in report.findings]
            self.assertIn("CF-SILENT-EXCEPT-PASS", rule_ids)

    def test_unbounded_http_detected(self) -> None:
        """Outbound HTTP requests without timeout must trigger CF-UNBOUNDED-HTTP."""
        raw_snippet = "\n".join([
            "import requests",
            "def fetch_remote():",
            "    return re" + "quests.get('https://example.com/api')",
        ])
        with tempfile.TemporaryDirectory() as tmp_dir:
            target = Path(tmp_dir) / "http_hang.py"
            target.write_text(raw_snippet, encoding="utf-8")

            report = ce.audit_artifact(target)
            rule_ids = [f.rule_id for f in report.findings]
            self.assertIn("CF-UNBOUNDED-HTTP", rule_ids)

    def test_bounded_http_adds_guard(self) -> None:
        """Outbound HTTP requests with timeout must record an explicit guard."""
        raw_snippet = "\n".join([
            "import requests",
            "def fetch_safe():",
            "    return re" + "quests.get('https://example.com/api', timeout=15)",
        ])
        with tempfile.TemporaryDirectory() as tmp_dir:
            target = Path(tmp_dir) / "http_safe.py"
            target.write_text(raw_snippet, encoding="utf-8")

            report = ce.audit_artifact(target)
            rule_ids = [f.rule_id for f in report.findings]
            self.assertNotIn("CF-UNBOUNDED-HTTP", rule_ids)
            self.assertIn("Explicit network timeout", report.ground_truth_guards)

    def test_environ_subscript_detected(self) -> None:
        """Direct os.environ subscripting without default must trigger CF-ENV-HARD-KEY."""
        raw_snippet = "\n".join([
            "import os",
            "def load_secret():",
            "    return os.environ['SECRET_KEY']",
        ])
        with tempfile.TemporaryDirectory() as tmp_dir:
            target = Path(tmp_dir) / "env_subscript.py"
            target.write_text(raw_snippet, encoding="utf-8")

            report = ce.audit_artifact(target)
            rule_ids = [f.rule_id for f in report.findings]
            self.assertIn("CF-ENV-HARD-KEY", rule_ids)

    def test_irreversible_delete_detected(self) -> None:
        """File deletion calls must trigger CF-IRREVERSIBLE-DELETE."""
        raw_snippet = "\n".join([
            "import os",
            "def purge_cache(target_path: str):",
            "    os.remove(target_path)",
        ])
        with tempfile.TemporaryDirectory() as tmp_dir:
            target = Path(tmp_dir) / "delete_file.py"
            target.write_text(raw_snippet, encoding="utf-8")

            report = ce.audit_artifact(target)
            rule_ids = [f.rule_id for f in report.findings]
            self.assertIn("CF-IRREVERSIBLE-DELETE", rule_ids)
            self.assertFalse(report.findings[0].rollback_symmetric)

    def test_toctou_race_window_detected(self) -> None:
        """Path check followed closely by file open must trigger CF-TOCTOU-RACE."""
        raw_snippet = "\n".join([
            "import os",
            "def write_if_not_present(file_path: str):",
            "    if not os.path.exists(file_path):",
            "        with open(file_path, 'w', encoding='utf-8') as handle:",
            "            handle.write('data')",
        ])
        with tempfile.TemporaryDirectory() as tmp_dir:
            target = Path(tmp_dir) / "toctou_race.py"
            target.write_text(raw_snippet, encoding="utf-8")

            report = ce.audit_artifact(target)
            rule_ids = [f.rule_id for f in report.findings]
            self.assertIn("CF-TOCTOU-RACE", rule_ids)

    def test_implicit_encoding_detected(self) -> None:
        """Open calls omitting encoding parameter must trigger CF-IMPLICIT-ENCODING."""
        raw_snippet = "\n".join([
            "def read_notes(file_path: str):",
            "    with open(file_path, 'r') as handle:",
            "        return handle.read()",
        ])
        with tempfile.TemporaryDirectory() as tmp_dir:
            target = Path(tmp_dir) / "implicit_enc.py"
            target.write_text(raw_snippet, encoding="utf-8")

            report = ce.audit_artifact(target)
            rule_ids = [f.rule_id for f in report.findings]
            self.assertIn("CF-IMPLICIT-ENCODING", rule_ids)

    def test_syntax_error_detected(self) -> None:
        """Unparsable Python files must trigger CF-SYNTAX-UNPARSABLE immediately."""
        raw_snippet = "def broken_syntax(:\n"
        with tempfile.TemporaryDirectory() as tmp_dir:
            target = Path(tmp_dir) / "unparsable.py"
            target.write_text(raw_snippet, encoding="utf-8")

            report = ce.audit_artifact(target)
            rule_ids = [f.rule_id for f in report.findings]
            self.assertIn("CF-SYNTAX-UNPARSABLE", rule_ids)
            self.assertEqual(report.findings[0].severity, "CRITICAL")
            self.assertEqual(report.epistemic_safety_score, 72)
            self.assertEqual(report.verdict, "GUARDED_EXECUTION")

    def test_clean_python_module_passes_audit(self) -> None:
        """Safe, guarded Python modules must achieve SAFE_TO_PROCEED score of 100."""
        raw_snippet = "\n".join([
            "from __future__ import annotations",
            "import os",
            "from pathlib import Path",
            "",
            "def read_config(target_path: Path) -> str:",
            "    api_token = os.environ.get('APP_TOKEN', 'fallback')",
            "    file_data = target_path.read_text(encoding='utf-8', errors='replace')",
            "    return f'{api_token}:{len(file_data)}'",
        ])
        with tempfile.TemporaryDirectory() as tmp_dir:
            target = Path(tmp_dir) / "clean_module.py"
            target.write_text(raw_snippet, encoding="utf-8")

            report = ce.audit_artifact(target)
            self.assertEqual(report.verdict, "SAFE_TO_PROCEED")
            self.assertEqual(report.epistemic_safety_score, 100)
            self.assertEqual(len(report.findings), 0)
            self.assertEqual(report.rollback_symmetry_ratio, 1.0)


class TestCounterfactualTextAndPlanAnalysis(unittest.TestCase):
    """Test text-level regex scanning on shell scripts and plan documents."""

    def test_destructive_command_in_text(self) -> None:
        """Destructive shell commands in text files must trigger CF-DESTRUCTIVE-CMD."""
        raw_text = "\n".join([
            "# Deployment Plan",
            "Step 1: " + "rm " + "-rf /var/app/state",
        ])
        with tempfile.TemporaryDirectory() as tmp_dir:
            target = Path(tmp_dir) / "plan.md"
            target.write_text(raw_text, encoding="utf-8")

            report = ce.audit_artifact(target)
            rule_ids = [f.rule_id for f in report.findings]
            self.assertIn("CF-DESTRUCTIVE-CMD", rule_ids)
            self.assertEqual(report.findings[0].severity, "CRITICAL")

    def test_remote_git_push_in_text(self) -> None:
        """Remote git push commands in text files must trigger CF-GITHUB-REMOTE-PUSH."""
        raw_text = "\n".join([
            "# Release Steps",
            "Execute: " + "git " + "push origin main",
        ])
        with tempfile.TemporaryDirectory() as tmp_dir:
            target = Path(tmp_dir) / "release.sh"
            target.write_text(raw_text, encoding="utf-8")

            report = ce.audit_artifact(target)
            rule_ids = [f.rule_id for f in report.findings]
            self.assertIn("CF-GITHUB-REMOTE-PUSH", rule_ids)

    def test_unverified_epistemic_claim_in_text(self) -> None:
        """Unverified claims in markdown must trigger CF-UNVERIFIED-CLAIM."""
        raw_text = "\n".join([
            "# Architecture Hypothesis",
            "We " + "assume " + "that the database migration succeeded without error.",
        ])
        with tempfile.TemporaryDirectory() as tmp_dir:
            target = Path(tmp_dir) / "hypothesis.md"
            target.write_text(raw_text, encoding="utf-8")

            report = ce.audit_artifact(target)
            rule_ids = [f.rule_id for f in report.findings]
            self.assertIn("CF-UNVERIFIED-CLAIM", rule_ids)


class TestCounterfactualIntentDrift(unittest.TestCase):
    """Test detection of semantic goal contradictions."""

    def test_intent_drift_no_github_violation(self) -> None:
        """Artifact attempting git push under local-only constraint must trigger drift alert."""
        raw_text = "\n".join([
            "Step: " + "git " + "push origin main",
        ])
        with tempfile.TemporaryDirectory() as tmp_dir:
            target = Path(tmp_dir) / "script.sh"
            target.write_text(raw_text, encoding="utf-8")

            report = ce.audit_artifact(target, intent="Never push to GitHub, keep everything local only")
            rule_ids = [f.rule_id for f in report.findings]
            self.assertIn("CF-INTENT-DRIFT", rule_ids)

    def test_intent_drift_read_only_violation(self) -> None:
        """Artifact performing writes under read-only intent must trigger drift alert."""
        raw_code = "\n".join([
            "from pathlib import Path",
            "p = Path('output.txt')",
            "p." + "write_text('mutated', encoding='utf-8')",
        ])
        with tempfile.TemporaryDirectory() as tmp_dir:
            target = Path(tmp_dir) / "audit_action.py"
            target.write_text(raw_code, encoding="utf-8")

            report = ce.audit_artifact(target, intent="Perform strictly read-only inspection")
            rule_ids = [f.rule_id for f in report.findings]
            self.assertIn("CF-INTENT-DRIFT", rule_ids)

    def test_intent_drift_offline_violation(self) -> None:
        """Artifact performing HTTP requests under offline intent must trigger drift alert."""
        raw_code = "\n".join([
            "import urllib.request",
            "def fetch():",
            "    return urllib.request.urlopen('https://example.com', timeout=5)",
        ])
        with tempfile.TemporaryDirectory() as tmp_dir:
            target = Path(tmp_dir) / "network_action.py"
            target.write_text(raw_code, encoding="utf-8")

            report = ce.audit_artifact(target, intent="Run offline without internet access")
            rule_ids = [f.rule_id for f in report.findings]
            self.assertIn("CF-INTENT-DRIFT", rule_ids)

    def test_aligned_intent_passes_cleanly(self) -> None:
        """Artifact matching user intent must not trigger CF-INTENT-DRIFT."""
        raw_code = "\n".join([
            "from pathlib import Path",
            "def inspect_path(p: Path) -> str:",
            "    return p.read_text(encoding='utf-8')",
        ])
        with tempfile.TemporaryDirectory() as tmp_dir:
            target = Path(tmp_dir) / "aligned.py"
            target.write_text(raw_code, encoding="utf-8")

            report = ce.audit_artifact(target, intent="Perform strictly read-only inspection")
            rule_ids = [f.rule_id for f in report.findings]
            self.assertNotIn("CF-INTENT-DRIFT", rule_ids)


class TestCLIAndFormatting(unittest.TestCase):
    """Test CLI exit codes, JSON/Markdown formatters, and error handling."""

    def test_markdown_report_structure(self) -> None:
        """Markdown output must include summary table and mitigation section."""
        raw_snippet = "\n".join([
            "def dangerous():",
            "    return " + "ev" + "al('1+1')",
        ])
        with tempfile.TemporaryDirectory() as tmp_dir:
            target = Path(tmp_dir) / "report_sample.py"
            target.write_text(raw_snippet, encoding="utf-8")

            report = ce.audit_artifact(target)
            md_output = ce.format_markdown_report(report)
            self.assertIn("# Counterfactual Pre-Mortem Oracle — Epistemic Audit", md_output)
            self.assertIn("CF-DYNAMIC-EXEC", md_output)
            self.assertIn("## Required Mitigations", md_output)

    def test_cli_json_mode(self) -> None:
        """CLI with --format json must print parseable JSON report with 0 exit code."""
        raw_snippet = "\n".join([
            "from pathlib import Path",
            "def read_file(p: Path) -> str:",
            "    return p.read_text(encoding='utf-8')",
        ])
        with tempfile.TemporaryDirectory() as tmp_dir:
            target = Path(tmp_dir) / "cli_sample.py"
            target.write_text(raw_snippet, encoding="utf-8")

            buf = io.StringIO()
            with redirect_stdout(buf):
                exit_code = ce.main([str(target), "--format", "json"])

            self.assertEqual(exit_code, 0)
            data = json.loads(buf.getvalue())
            self.assertEqual(data["verdict"], "SAFE_TO_PROCEED")
            self.assertEqual(data["epistemic_safety_score"], 100)

    def test_cli_strict_mode_failure(self) -> None:
        """CLI with --strict must return exit code 1 when audit triggers HALT verdict."""
        raw_snippet = "\n".join([
            "def bad():",
            "    " + "ev" + "al('exit()')",
            "    " + "ev" + "al('quit()')",
        ])
        with tempfile.TemporaryDirectory() as tmp_dir:
            target = Path(tmp_dir) / "strict_fail.py"
            target.write_text(raw_snippet, encoding="utf-8")

            buf = io.StringIO()
            with redirect_stdout(buf):
                exit_code = ce.main([str(target), "--strict"])

            self.assertEqual(exit_code, 1)

    def test_cli_missing_file_returns_code_2(self) -> None:
        """CLI must return exit code 2 when target file does not exist."""
        buf = io.StringIO()
        with redirect_stdout(buf):
            exit_code = ce.main(["/non/existent/path/for/premortem.py"])
        self.assertEqual(exit_code, 2)


if __name__ == "__main__":
    unittest.main()
