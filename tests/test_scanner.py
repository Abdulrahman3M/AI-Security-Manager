"""Baseline security scanner tests with synthetic data only."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCANNER = Path(__file__).resolve().parents[1] / "scripts" / "asm.py"

def invoke(path, fmt="json"):
    return subprocess.run(
        [sys.executable, str(SCANNER), "scan", str(path), "--format", fmt],
        capture_output=True, text=True, check=False,
    )

class BaselineScannerTests(unittest.TestCase):
    def test_sensitive_secret_values_not_in_reports(self):
        with tempfile.TemporaryDirectory() as temp:
            secret = "this_is_a_fake_test_secret_123456"
            (Path(temp) / "config.py").write_text(f'api_key = "{secret}"\n')
            r = invoke(temp)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("ASM001", r.stdout)
            self.assertNotIn(secret, r.stdout)

    def test_explicit_rls_disable_is_flagged(self):
        with tempfile.TemporaryDirectory() as temp:
            (Path(temp) / "schema.sql").write_text(
                "ALTER TABLE public.accounts DISABLE ROW LEVEL SECURITY;\n"
            )
            result = json.loads(invoke(temp).stdout)
            self.assertTrue(any(x["rule_id"] == "ASM004" for x in result["findings"]))

    def test_env_file_is_not_read_and_is_flagged(self):
        with tempfile.TemporaryDirectory() as temp:
            (Path(temp) / ".env").write_text("SECRET_TOKEN=never_show_this_123456\n")
            r = invoke(temp, "markdown")
            self.assertIn("ASM011", r.stdout)
            self.assertNotIn("never_show_this", r.stdout)

    def test_sarif_valid_minimum_shape(self):
        with tempfile.TemporaryDirectory() as temp:
            (Path(temp) / "safe.txt").write_text("hello world\n")
            r = invoke(temp, "sarif")
            self.assertEqual(r.returncode, 0, r.stderr)
            data = json.loads(r.stdout)
            self.assertEqual(data["version"], "2.1.0")
            self.assertEqual(data["runs"][0]["tool"]["driver"]["name"],
                             "AI Security Manager")

    def test_ignored_directory_not_scanned(self):
        with tempfile.TemporaryDirectory() as temp:
            dep = Path(temp) / "node_modules"
            dep.mkdir()
            (dep / "bad.py").write_text('password="fake_secret_12345"\n')
            data = json.loads(invoke(temp).stdout)
            self.assertFalse(data["findings"])

    def test_existing_report_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            rpath = Path(temp) / "existing.md"
            rpath.write_text("keep")
            r = subprocess.run(
                [sys.executable, str(SCANNER), "scan", temp, "--output", str(rpath)],
                capture_output=True, text=True, check=False)
            self.assertEqual(r.returncode, 2)
            self.assertEqual(rpath.read_text(), "keep")

if __name__ == "__main__":
    unittest.main()
