"""Phase 3 CLI end-to-end tests.

These exercise the actual CLI entry point via subprocess so we test the
argparse path and file writing exactly as a user would, not just via
main() with an argv list.
"""
import csv
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "netscan_lite.py"
PYTHON = [sys.executable, "-u", str(SCRIPT)]


class CliExportE2E(unittest.TestCase):
    def _run(self, *args):
        p = subprocess.run(
            PYTHON + list(args),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return p

    def test_json_stdout_is_parseable(self):
        p = self._run("--target", "127.0.0.1", "--ports", "22", "--timeout", "0.1", "--output", "json", "--mode", "tcp")
        self.assertEqual(p.returncode, 0, msg=p.stderr)
        payload = json.loads(p.stdout)
        self.assertIn("metadata", payload)
        self.assertIn("results", payload)

    def test_csv_stdout_is_parseable(self):
        p = self._run("--target", "127.0.0.1", "--ports", "22", "--timeout", "0.1", "--output", "csv", "--mode", "tcp")
        self.assertEqual(p.returncode, 0, msg=p.stderr)
        text = p.stdout
        reader = csv.DictReader(text.splitlines())
        rows = list(reader)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["target"], "127.0.0.1")

    def test_all_writes_both_files(self):
        with tempfile.TemporaryDirectory() as d:
            base = Path(d) / "scan"
            p = self._run(
                "--target", "127.0.0.1",
                "--ports", "22",
                "--timeout", "0.1",
                "--output", "all",
                "--output-file", str(base),
                "--mode", "tcp",
            )
            self.assertEqual(p.returncode, 0, msg=p.stderr)
            json_path = Path(str(base) + ".json")
            csv_path = Path(str(base) + ".csv")
            self.assertTrue(json_path.exists())
            self.assertTrue(csv_path.exists())
            payload = json.loads(json_path.read_text())
            self.assertIn("metadata", payload)
            self.assertIn("results", payload)
            rows = list(csv.DictReader(csv_path.read_text().splitlines()))
            self.assertEqual(len(rows), 1)

    def test_json_file_written(self):
        with tempfile.TemporaryDirectory() as d:
            out_path = Path(d) / "report.json"
            p = self._run(
                "--target", "127.0.0.1",
                "--ports", "22",
                "--timeout", "0.1",
                "--output", "json",
                "--output-file", str(out_path),
                "--mode", "tcp",
            )
            self.assertEqual(p.returncode, 0, msg=p.stderr)
            data = json.loads(out_path.read_text())
            self.assertIn("metadata", data)
            self.assertIn("results", data)

    def test_csv_file_written(self):
        with tempfile.TemporaryDirectory() as d:
            out_path = Path(d) / "report.csv"
            p = self._run(
                "--target", "127.0.0.1",
                "--ports", "22",
                "--timeout", "0.1",
                "--output", "csv",
                "--output-file", str(out_path),
                "--mode", "tcp",
            )
            self.assertEqual(p.returncode, 0, msg=p.stderr)
            reader = csv.DictReader(out_path.read_text().splitlines())
            rows = list(reader)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["target"], "127.0.0.1")


if __name__ == "__main__":
    unittest.main()
