"""Phase 3 tests: result normalization, JSON/CSV reports, metadata, and best-effort TCP banner grabbing.

These tests parse generated JSON and CSV rather than relying on smoke output,
and they keep banners best-effort/honest: an empty banner is expected behavior,
not a scan failure.
"""
import csv
import io
import json
import socket
import tempfile
import unittest
from pathlib import Path

import netscan_lite
from netscan_lite import banner_grab_tcp, normalize_results
from netscan.tcp_scanner import scan_ports, scan_port, COMMON_PORTS

# Helpers ----------------------------------------------------------------

def _tcp_open_listener(port):
    """Start a one-connection loopback TCP listener on the given port.

    Returns (socket, port).
    """
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(1)
    return srv, srv.getsockname()[1]


def _accept_once(srv):
    """Accept a single connection then close it, in a daemon thread."""
    import threading
    t = threading.Thread(target=lambda: srv.accept()[0].close(), daemon=True)
    t.start()
    return t


# Normalization ----------------------------------------------------------

class TestNormalizeResults(unittest.TestCase):
    """Normalize results into a stable, comparable shape."""

    def test_normalizes_all_required_keys(self):
        results = [{"port": 22, "state": "open", "service": "ssh", "error": None}]
        normalized = netscan_lite.normalize_results("127.0.0.1", results, protocol="tcp")
        row = normalized[0]
        for key in ("target", "port", "protocol", "state", "service", "banner", "error"):
            self.assertIn(key, row)
        self.assertEqual(row["target"], "127.0.0.1")
        self.assertEqual(row["protocol"], "tcp")

    def test_missing_service_defaults_to_unknown(self):
        results = [{"port": 12345, "state": "unknown", "error": "timeout"}]
        normalized = netscan_lite.normalize_results("127.0.0.1", results, protocol="tcp")
        self.assertEqual(normalized[0]["service"], "unknown")

    def test_missing_banner_defaults_to_empty(self):
        results = [{"port": 80, "state": "unknown", "error": "timeout"}]
        normalized = netscan_lite.normalize_results("127.0.0.1", results, protocol="tcp")
        self.assertEqual(normalized[0]["banner"], "")

    def test_explicit_banner_preserved(self):
        results = [
            {
                "port": 22,
                "state": "open",
                "service": "ssh",
                "error": None,
                "banner": "SSH-2.0-test",
            }
        ]
        normalized = netscan_lite.normalize_results("127.0.0.1", results, protocol="tcp")
        self.assertEqual(normalized[0]["banner"], "SSH-2.0-test")

    def test_error_none_stays_none(self):
        results = [{"port": 22, "state": "open", "service": "ssh", "error": None}]
        normalized = netscan_lite.normalize_results("127.0.0.1", results, protocol="tcp")
        self.assertIsNone(normalized[0]["error"])

    def test_normalizes_multiple_results(self):
        results = [
            {"port": 22, "state": "open", "service": "ssh", "error": None},
            {"port": 80, "state": "unknown", "service": "http", "error": "timeout"},
        ]
        normalized = netscan_lite.normalize_results("192.168.1.1", results, protocol="tcp")
        self.assertEqual(len(normalized), 2)
        self.assertEqual(normalized[0]["target"], "192.168.1.1")
        self.assertEqual(normalized[1]["target"], "192.168.1.1")

    def test_udp_protocol_preserved(self):
        results = [{"port": 53, "state": "open|filtered", "error": None}]
        normalized = netscan_lite.normalize_results("127.0.0.1", results, protocol="udp")
        self.assertEqual(normalized[0]["protocol"], "udp")
        self.assertEqual(normalized[0]["state"], "open|filtered")


# JSON report ------------------------------------------------------------

class TestJsonReport(unittest.TestCase):
    """JSON output contains both metadata and a parseable results array."""

    def test_json_stdout_is_parseable_report(self):
        # Capture stdout while producing JSON on stdout.
        import contextlib
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            netscan_lite.main([
                "--target", "127.0.0.1",
                "--ports", "22",
                "--timeout", "0.1",
                "--output", "json",
                "--mode", "tcp",
            ])
        payload = json.loads(out.getvalue())
        self.assertIn("metadata", payload)
        self.assertIn("results", payload)
        self.assertIsInstance(payload["results"], list)

    def test_json_stdout_when_no_target_raises(self):
        import contextlib
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            with self.assertRaises(SystemExit) as ctx:
                netscan_lite.main([])
        self.assertIn(ctx.exception.code, (1, 2))

    def test_json_metadata_fields(self):
        import contextlib
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            netscan_lite.main([
                "--target", "127.0.0.1",
                "--ports", "22",
                "--timeout", "0.1",
                "--output", "json",
                "--mode", "tcp",
            ])
        meta = json.loads(out.getvalue())["metadata"]
        for key in (
            "scan_start",
            "scan_end",
            "elapsed_seconds",
            "timeout",
            "ports_scanned",
            "target",
            "mode",
        ):
            self.assertIn(key, meta)
        self.assertEqual(meta["target"], "127.0.0.1")
        self.assertEqual(meta["mode"], "tcp")
        self.assertEqual(meta["timeout"], 0.1)
        self.assertEqual(meta["ports_scanned"], 1)
        self.assertIsInstance(meta["elapsed_seconds"], (int, float))
        self.assertGreaterEqual(meta["elapsed_seconds"], 0)

    def test_json_results_match_normalized_shape(self):
        import contextlib
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            netscan_lite.main([
                "--target", "127.0.0.1",
                "--ports", "22,80",
                "--timeout", "0.2",
                "--output", "json",
                "--mode", "tcp",
            ])
        payload = json.loads(out.getvalue())
        for row in payload["results"]:
            for key in ("target", "port", "protocol", "state", "service", "banner", "error"):
                self.assertIn(key, row)
            self.assertEqual(row["target"], "127.0.0.1")
            self.assertEqual(row["protocol"], "tcp")

    def test_json_file_written_and_parseable(self):
        with tempfile.TemporaryDirectory() as d:
            out_path = Path(d) / "report.json"
            with open(out_path, "w") as f:
                pass
            rc = netscan_lite.main([
                "--target", "127.0.0.1",
                "--ports", "22",
                "--timeout", "0.1",
                "--output", "json",
                "--output-file", str(out_path),
                "--mode", "tcp",
            ])
            self.assertIsNone(rc)
            data = json.loads(out_path.read_text())
            self.assertIn("metadata", data)
            self.assertIn("results", data)
            self.assertTrue(out_path.exists())


# CSV report -------------------------------------------------------------

class TestCsvReport(unittest.TestCase):
    """CSV output is parseable and includes both result fields and metadata."""

    def test_csv_stdout_is_parseable(self):
        import contextlib
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            netscan_lite.main([
                "--target", "127.0.0.1",
                "--ports", "22",
                "--timeout", "0.1",
                "--output", "csv",
                "--mode", "tcp",
            ])
        text = out.getvalue()
        self.assertIn("\n", text)
        reader = csv.DictReader(io.StringIO(text))
        rows = list(reader)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["target"], "127.0.0.1")
        self.assertEqual(rows[0]["port"], "22")

    def test_csv_includes_metadata_columns(self):
        import contextlib
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            netscan_lite.main([
                "--target", "127.0.0.1",
                "--ports", "22",
                "--timeout", "0.1",
                "--output", "csv",
                "--mode", "tcp",
            ])
        reader = csv.DictReader(io.StringIO(out.getvalue()))
        fieldnames = reader.fieldnames or []
        for key in (
            "scan_start",
            "scan_end",
            "elapsed_seconds",
            "timeout",
            "ports_scanned",
            "mode",
        ):
            self.assertIn(key, fieldnames)

    def test_csv_file_written_and_parseable(self):
        with tempfile.TemporaryDirectory() as d:
            out_path = Path(d) / "report.csv"
            rc = netscan_lite.main([
                "--target", "127.0.0.1",
                "--ports", "22",
                "--timeout", "0.1",
                "--output", "csv",
                "--output-file", str(out_path),
                "--mode", "tcp",
            ])
            self.assertIsNone(rc)
            reader = csv.DictReader(out_path.read_text().splitlines())
            rows = list(reader)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["target"], "127.0.0.1")
            self.assertTrue(out_path.exists())


# All-formats file output ------------------------------------------------

class TestAllFormatsOutputFile(unittest.TestCase):
    """--output all writes both JSON and CSV when --output-file is used."""

    def test_writes_both_json_and_csv(self):
        with tempfile.TemporaryDirectory() as d:
            base = Path(d) / "scan"
            rc = netscan_lite.main([
                "--target", "127.0.0.1",
                "--ports", "22",
                "--timeout", "0.1",
                "--output", "all",
                "--output-file", str(base),
                "--mode", "tcp",
            ])
            self.assertIsNone(rc)
            json_path = Path(str(base) + ".json")
            csv_path = Path(str(base) + ".csv")
            self.assertTrue(json_path.exists())
            self.assertTrue(csv_path.exists())
            payload = json.loads(json_path.read_text())
            self.assertIn("metadata", payload)
            self.assertIn("results", payload)
            rows = list(csv.DictReader(csv_path.read_text().splitlines()))
            self.assertEqual(len(rows), 1)


# TCP banner grabbing ---------------------------------------------------

class TestBannerGrabTcp(unittest.TestCase):
    """banner_grab_tcp is best-effort and honest about empty banners."""

    def test_empty_banner_for_closed_port(self):
        banner = banner_grab_tcp("127.0.0.1", 1, timeout=0.1)
        self.assertIsInstance(banner, str)
        # Closed/unresponsive ports do not send a banner.
        self.assertEqual(banner, "")

    def test_empty_banner_for_discarding_listener(self):
        srv, port = _tcp_open_listener(0)
        t = _accept_once(srv)
        try:
            banner = banner_grab_tcp("127.0.0.1", port, timeout=0.2)
            self.assertIsInstance(banner, str)
            # A listener that accepts and immediately closes does not send data.
            self.assertEqual(banner, "")
        finally:
            srv.close()
            t.join(timeout=1)

    def test_banner_captured_from_smtp_like_listener(self):
        srv, port = _tcp_open_listener(0)
        greeter = b"220 test.local ESMTP\r\n"
        def serve():
            conn, _ = srv.accept()
            try:
                conn.sendall(greeter)
            finally:
                conn.close()
        import threading
        t = threading.Thread(target=serve, daemon=True)
        t.start()
        try:
            banner = banner_grab_tcp("127.0.0.1", port, timeout=0.5)
            self.assertEqual(banner, "220 test.local ESMTP")
        finally:
            srv.close()
            t.join(timeout=1)

    def test_timeout_returns_empty_string(self):
        banner = banner_grab_tcp("127.0.0.1", 9, timeout=0.05)
        self.assertIsInstance(banner, str)
        self.assertEqual(banner, "")

    def test_returns_empty_not_none(self):
        banner = banner_grab_tcp("127.0.0.1", 1, timeout=0.05)
        self.assertIsNotNone(banner)


if __name__ == "__main__":
    unittest.main()
