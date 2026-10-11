"""Tests for the Flask app: route behavior, input validation, and safety.

Key safety property: rejected targets never result in a network probe,
and rejected targets raise ValueError in the scanner before any socket
is created. Those scanner-level guarantees are covered in
tests.test_tcp_scanner; here we verify that the HTTP layer enforces the
same policy and that the dashboard is served.
"""
import json
import unittest

from netscan.app import app
from netscan.validation import is_authorized_target, parse_port_spec, validate_subnet


class TestDashboard(unittest.TestCase):
    def test_index_returns_html(self):
        with app.test_client() as c:
            r = c.get("/")
            self.assertEqual(r.status_code, 200)
            self.assertIn("text/html", r.headers["Content-Type"])
            body = r.get_data(as_text=True)
            self.assertIn("scan-form", body)
            self.assertIn("results-table", body)

    def test_static_assets_served(self):
        with app.test_client() as c:
            for path in ("/static/styles.css", "/static/app.js"):
                r = c.get(path)
                self.assertEqual(r.status_code, 200, f"{path} should be served")
                self.assertIn("text/", r.headers["Content-Type"])


class TestValidationAPI(unittest.TestCase):
    def _post(self, **body):
        with app.test_client() as c:
            r = c.post("/api/validate", json=body, content_type="application/json")
            return r

    def test_empty_body_is_rejected(self):
        r = self._post()
        self.assertEqual(r.status_code, 400)
        self.assertIn("error", r.get_json())

    def test_missing_json_is_rejected(self):
        with app.test_client() as c:
            r = c.post("/api/validate")
            self.assertEqual(r.status_code, 400)

    def test_authorized_target(self):
        r = self._post(target="127.0.0.1")
        body = r.get_json()
        self.assertTrue(body["target"]["authorized"])
        self.assertEqual(body["target"]["value"], "127.0.0.1")

    def test_rejected_public_target(self):
        r = self._post(target="8.8.8.8")
        body = r.get_json()
        self.assertFalse(body["target"]["authorized"])
        self.assertIn("unauthorized", body["target"]["reason"].lower())

    def test_rejected_link_local_target(self):
        r = self._post(target="169.254.1.1")
        body = r.get_json()
        self.assertFalse(body["target"]["authorized"])
        self.assertIn("authorized", body["target"]["reason"].lower())

    def test_invalid_target(self):
        r = self._post(target="not.an.ip")
        body = r.get_json()
        self.assertFalse(body["target"]["authorized"])
        self.assertIn("invalid", body["target"]["reason"].lower())

    def test_valid_port_spec(self):
        r = self._post(ports="22,80-81,443")
        body = r.get_json()
        self.assertTrue(body["ports"]["valid"])
        self.assertEqual(body["ports"]["count"], 4)

    def test_invalid_port_spec(self):
        r = self._post(ports="abc")
        body = r.get_json()
        self.assertFalse(body["ports"]["valid"])
        self.assertIn("Port must be", body["ports"]["error"])

    def test_too_large_port_range(self):
        # 1-2000 exceeds the 1000-port limit
        r = self._post(ports="1-2000")
        body = r.get_json()
        self.assertFalse(body["ports"]["valid"])
        self.assertIn("too large", body["ports"]["error"].lower())

    def test_valid_subnet(self):
        r = self._post(subnet="192.168.1.0/24")
        body = r.get_json()
        self.assertTrue(body["subnet"]["valid"])

    def test_too_large_subnet(self):
        r = self._post(subnet="192.168.0.0/16")
        body = r.get_json()
        self.assertFalse(body["subnet"]["valid"])
        self.assertIn("too large", body["subnet"]["error"].lower())

    def test_public_subnet_rejected(self):
        r = self._post(subnet="8.0.0.0/8")
        body = r.get_json()
        self.assertFalse(body["subnet"]["valid"])


class TestScanAPI(unittest.TestCase):
    def _post(self, **body):
        with app.test_client() as c:
            r = c.post("/api/scan", json=body, content_type="application/json")
            return r

    def test_empty_body_is_rejected(self):
        r = self._post()
        self.assertEqual(r.status_code, 400)
        self.assertIn("error", r.get_json())

    def test_missing_target_rejected(self):
        r = self._post(ports="22")
        self.assertEqual(r.status_code, 400)
        self.assertIn("Target is required", r.get_json()["error"])

    def test_missing_ports_rejected(self):
        r = self._post(target="127.0.0.1")
        self.assertEqual(r.status_code, 400)
        self.assertIn("Ports are required", r.get_json()["error"])

    def test_public_target_rejected_with_403(self):
        r = self._post(target="8.8.8.8", ports="22")
        self.assertEqual(r.status_code, 403)
        self.assertIn("Public or unauthorized address", r.get_json()["error"])

    def test_link_local_target_rejected_with_403(self):
        r = self._post(target="169.254.1.1", ports="22")
        self.assertEqual(r.status_code, 403)
        self.assertIn("Link-local", r.get_json()["error"])

    def test_invalid_port_spec_rejected(self):
        r = self._post(target="127.0.0.1", ports="abc")
        self.assertEqual(r.status_code, 400)
        self.assertIn("Port must be", r.get_json()["error"])

    def test_too_large_port_range_rejected(self):
        r = self._post(target="127.0.0.1", ports="1-2000")
        self.assertEqual(r.status_code, 400)
        self.assertIn("too large", r.get_json()["error"].lower())

    def test_invalid_timeout_rejected(self):
        r = self._post(target="127.0.0.1", ports="22", timeout="not-a-number")
        self.assertEqual(r.status_code, 400)
        self.assertIn("Invalid timeout", r.get_json()["error"])

    def test_zero_timeout_rejected(self):
        r = self._post(target="127.0.0.1", ports="22", timeout=0)
        self.assertEqual(r.status_code, 400)
        self.assertIn("Timeout must be", r.get_json()["error"])

    def test_negative_timeout_rejected(self):
        r = self._post(target="127.0.0.1", ports="22", timeout=-0.5)
        self.assertEqual(r.status_code, 400)
        self.assertIn("Timeout must be", r.get_json()["error"])

    def test_successful_scan_shape(self):
        with app.test_client() as c:
            r = c.post(
                "/api/scan",
                json={"target": "127.0.0.1", "ports": "22", "timeout": 0.2},
                content_type="application/json",
            )
            self.assertEqual(r.status_code, 200)
            body = r.get_json()
            self.assertEqual(body["target"], "127.0.0.1")
            self.assertEqual(body["mode"], "tcp")
            self.assertIn("results", body)
            self.assertIsInstance(body["results"], list)
            for rec in body["results"]:
                self.assertIn("port", rec)
                self.assertIn("state", rec)
                self.assertIn("service", rec)
                self.assertIn("error", rec)

    def test_structured_export_added(self):
        with app.test_client() as c:
            r = c.post(
                "/api/scan/export",
                json={"target": "127.0.0.1", "ports": "22", "timeout": 0.2},
                content_type="application/json",
            )
            self.assertEqual(r.status_code, 200)
            body = r.get_json()
            self.assertEqual(body["target"], "127.0.0.1")
            self.assertEqual(body["mode"], "tcp")
            self.assertIn("results", body)
            self.assertIn("normalized_results", body)
            self.assertIn("metadata", body)
            self.assertIsInstance(body["normalized_results"], list)
            self.assertEqual(body["normalized_results"][0]["protocol"], "tcp")
            self.assertIn("banner", body["normalized_results"][0])
            self.assertIn("scan_start", body["metadata"])
            self.assertIn("elapsed_seconds", body["metadata"])
            self.assertIn("ports_scanned", body["metadata"])
            self.assertEqual(body["metadata"]["ports_scanned"], 1)

    def test_structured_export_rejects_public_target(self):
        with app.test_client() as c:
            r = c.post(
                "/api/scan/export",
                json={"target": "8.8.8.8", "ports": "22"},
                content_type="application/json",
            )
            self.assertEqual(r.status_code, 403)
            self.assertIn("unauthorized", r.get_json()["error"].lower())

    def test_structured_export_rejects_invalid_ports(self):
        with app.test_client() as c:
            r = c.post(
                "/api/scan/export",
                json={"target": "127.0.0.1", "ports": "bad"},
                content_type="application/json",
            )
            self.assertEqual(r.status_code, 400)
            self.assertIn("Port must be", r.get_json()["error"])



if __name__ == "__main__":
    unittest.main()
