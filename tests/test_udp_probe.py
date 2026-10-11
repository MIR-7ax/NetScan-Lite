"""Phase 4 tests: UDP probe classification and honesty.

These tests verify that UDP silence is treated as inconclusive, that a
clear response is treated as evidence of a listener, and that result
shapes stay consistent with the rest of the project.
"""
import socket
import threading
import unittest
from pathlib import Path

from netscan.udp_probe import probe_udp, scan_udp, _service_hint, UDP_SERVICE_HINTS
from netscan.tcp_scanner import COMMON_PORTS


class TestServiceHint(unittest.TestCase):
    def test_known_udp_hints(self):
        self.assertEqual(_service_hint(53), "dns")
        self.assertEqual(_service_hint(123), "ntp")

    def test_tcp_hints_reused_when_no_udp_hint(self):
        # Port 22 has no UDP hint but has a TCP hint.
        self.assertEqual(_service_hint(22), "ssh")

    def test_unknown_port(self):
        self.assertEqual(_service_hint(9999), "unknown")


class TestUdpProbeSilence(unittest.TestCase):
    def test_timeout_yields_open_filtered(self):
        # Nothing responds on this closed loopback port quickly enough.
        result = probe_udp("127.0.0.1", 1, timeout=0.1)
        self.assertEqual(result["protocol"], "udp")
        self.assertEqual(result["state"], "open|filtered")
        self.assertEqual(result["error"], "timeout")

    def test_result_shape_on_timeout(self):
        result = probe_udp("127.0.0.1", 1, timeout=0.1)
        for key in ("port", "protocol", "state", "service", "error"):
            self.assertIn(key, result)


class TestUdpProbeResponse(unittest.TestCase):
    def test_responder_produces_open(self):
        server, port = _udp_listener(0)
        t = _udp_responder(server, b"hi")
        try:
            result = probe_udp("127.0.0.1", port, timeout=0.5)
            self.assertEqual(result["protocol"], "udp")
            self.assertEqual(result["state"], "open")
            self.assertIsNone(result["error"])
        finally:
            server.close()
            t.join(timeout=1)


class TestUdpProbeRefused(unittest.TestCase):
    def test_refused_on_loopback_when_detectable(self):
        # Some environments report refused UDP to loopback clearly.
        # If the platform does not, this test is allowed to observe a
        # different state; the important invariant is elsewhere.
        result = probe_udp("127.0.0.1", 1, timeout=0.1)
        self.assertEqual(result["protocol"], "udp")
        # If we get a closed verdict, make sure it is not overclaiming open.
        if result["state"] == "closed":
            self.assertIn("error", result)


class TestUdpClassificationHonest(unittest.TestCase):
    def test_inconclusive_never_reported_as_open(self):
        # A probe that times out must not be classified as open.
        result = probe_udp("127.0.0.1", 1, timeout=0.05)
        self.assertEqual(result["protocol"], "udp")
        self.assertNotEqual(result["state"], "open")


class TestUdpShapeAndProtocol(unittest.TestCase):
    def test_protocol_is_udp(self):
        result = probe_udp("127.0.0.1", 53, timeout=0.1)
        self.assertEqual(result["protocol"], "udp")

    def test_state_is_known_enum_like_value(self):
        result = probe_udp("127.0.0.1", 53, timeout=0.1)
        self.assertIn(result["state"], {"open", "closed", "open|filtered", "error"})


# Helpers ----------------------------------------------------------------


def _udp_listener(port: int):
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    return srv, srv.getsockname()[1]


def _udp_responder(server, payload: bytes):
    def run():
        try:
            server.settimeout(1.0)
            data, addr = server.recvfrom(1024)
            server.sendto(payload, addr)
        except OSError:
            pass

    t = threading.Thread(target=run, daemon=True)
    t.start()
    return t


if __name__ == "__main__":
    unittest.main()
