"""Unit tests for the TCP connect scanner.

These tests use loopback-only fixtures and mocked network paths where
possible. No rejected/authorized target ever triggers a real network probe,
because rejected targets raise ValueError before any socket is created.
"""
import socket
import threading
import time
import unittest
from unittest import mock

from netscan.tcp_scanner import (
    scan_port,
    scan_ports,
    is_authorized_target,
    _connect_error_state,
    _connect_error_text,
)


class TestConnectErrorClassification(unittest.TestCase):
    """Verify errno-based state mapping matches the documented contract."""

    def test_zero_means_open(self):
        self.assertEqual(_connect_error_state(0), "open")

    def test_econrefused_means_closed(self):
        # Python maps ECONNREFUSED on Windows to errno.ECONNREFUSED
        self.assertEqual(_connect_error_state(10061), "closed")

    def test_wsaewouldblock_means_unknown(self):
        # connect_ex to a closed port returns WSAEWOULDBLOCK (10035)
        self.assertEqual(_connect_error_state(10035), "unknown")

    def test_wsaeetimedout_means_unknown(self):
        # WSAETIMEDOUT is 10060
        self.assertEqual(_connect_error_state(10060), "unknown")

    def test_unmapped_nonzero_means_unknown(self):
        self.assertEqual(_connect_error_state(99999), "unknown")

    def test_error_text_for_wsaewouldblock(self):
        self.assertEqual(_connect_error_text(10035), "timeout")

    def test_error_text_for_wsaetimedout(self):
        self.assertEqual(_connect_error_text(10060), "timeout")

    def test_error_text_for_econrefused(self):
        self.assertEqual(_connect_error_text(10061), "connection refused")

    def test_error_text_for_unmapped(self):
        self.assertEqual(_connect_error_text(99999), "connect error 99999")


class TestIsAuthorizedTarget(unittest.TestCase):
    """Authoriation logic shared by CLI and Flask."""

    def test_loopback_authorized(self):
        self.assertTrue(is_authorized_target("127.0.0.1")[0])

    def test_private_authorized(self):
        self.assertTrue(is_authorized_target("10.0.0.1")[0])
        self.assertTrue(is_authorized_target("192.168.1.1")[0])
        self.assertTrue(is_authorized_target("172.16.0.1")[0])

    def test_link_local_rejected(self):
        authorized, reason = is_authorized_target("169.254.1.1")
        self.assertFalse(authorized)
        self.assertIn("authorized", reason.lower())

    def test_public_rejected(self):
        authorized, reason = is_authorized_target("8.8.8.8")
        self.assertFalse(authorized)
        self.assertIn("unauthorized", reason.lower())

    def test_invalid_rejected(self):
        authorized, reason = is_authorized_target("not.an.ip")
        self.assertFalse(authorized)
        self.assertIn("invalid", reason.lower())


class TestScanPortLoopback(unittest.TestCase):
    """Live loopback probes only. No out-of-scope target is ever touched."""

    def test_open_port_reported_open(self):
        # Spin up a listener that accepts one connection then closes.
        server = socket.socket()
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        port = server.getsockname()[1]
        server.listen(1)
        acceptor = threading.Thread(target=lambda: server.accept()[0].close(), daemon=True)
        acceptor.start()
        time.sleep(0.2)

        try:
            result = scan_port("127.0.0.1", port, timeout=0.1)
        finally:
            server.close()
            acceptor.join(timeout=1)

        self.assertEqual(result["port"], port)
        self.assertEqual(result["state"], "open")
        self.assertIsNone(result["error"])
        self.assertEqual(result["service"], "unknown")

    def test_closed_port_has_unknown_state(self):
        # Port 9 is normally closed on loopback.
        result = scan_port("127.0.0.1", 9, timeout=0.1)
        self.assertEqual(result["port"], 9)
        self.assertEqual(result["state"], "unknown")
        self.assertEqual(result["error"], "timeout")

    def test_service_hint_mapped(self):
        self.assertEqual(scan_port("127.0.0.1", 22, timeout=0.1)["service"], "ssh")
        self.assertEqual(scan_port("127.0.0.1", 80, timeout=0.1)["service"], "http")
        self.assertEqual(scan_port("127.0.0.1", 8080, timeout=0.1)["service"], "http-proxy")
        self.assertEqual(scan_port("127.0.0.1", 12345, timeout=0.1)["service"], "unknown")

    def test_socket_closed_before_return(self):
        # Confirm the socket is closed even on a technically exceptional path.
        with mock.patch("socket.socket") as mock_socket:
            instance = mock_socket.return_value
            instance.connect_ex.return_value = 10035
            result = scan_port("127.0.0.1", 7, timeout=0.1)
            instance.close.assert_called_once()
        self.assertEqual(result["state"], "unknown")


class TestScanPortsAuthorization(unittest.TestCase):
    """Rejected targets never reach the executor."""

    def test_public_target_raises_before_socket(self):
        with mock.patch("netscan.tcp_scanner.socket") as mock_socket:
            with self.assertRaises(ValueError) as ctx:
                scan_ports("8.8.8.8", [22, 80])
            self.assertIn("Public or unauthorized address", str(ctx.exception))
            mock_socket.assert_not_called()

    def test_link_local_target_raises_before_socket(self):
        with mock.patch("netscan.tcp_scanner.socket") as mock_socket:
            with self.assertRaises(ValueError) as ctx:
                scan_ports("169.254.1.1", [22])
            self.assertIn("Link-local", str(ctx.exception))
            mock_socket.assert_not_called()

    def test_invalid_target_raises_before_socket(self):
        with mock.patch("netscan.tcp_scanner.socket") as mock_socket:
            with self.assertRaises(ValueError) as ctx:
                scan_ports("not.an.ip", [22])
            self.assertIn("Invalid IP", str(ctx.exception))
            mock_socket.assert_not_called()

    def test_timeout_validation(self):
        with self.assertRaises(ValueError):
            scan_ports("127.0.0.1", [22], timeout=-1)
        with self.assertRaises(ValueError):
            scan_ports("127.0.0.1", [22], timeout=0)


class TestScanPortsLoopback(unittest.TestCase):
    """Small live scans on loopback to validate the multi-port path."""

    def test_closed_and_open_mix(self):
        server = socket.socket()
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        open_port = server.getsockname()[1]
        server.listen(1)
        t = threading.Thread(target=lambda: server.accept()[0].close(), daemon=True)
        t.start()
        time.sleep(0.2)

        try:
            results = scan_ports("127.0.0.1", [9, open_port, 80], timeout=0.1)
        finally:
            server.close()
            t.join(timeout=1)

        by_port = {r["port"]: r for r in results}
        self.assertEqual(by_port[9]["state"], "unknown")
        self.assertEqual(by_port[open_port]["state"], "open")
        self.assertEqual(by_port[80]["service"], "http")
        self.assertEqual(results, sorted(results, key=lambda r: r["port"]))


class TestScanPortsSorting(unittest.TestCase):
    """Results must be sorted by port for consistent output."""

    def test_unsorted_input_is_sorted_out(self):
        with mock.patch("netscan.tcp_scanner.scan_port", side_effect=lambda target, port, timeout: {
            "port": port,
            "state": "closed",
            "service": "unknown",
            "error": None,
        }):
            results = scan_ports("127.0.0.1", [100, 10, 50], timeout=0.1)
        self.assertEqual([r["port"] for r in results], [10, 50, 100])


if __name__ == "__main__":
    unittest.main()
