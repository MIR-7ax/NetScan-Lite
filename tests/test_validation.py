"""Unit tests for input validation and scope authorization."""

import unittest
import sys
from pathlib import Path

# Add parent directory to path to import netscan_lite
sys.path.insert(0, str(Path(__file__).parent.parent))

from netscan_lite import is_authorized_target, validate_port_range, validate_subnet


class TestAuthorizedTarget(unittest.TestCase):
    """Test target authorization checks."""

    def test_loopback_authorized(self):
        """Loopback addresses should be authorized."""
        self.assertTrue(is_authorized_target("127.0.0.1")[0])
        self.assertTrue(is_authorized_target("127.0.0.255")[0])

    def test_private_authorized(self):
        """Private IP addresses should be authorized."""
        self.assertTrue(is_authorized_target("10.0.0.1")[0])
        self.assertTrue(is_authorized_target("192.168.1.1")[0])
        self.assertTrue(is_authorized_target("172.16.0.1")[0])

    def test_link_local_rejected(self):
        """Link-local addresses should be rejected (not in authorized scope)."""
        result, reason = is_authorized_target("169.254.1.1")
        self.assertFalse(result)
        self.assertIn("authorized", reason.lower())

    def test_public_rejected(self):
        """Public IP addresses should be rejected."""
        result, reason = is_authorized_target("8.8.8.8")
        self.assertFalse(result)
        self.assertIn("unauthorized", reason.lower())

        result, reason = is_authorized_target("1.1.1.1")
        self.assertFalse(result)

    def test_invalid_address_rejected(self):
        """Invalid IP addresses should be rejected."""
        result, reason = is_authorized_target("invalid")
        self.assertFalse(result)
        self.assertIn("invalid", reason.lower())

        result, reason = is_authorized_target("999.999.999.999")
        self.assertFalse(result)


class TestPortRangeValidation(unittest.TestCase):
    """Test port range validation."""

    def test_single_port(self):
        """Single port should be valid."""
        start, end = validate_port_range("80")
        self.assertEqual(start, 80)
        self.assertEqual(end, 80)

    def test_port_range(self):
        """Port range should be valid."""
        start, end = validate_port_range("1-100")
        self.assertEqual(start, 1)
        self.assertEqual(end, 100)

    def test_invalid_port_format(self):
        """Invalid port format should raise ValueError."""
        with self.assertRaises(ValueError):
            validate_port_range("80-100-200")

        with self.assertRaises(ValueError):
            validate_port_range("abc")

    def test_port_out_of_range(self):
        """Ports outside 1-65535 should be invalid."""
        with self.assertRaises(ValueError):
            validate_port_range("0")

        with self.assertRaises(ValueError):
            validate_port_range("65536")

        with self.assertRaises(ValueError):
            validate_port_range("0-100")

    def test_start_greater_than_end(self):
        """Start port greater than end port should be invalid."""
        with self.assertRaises(ValueError):
            validate_port_range("100-1")

    def test_range_too_large(self):
        """Ranges larger than 1000 ports should be rejected."""
        with self.assertRaises(ValueError):
            validate_port_range("1-2000")


class TestSubnetValidation(unittest.TestCase):
    """Test subnet validation."""

    def test_valid_subnet(self):
        """Valid subnets should pass validation."""
        self.assertTrue(validate_subnet("192.168.1.0/24"))
        self.assertTrue(validate_subnet("10.0.0.0/24"))
        self.assertTrue(validate_subnet("172.16.0.0/24"))

    def test_invalid_subnet_format(self):
        """Invalid subnet format should raise ValueError."""
        with self.assertRaises(ValueError):
            validate_subnet("invalid")

        with self.assertRaises(ValueError):
            validate_subnet("192.168.1.0/33")

    def test_subnet_too_large(self):
        """Subnets larger than 256 addresses should be rejected."""
        with self.assertRaises(ValueError):
            validate_subnet("192.168.0.0/16")  # 65536 addresses

    def test_public_subnet_rejected(self):
        """Public subnets should be rejected."""
        with self.assertRaises(ValueError):
            validate_subnet("8.0.0.0/8")


if __name__ == '__main__':
    unittest.main()
