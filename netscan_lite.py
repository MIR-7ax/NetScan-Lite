#!/usr/bin/env python3
"""
NetScan-Lite: Custom TCP/UDP Port Scanner & Network Mapper

A minimal network scanner for educational purposes, demonstrating TCP/IP,
sockets, TCP connection establishment, UDP's connectionless behavior, and
structured scan reports.

This is the CLI entry point for the scanner.
"""

import argparse
import sys
from ipaddress import ip_address, ip_network


def is_authorized_target(target: str) -> tuple[bool, str]:
    """
    Check if a target IP address is authorized for scanning.

    Authorized targets (per Phase 0 agreement):
    - Loopback addresses (127.0.0.0/8)
    - Private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)

    Public/global targets and link-local addresses are rejected by default.
    Link-local (169.254.0.0/16) is auto-configured and not necessarily
    under user control.

    Args:
        target: IP address string to validate

    Returns:
        Tuple of (is_authorized, reason_string)
    """
    try:
        ip = ip_address(target)
    except ValueError:
        return False, f"Invalid IP address: {target}"

    # Reject link-local explicitly (not in authorized scope)
    if ip.is_link_local:
        return False, "Link-local address not in authorized scope"

    # Allow loopback
    if ip.is_loopback:
        return True, "Loopback address"

    # Allow private ranges (excludes link-local which we already rejected)
    if ip.is_private:
        return True, "Private IP address"

    # Reject everything else (public IPs, multicast, reserved, etc.)
    return False, "Public or unauthorized address"


def validate_port_range(port_str: str) -> tuple[int, int]:
    """
    Validate and parse a port range string.

    Args:
        port_str: Port range in format "START-END" or single port "PORT"

    Returns:
        Tuple of (start_port, end_port)

    Raises:
        ValueError: If the port range is invalid
    """
    if '-' in port_str:
        parts = port_str.split('-')
        if len(parts) != 2:
            raise ValueError(f"Invalid port range format: {port_str}")

        try:
            start = int(parts[0])
            end = int(parts[1])
        except ValueError:
            raise ValueError(f"Ports must be integers: {port_str}")

        if not (1 <= start <= 65535) or not (1 <= end <= 65535):
            raise ValueError(f"Ports must be between 1 and 65535: {port_str}")

        if start > end:
            raise ValueError(f"Start port must be <= end port: {port_str}")

        # Prevent excessively large ranges
        if (end - start) > 1000:
            raise ValueError(f"Port range too large (max 1000 ports): {port_str}")

        return start, end
    else:
        try:
            port = int(port_str)
        except ValueError:
            raise ValueError(f"Port must be an integer: {port_str}")

        if not (1 <= port <= 65535):
            raise ValueError(f"Port must be between 1 and 65535: {port_str}")

        return port, port


def validate_subnet(subnet_str: str) -> bool:
    """
    Validate a subnet CIDR notation.

    Args:
        subnet_str: Subnet in CIDR notation (e.g., "192.168.1.0/24")

    Returns:
        True if valid

    Raises:
        ValueError: If the subnet is invalid
    """
    try:
        network = ip_network(subnet_str, strict=True)
    except ValueError as e:
        raise ValueError(f"Invalid subnet: {subnet_str}") from e

    # Check if subnet is too large
    if network.num_addresses > 256:
        raise ValueError(f"Subnet too large (max 256 addresses): {subnet_str}")

    # Check if subnet is authorized
    if not network.is_private and not network.is_loopback:
        raise ValueError(f"Subnet must be private or loopback: {subnet_str}")

    return True


def parse_arguments():
    """
    Parse command-line arguments.

    Returns:
        argparse.Namespace: Parsed arguments
    """
    parser = argparse.ArgumentParser(
        description="NetScan-Lite: Educational TCP/UDP Port Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan single host on common ports
  python netscan_lite.py --target 127.0.0.1 --ports 1-100

  # Scan specific ports
  python netscan_lite.py --target 192.168.1.10 --ports 22,80,443

  # Scan a subnet (host discovery will be added in later phase)
  python netscan_lite.py --subnet 192.168.1.0/24 --ports 1-100

Note: Only loopback and private IP addresses are authorized for scanning.
Public/global targets and link-local addresses are rejected by default.
        """
    )

    # Target selection (mutually exclusive)
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument(
        '--target',
        type=str,
        help='Single target IP address to scan'
    )
    target_group.add_argument(
        '--subnet',
        type=str,
        help='Subnet in CIDR notation (e.g., 192.168.1.0/24)'
    )

    # Port specification
    parser.add_argument(
        '--ports',
        type=str,
        required=True,
        help='Port range (e.g., 1-100) or comma-separated ports (e.g., 22,80,443)'
    )

    # Scan mode
    parser.add_argument(
        '--mode',
        type=str,
        choices=['tcp', 'udp'],
        default='tcp',
        help='Scan mode: tcp (default) or udp'
    )

    # Report format
    parser.add_argument(
        '--output',
        type=str,
        choices=['json', 'csv'],
        help='Output format for scan results'
    )

    # Timeout
    parser.add_argument(
        '--timeout',
        type=float,
        default=1.0,
        help='Connection timeout in seconds (default: 1.0)'
    )

    return parser.parse_args()


def main():
    """Main entry point for the CLI."""
    args = parse_arguments()

    # Validate port range first (before any success messages)
    try:
        if ',' in args.ports:
            # Handle comma-separated ports
            port_list = []
            for port_str in args.ports.split(','):
                start, end = validate_port_range(port_str.strip())
                if start == end:
                    port_list.append(start)
                else:
                    port_list.extend(range(start, end + 1))
            port_count = len(port_list)
            port_summary = f"{port_count} ports"
        else:
            start, end = validate_port_range(args.ports)
            port_count = end - start + 1
            port_summary = f"{start}-{end} ({port_count} ports)"
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    # Validate target or subnet
    if args.target:
        authorized, reason = is_authorized_target(args.target)
        if not authorized:
            print(f"Error: Target rejected - {reason}", file=sys.stderr)
            print(f"Only loopback and private IP addresses are authorized.", file=sys.stderr)
            sys.exit(1)
        print(f"Target authorized: {args.target} ({reason})")
    elif args.subnet:
        try:
            validate_subnet(args.subnet)
            print(f"Subnet authorized: {args.subnet}")
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)

    # Print port summary after all validations pass
    if ',' in args.ports:
        print(f"Ports to scan: {port_summary}")
    else:
        print(f"Port range: {port_summary}")

    print(f"Scan mode: {args.mode}")
    print(f"Timeout: {args.timeout}s")

    if args.output:
        print(f"Output format: {args.output}")

    print("\nPhase 1: CLI and validation complete. Scanner implementation will be added in Phase 2.")
    print("No network probes were performed in this phase.")


if __name__ == '__main__':
    main()
