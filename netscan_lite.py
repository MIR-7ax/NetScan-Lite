#!/usr/bin/env python3
"""
NetScan-Lite: Custom TCP/UDP Port Scanner & Network Mapper

A minimal network scanner for educational purposes, demonstrating TCP/IP,
sockets, TCP connection establishment, UDP's connectionless behavior, and
structured scan reports.

CLI entry point.

Re-exports the canonical validation/authorization helpers so existing code
and tests that imported from netscan_lite continue to work.
"""
import argparse
import sys

from netscan.tcp_scanner import scan_ports
from netscan.validation import (
    is_authorized_target,
    parse_port_spec,
    validate_subnet,
    validate_port_range,
)

__all__ = [
    "parse_arguments",
    "main",
    "is_authorized_target",
    "validate_port_range",
    "validate_subnet",
]


def parse_arguments():
    """Parse command-line arguments.

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
        """,
    )

    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument(
        "--target",
        type=str,
        help="Single target IP address to scan",
    )
    target_group.add_argument(
        "--subnet",
        type=str,
        help="Subnet in CIDR notation (e.g., 192.168.1.0/24)",
    )

    parser.add_argument(
        "--ports",
        type=str,
        required=True,
        help='Port range (e.g., 1-100) or comma-separated ports (e.g., 22,80,443)',
    )

    parser.add_argument(
        "--mode",
        type=str,
        choices=["tcp", "udp"],
        default="tcp",
        help="Scan mode: tcp (default) or udp",
    )

    parser.add_argument(
        "--output",
        type=str,
        choices=["json", "csv"],
        help="Output format for scan results",
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Connection timeout in seconds (default: 1.0)",
    )

    return parser.parse_args()


def main():
    """Main entry point for the CLI."""
    args = parse_arguments()

    # Validate ports first (fast, simple)
    try:
        port_list = parse_port_spec(args.ports)
        port_count = len(port_list)
        if args.ports and "," in args.ports:
            port_summary = f"{port_count} ports"
        else:
            if port_count == 1:
                port_summary = f"{port_list[0]} ({port_count} port)"
            else:
                port_summary = f"{port_list[0]}-{port_list[-1]} ({port_count} ports)"
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    # Validate target or subnet
    if args.target:
        authorized, reason = is_authorized_target(args.target)
        if not authorized:
            print(f"Error: Target rejected - {reason}", file=sys.stderr)
            print("Only loopback and private IP addresses are authorized.", file=sys.stderr)
            sys.exit(1)
        print(f"Target authorized: {args.target} ({reason})")
    elif args.subnet:
        try:
            validate_subnet(args.subnet)
            print(f"Subnet authorized: {args.subnet}")
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)

    print(f"Ports to scan: {port_summary}")
    print(f"Scan mode: {args.mode}")
    print(f"Timeout: {args.timeout}s")

    if args.output:
        print(f"Output format: {args.output}")

    if args.mode == "tcp":
        print("\nPerforming TCP connect scan\u2026")
        try:
            timeout_f = float(args.timeout)
        except (TypeError, ValueError):
            print("Error: Invalid timeout value", file=sys.stderr)
            sys.exit(1)
        try:
            results = scan_ports(args.target, port_list, timeout=timeout_f)
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)

        open_count = sum(1 for r in results if r["state"] == "open")
        if open_count:
            print(f"Open ports: {open_count}")
        else:
            print("No open TCP ports found in this range.")

        if args.output == "json":
            import json

            print(f"\nRaw JSON scan results:\n{json.dumps(results, indent=2)}")
        elif args.output == "csv":
            print("\nCSV scan results:")
            print("port,state,service,error")
            for r in results:
                print(f'{r["port"]},{r["state"]},{r["service"]},"{r["error"]}"')

        print(f"\nTotal ports scanned: {len(results)}")
    else:
        print(f"\n{args.mode.upper()} mode selected.")
        print("Network probing for this mode is not yet implemented in Phase 2.")
        print("Submit an authorized loopback/private target to proceed.")


if __name__ == "__main__":
    main()
