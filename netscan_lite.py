#!/usr/bin/env python3
"""NetScan-Lite: Custom TCP/UDP Port Scanner & Network Mapper

A minimal network scanner for educational purposes, demonstrating TCP/IP,
sockets, TCP connection establishment, UDP's connectionless behavior, and
structured scan reports.

CLI entry point.

Re-exports the canonical validation/authorization helpers so existing code
and tests that imported from netscan_lite continue to work.
"""
import argparse
import csv
import io
import json
import sys
from datetime import datetime, timezone

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


def parse_arguments(argv=None):
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
        help="Target IP address to scan (e.g., 127.0.0.1)",
    )
    target_group.add_argument(
        "--subnet",
        help="Subnet to scan in CIDR notation (e.g., 192.168.1.0/24)",
    )

    parser.add_argument(
        "--ports",
        required=True,
        help="Port range to scan (e.g., 1-100 or 22,80,443)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Connection timeout in seconds (default: 1.0)",
    )
    parser.add_argument(
        "--mode",
        choices=["tcp", "udp"],
        default="tcp",
        help="Scan mode (tcp or udp)",
    )
    parser.add_argument(
        "--output",
        choices=["console", "json", "csv", "all"],
        default="console",
        help="Output format (default: console)",
    )
    parser.add_argument(
        "--output-file",
        help="Output file path for JSON/CSV reports",
    )

    return parser.parse_args(argv)


def normalize_results(target: str, results: list[dict], protocol: str = "tcp") -> list[dict]:
    """Normalize scan results into a stable shape.

    Each result will have: target, port, protocol, state, service, banner, error.
    """
    normalized = []
    for r in results:
        normalized.append({
            "target": target,
            "port": r["port"],
            "protocol": protocol,
            "state": r["state"],
            "service": r.get("service", "unknown"),
            "banner": r.get("banner", ""),
            "error": r.get("error"),
        })
    return normalized


def print_console_report(target: str, results: list[dict], elapsed: float) -> None:
    """Print a human-readable scan report to stdout."""
    if elapsed is not None:
        print(f"\nScan completed in {elapsed:.2f} seconds")
    print(f"\n{'='*60}")
    print(f"NetScan-Lite Scan Report")
    print(f"{'='*60}")
    print(f"Target: {target}")
    print(f"Scanned: {len(results)} ports")
    print(f"{'='*60}")

    if not results:
        print("No ports scanned or no results returned.")
        return

    # Group by state
    by_state = {}
    for r in results:
        state = r["state"]
        if state not in by_state:
            by_state[state] = []
        by_state[state].append(r)

    for state in sorted(by_state.keys()):
        ports = by_state[state]
        print(f"\n{state.upper()} ({len(ports)} port{'s' if len(ports) != 1 else ''}):")
        for r in sorted(ports, key=lambda x: x["port"]):
            service = r.get("service", "unknown")
            banner = r.get("banner", "")
            if banner:
                print(f"  Port {r['port']:>5}/tcp  {service:<12} {banner[:50]}")
            else:
                print(f"  Port {r['port']:>5}/tcp  {service:<12}")

    print(f"\n{'='*60}")
    print(f"Scan completed: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"{'='*60}\n")


def write_json_report(results: list[dict], output_path: str, metadata: dict) -> None:
    """Write scan results to a JSON file."""
    report = {
        "metadata": metadata,
        "results": results,
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"JSON report written to: {output_path}")


def write_csv_report(results: list[dict], output_path: str, metadata: dict) -> None:
    """Write scan results to a CSV file."""
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        write_csv_report_to_writer(results, f, metadata)
    print(f"CSV report written to: {output_path}")


def write_csv_report_to_writer(
    results: list[dict], output_file, metadata: dict
) -> None:
    """Write scan results to a CSV writer (file or StringIO)."""
    fieldnames = [
        "target",
        "port",
        "protocol",
        "state",
        "service",
        "banner",
        "error",
        "scan_start",
        "scan_end",
        "elapsed_seconds",
        "timeout",
        "ports_scanned",
        "mode",
    ]
    writer = csv.DictWriter(output_file, fieldnames=fieldnames, extrasaction='ignore')
    writer.writeheader()
    for r in results:
        row = {**r, **metadata}
        writer.writerow(row)




def banner_grab_tcp(target: str, port: int, timeout: float) -> str:
    """Attempt to grab a banner from a TCP service.

    Returns the banner string if received, empty string otherwise.
    This is a best-effort operation; many services do not send banners
    without a proper application-layer request.
    """
    import socket as sock_module

    sock = sock_module.socket(sock_module.AF_INET, sock_module.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((target, port))
        # Try to receive any banner the service sends
        try:
            banner = sock.recv(1024)
            if banner:
                return banner.decode("utf-8", errors="replace").strip()
        except (sock_module.timeout, sock_module.error):
            pass
        return ""
    except (sock_module.timeout, sock_module.error, ConnectionRefusedError, OSError):
        return ""
    finally:
        try:
            sock.close()
        except OSError:
            pass


def main(argv=None):
    """Main entry point for the CLI.

    If argv is provided, parse that instead of sys.argv so tests can drive
    the CLI without touching process arguments.

    Returns the process exit code so callers (including tests) can inspect
    success/failure without calling sys.exit() themselves.
    """
    args = parse_arguments(argv=argv)

    # Validate target
    target = args.target
    if target:
        authorized, reason = is_authorized_target(target)
        if not authorized:
            print(f"Error: Target rejected - {reason}")
            print("Only loopback and private IP addresses are authorized for scanning.")
            return 1

    # Validate and parse ports
    try:
        ports = parse_port_spec(args.ports)
    except ValueError as e:
        print(f"Error: Invalid port specification: {e}")
        return 1

    if args.timeout <= 0:
        print("Error: Timeout must be positive")
        return 1

    # Perform TCP scan
    if args.mode == "tcp":
        start_time = datetime.now(timezone.utc)
        try:
            results = scan_ports(target, ports, timeout=args.timeout)
        except ValueError as e:
            print(f"Error: {e}")
            return 1
        end_time = datetime.now(timezone.utc)
        elapsed = (end_time - start_time).total_seconds()

        # Normalize results for consistent output
        normalized = normalize_results(target, results, protocol="tcp")

        # Output based on format choice
        if args.output in ("console", "all"):
            print_console_report(target, normalized, elapsed)

        # Single metadata dict for all report formats
        metadata = {
            "scan_start": start_time.isoformat(),
            "scan_end": end_time.isoformat(),
            "elapsed_seconds": elapsed,
            "timeout": args.timeout,
            "ports_scanned": len(ports),
            "target": target,
            "mode": args.mode,
        }

        # Determine output file paths (different extensions for each format)
        json_path = None
        csv_path = None
        if args.output_file:
            base = args.output_file
            if base.endswith((".json", ".csv")):
                base = base.rsplit(".", 1)[0]
            json_path = f"{base}.json"
            csv_path = f"{base}.csv"

        if args.output in ("json", "all"):
            path = json_path or args.output_file
            if path:
                write_json_report(normalized, path, metadata)
            else:
                report = {
                    "metadata": metadata,
                    "results": normalized,
                }
                json.dump(report, sys.stdout, indent=2, default=str)
                sys.stdout.write("\n")

        if args.output in ("csv", "all"):
            path = csv_path or args.output_file
            if path:
                write_csv_report(normalized, path, metadata)
            else:
                output = io.StringIO()
                write_csv_report_to_writer(normalized, output, metadata)
                sys.stdout.write(output.getvalue())
                sys.stdout.write("\n")

    elif args.mode == "udp":
        from netscan.udp_probe import scan_udp

        start_time = datetime.now(timezone.utc)
        try:
            results = scan_udp(target, ports, timeout=args.timeout)
        except ValueError as e:
            print(f"Error: {e}")
            return 1
        end_time = datetime.now(timezone.utc)
        elapsed = (end_time - start_time).total_seconds()

        normalized = normalize_results(target, results, protocol="udp")

        if args.output in ("console", "all"):
            print_console_report(target, normalized, elapsed)

        metadata = {
            "scan_start": start_time.isoformat(),
            "scan_end": end_time.isoformat(),
            "elapsed_seconds": elapsed,
            "timeout": args.timeout,
            "ports_scanned": len(ports),
            "target": target,
            "mode": args.mode,
        }

        json_path = None
        csv_path = None
        if args.output_file:
            base = args.output_file
            if base.endswith((".json", ".csv")):
                base = base.rsplit(".", 1)[0]
            json_path = f"{base}.json"
            csv_path = f"{base}.csv"

        if args.output in ("json", "all"):
            path = json_path or args.output_file
            if path:
                write_json_report(normalized, path, metadata)
            else:
                report = {
                    "metadata": metadata,
                    "results": normalized,
                }
                json.dump(report, sys.stdout, indent=2, default=str)
                sys.stdout.write("\n")

        if args.output in ("csv", "all"):
            path = csv_path or args.output_file
            if path:
                write_csv_report(normalized, path, metadata)
            else:
                output = io.StringIO()
                write_csv_report_to_writer(normalized, output, metadata)
                sys.stdout.write(output.getvalue())
                sys.stdout.write("\n")
    else:
        print(f"Error: Unknown scan mode '{args.mode}'")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
