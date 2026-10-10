"""Validation and authorization shared by CLI and Flask app.

This is the canonical place for the target allow policy, port-range
parsing, and subnet validation. netscan_lite.py imports from here so
the CLI continues to behave exactly as it did before the refactor.
"""
from ipaddress import ip_address, ip_network


def is_authorized_target(target: str):
    """Return (bool, reason) for the explicit scan allow list.

    Authorized by default (Phase 0 agreement):
        - Loopback (127.0.0.0/8)
        - Private (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)

    Rejected by default: link-local (169.254.0.0/16), multicast,
    reserved, and all global/public addresses. Link-local is not
    automatically allowed because it is auto-configured and not
    necessarily under user control; approve any change here in DEV.md.
    """
    try:
        ip = ip_address(target)
    except ValueError:
        return False, f"Invalid IP address: {target}"

    if ip.is_link_local:
        return False, "Link-local address not in authorized scope"
    if ip.is_loopback:
        return True, "Loopback address"
    if ip.is_private:
        return True, "Private IP address"
    return False, "Public or unauthorized address"


def validate_port_range(port_str: str):
    """Parse and validate a port spec like "22" or "1-100".

    Returns (start, end). Raises ValueError for invalid input.
    """
    if "-" in port_str:
        parts = port_str.split("-")
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
        if (end - start) > 1000:
            raise ValueError(f"Port range too large (max 1000 ports): {port_str}")
        return start, end

    try:
        port = int(port_str)
    except ValueError:
        raise ValueError(f"Port must be an integer: {port_str}")
    if not (1 <= port <= 65535):
        raise ValueError(f"Port must be between 1 and 65535: {port_str}")
    return port, port


def validate_subnet(subnet_str: str):
    """Validate a CIDR subnet with size and authorization limits.

    Raises ValueError for invalid, oversized, or out-of-scope subnets.
    """
    try:
        network = ip_network(subnet_str, strict=True)
    except ValueError as e:
        raise ValueError(f"Invalid subnet: {subnet_str}") from e

    if network.num_addresses > 256:
        raise ValueError(f"Subnet too large (max 256 addresses): {subnet_str}")
    if not network.is_private and not network.is_loopback:
        raise ValueError(f"Subnet must be private or loopback: {subnet_str}")
    return True


def parse_port_spec(ports_str: str):
    """Expand "1-100" or "22,80,443" or "1-100,443" into a sorted port list.

    Bound by the same 1000-port limit as the CLI. Raises ValueError on bad
    input. Returns list[int].
    """
    if "," in ports_str:
        port_list = []
        for spec in ports_str.split(","):
            start, end = validate_port_range(spec.strip())
            port_list.extend(range(start, end + 1))
        return port_list

    start, end = validate_port_range(ports_str)
    return list(range(start, end + 1))
