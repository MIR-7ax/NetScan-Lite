"""TCP connect scanner implementation.

Edge cases:
- connect_ex returns 0 on a successful connection -> open
- connect_ex returns HTTP-WSAECONNREFUSED (10061) -> closed (the target actively refused)
- connect_ex returns WSAEWOULDBLOCK (10035) or WSAETIMEDOUT (10060) -> timeout -> unknown
- Other nonzero connect_ex results -> unknown
- socket.timeout / TimeoutError raised by connect_ex -> unknown
"""
import errno
import socket
import concurrent.futures
from typing import List, Dict

from ipaddress import ip_address


# Common TCP port to service name mapping
COMMON_PORTS = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "smb",
    993: "imaps",
    995: "pop3s",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8080: "http-proxy",
    8443: "https-alt",
}


def _connect_error_state(rc: int) -> str:
    if rc == 0:
        return "open"
    if rc == errno.ECONNREFUSED:
        return "closed"
    if rc == errno.WSAEWOULDBLOCK or rc == errno.WSAETIMEDOUT:
        return "unknown"
    return "unknown"


def _connect_error_text(rc: int) -> str:
    if rc == errno.WSAEWOULDBLOCK:
        return "timeout"
    if rc == errno.WSAETIMEDOUT:
        return "timeout"
    if rc == errno.ECONNREFUSED:
        return "connection refused"
    if rc == errno.WSAEADDRNOTAVAIL:
        return "address not available"
    return f"connect error {rc}"


def is_authorized_target(target: str):
    """Check if a target IP address is authorized for scanning.

    Reuses the same allow policy as Phase 1 CLI. Implementation kept
    local to this module and documented; do not extend the authorized
    set without a scope decision recorded in DEV.md.
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


def scan_port(target: str, port: int, timeout: float) -> Dict:
    """Scan a single TCP port on a target via a bounded connect_ex probe.

    Returns a dict with keys: port, state, service, error.
    state is one of: open, closed, unknown.
    """
    result: Dict = {
        "port": port,
        "state": "unknown",
        "service": COMMON_PORTS.get(port, "unknown"),
        "error": None,
    }
    sock: socket.socket | None = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        rc = sock.connect_ex((target, port))
        if rc == 0:
            result["state"] = "open"
        else:
            result["error"] = _connect_error_text(rc)
            result["state"] = _connect_error_state(rc)
    except (socket.timeout, TimeoutError):
        result["state"] = "unknown"
        result["error"] = "timeout"
    except socket.gaierror:
        result["state"] = "error"
        result["error"] = "hostname resolution failed"
    except OSError as e:
        result["state"] = "error"
        result["error"] = str(e)
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    return result


def scan_ports(
    target: str,
    ports: List[int],
    timeout: float = 1.0,
    max_workers: int = 50,
) -> List[Dict]:
    """Scan multiple TCP ports on a target with bounded concurrency.

    Has server-side authorization and validation built in (raises ValueError
    for rejected targets before any probe).
    """
    if not isinstance(timeout, (int, float)) or timeout <= 0:
        raise ValueError("timeout must be > 0")

    authorized, reason = is_authorized_target(target)
    if not authorized:
        raise ValueError(f"Target rejected - {reason}")

    # Reasonable bound; keep modest defaults
    max_workers = min(max_workers, 200)
    results: List[Dict] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {
            executor.submit(scan_port, target, port, timeout): port
            for port in ports
        }
        for future in concurrent.futures.as_completed(future_to_port):
            try:
                results.append(future.result())
            except Exception as e:
                port = future_to_port[future]
                results.append({
                    "port": port,
                    "state": "error",
                    "service": COMMON_PORTS.get(port, "unknown"),
                    "error": str(e),
                })

    results.sort(key=lambda x: x["port"])
    return results
