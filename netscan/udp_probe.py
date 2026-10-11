"""UDP probe implementation for NetScan-Lite.

This is a best-effort UDP probe. UDP has no handshake, so silence is
ambiguous: we never treat "no response" as confirmed open.

Classification:
- any reply received        -> state: open
- clearly distinguishable refusal on this platform -> state: closed
- otherwise                 -> state: open|filtered, error: "timeout"
"""
from __future__ import annotations

import errno
import socket
from typing import Dict, List

from netscan.tcp_scanner import COMMON_PORTS, is_authorized_target

UDP_SERVICE_HINTS = {
    53: "dns",
    123: "ntp",
}


def _service_hint(port: int) -> str:
    return UDP_SERVICE_HINTS.get(port) or COMMON_PORTS.get(port, "unknown")


def probe_udp(target: str, port: int, timeout: float) -> Dict:
    """Send a single small UDP datagram and wait for a bounded response.

    Returns a dict with keys: port, state, service, error.
    state is one of: open, closed, open|filtered.
    """
    result: Dict = {
        "port": port,
        "protocol": "udp",
        "state": "open|filtered",
        "service": _service_hint(port),
        "error": None,
    }
    sock: socket.socket | None = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)

        # A minimal probe payload. We do not attempt protocol-specific
        # interrogation here beyond a tiny safe datagram.
        payload = b"\x00"
        sock.sendto(payload, (target, port))

        try:
            data, _ = sock.recvfrom(1024)
        except socket.timeout:
            # Silence is ambiguous.
            result["state"] = "open|filtered"
            result["error"] = "timeout"
            return result

        if data:
            result["state"] = "open"
            result["error"] = None
            return result

        # Empty reply still counts as evidence that something responded.
        result["state"] = "open"
        result["error"] = None
        return result

    except ConnectionRefusedError:
        # On some platforms a refused UDP target surfaces here.
        result["state"] = "closed"
        result["error"] = "connection refused"
        return result

    except OSError as e:
        _classify_os_error(result, e)
        return result

    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _classify_os_error(result: Dict, exc: OSError) -> None:
    """Try to distinguish a clear refusal from an inconclusive error.

    When in doubt, we stay conservative.
    """
    # Windows-coded errors sometimes surface as WinSock codes through OSError.
    win_sock_refused = getattr(errno, "WSAEHOSTUNREACH", None) or getattr(errno, "WSAENETUNREACH", None)

    if exc.errno in (errno.ECONNREFUSED,):
        result["state"] = "closed"
        result["error"] = "connection refused"
        return

    if exc.errno in (
        errno.WSAEHOSTUNREACH,
        errno.WSAENETUNREACH,
        errno.EHOSTUNREACH,
        errno.ENETUNREACH,
    ):
        # Reachable host but unreachable port/service is the strongest
        # non-timeout signal we commonly have for UDP.
        result["state"] = "closed"
        result["error"] = "host or port unreachable"
        return

    # Anything else is treated as inconclusive.
    result["state"] = "open|filtered"
    result["error"] = "timeout"


def scan_udp(
    target: str,
    ports: List[int],
    timeout: float = 1.0,
    max_workers: int = 50,
) -> List[Dict]:
    """Scan multiple UDP ports on a target with bounded concurrency.

    Authorization and timeout validation are enforced before any probe.
    """
    if not isinstance(timeout, (int, float)) or timeout <= 0:
        raise ValueError("timeout must be > 0")

    authorized, reason = is_authorized_target(target)
    if not authorized:
        raise ValueError(f"Target rejected - {reason}")

    max_workers = min(max_workers, 200)
    results: List[Dict] = []

    import concurrent.futures

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {
            executor.submit(probe_udp, target, port, timeout): port
            for port in ports
        }
        for future in concurrent.futures.as_completed(future_to_port):
            try:
                results.append(future.result())
            except Exception as e:
                port = future_to_port[future]
                results.append({
                    "port": port,
                    "protocol": "udp",
                    "state": "error",
                    "service": _service_hint(port),
                    "error": str(e),
                })

    results.sort(key=lambda x: x["port"])
    return results
