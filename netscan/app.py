"""Flask web application for NetScan-Lite.

The dashboard and API live here. The app runs on loopback only, and every
request is validated server-side before any network probe is initiated.
"""
import logging

from datetime import datetime, timezone

from flask import Flask, jsonify, render_template, request
from netscan.tcp_scanner import scan_ports
from netscan.validation import (
    is_authorized_target,
    parse_port_spec,
    validate_subnet,
)
from netscan_lite import normalize_results


app = Flask(__name__)

logger = logging.getLogger(__name__)


@app.route("/")
def index():
    """Render the main dashboard page."""
    return render_template("dashboard.html")


@app.route("/api/scan", methods=["POST"])
def api_scan():
    """Initiate a TCP connect scan against an authorized target.

    Expects JSON with keys:
        target  - IP address (required)
        ports   - port spec string, e.g. "1-100" or "22,80,443" (required)
        timeout - seconds, defaults to 1.0 if omitted
    """
    try:
        data = request.get_json(silent=True)
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400

        target = data.get("target")
        ports_str = data.get("ports")
        timeout = data.get("timeout", 1.0)

        if not target:
            return jsonify({"error": "Target is required"}), 400
        if not ports_str:
            return jsonify({"error": "Ports are required"}), 400

        # Server-side authorization first
        authorized, reason = is_authorized_target(target)
        if not authorized:
            return jsonify({"error": f"Target rejected - {reason}"}), 403

        # Server-side input validation
        try:
            port_list = parse_port_spec(ports_str)
        except ValueError as e:
            return jsonify({"error": str(e)}), 400

        if len(port_list) > 1000:
            return jsonify({"error": "Port range too large (max 1000 ports)"}), 400

        try:
            timeout_f = float(timeout)
        except (TypeError, ValueError):
            return jsonify({"error": "Invalid timeout value"}), 400

        if timeout_f <= 0:
            return jsonify({"error": "Timeout must be > 0"}), 400

        results = scan_ports(target, port_list, timeout=timeout_f)

        return jsonify(
            {
                "target": target,
                "timeout": timeout_f,
                "mode": "tcp",
                "results": results,
            }
        )

    except Exception as e:
        logger.exception("Unexpected scan error")
        return jsonify({"error": "Internal server error"}), 500


@app.route("/api/scan/export", methods=["POST"])
def api_scan_export():
    """Return a structured Phase 3 payload for the current scan result.

    This preserves the existing dashboard contract (target, timeout, mode,
    results) and adds normalized results, TCP banners where available, and
    scan metadata. The dashboard JS already renders the 'results' array; the
    extra keys are used by the JSON/CSV export buttons.
    """
    try:
        data = request.get_json(silent=True)
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400

        target = data.get("target")
        ports_str = data.get("ports")
        timeout = data.get("timeout", 1.0)

        if not target:
            return jsonify({"error": "Target is required"}), 400
        if not ports_str:
            return jsonify({"error": "Ports are required"}), 400

        authorized, reason = is_authorized_target(target)
        if not authorized:
            return jsonify({"error": f"Target rejected - {reason}"}), 403

        try:
            port_list = parse_port_spec(ports_str)
        except ValueError as e:
            return jsonify({"error": str(e)}), 400

        if len(port_list) > 1000:
            return jsonify({"error": "Port range too large (max 1000 ports)"}), 400

        try:
            timeout_f = float(timeout)
        except (TypeError, ValueError):
            return jsonify({"error": "Invalid timeout value"}), 400

        if timeout_f <= 0:
            return jsonify({"error": "Timeout must be > 0"}), 400

        scan_start = datetime.now(timezone.utc)
        results = scan_ports(target, port_list, timeout=timeout_f)
        scan_end = datetime.now(timezone.utc)

        normalized = normalize_results(target, results, protocol="tcp")

        metadata = {
            "scan_start": scan_start.isoformat(),
            "scan_end": scan_end.isoformat(),
            "elapsed_seconds": (scan_end - scan_start).total_seconds(),
            "timeout": timeout_f,
            "ports_scanned": len(port_list),
            "target": target,
            "mode": "tcp",
        }

        return jsonify(
            {
                "target": target,
                "timeout": timeout_f,
                "mode": "tcp",
                "results": results,
                "normalized_results": normalized,
                "metadata": metadata,
            }
        )

    except Exception as e:
        logger.exception("Unexpected scan error")
        return jsonify({"error": "Internal server error"}), 500


@app.route("/api/validate", methods=["POST"])
def api_validate():
    """Validate target and/or port spec without performing a scan.

    Expects optional JSON with keys:
        target  - IP address
        ports   - port spec string
        subnet  - CIDR string
    """
    try:
        data = request.get_json(silent=True)
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400

        target = data.get("target")
        ports_str = data.get("ports")
        subnet = data.get("subnet")

        response = {}

        if target:
            authorized, reason = is_authorized_target(target)
            response["target"] = {
                "value": target,
                "authorized": authorized,
                "reason": reason,
            }

        if ports_str:
            try:
                port_list = parse_port_spec(ports_str)
                if len(port_list) > 1000:
                    raise ValueError("Port range too large (max 1000 ports)")
                response["ports"] = {
                    "value": ports_str,
                    "valid": True,
                    "count": len(port_list),
                }
            except ValueError as e:
                response["ports"] = {
                    "value": ports_str,
                    "valid": False,
                    "error": str(e),
                }

        if subnet:
            try:
                validate_subnet(subnet)
                response["subnet"] = {
                    "value": subnet,
                    "valid": True,
                }
            except ValueError as e:
                response["subnet"] = {
                    "value": subnet,
                    "valid": False,
                    "error": str(e),
                }

        return jsonify(response)

    except Exception as e:
        logger.exception("Unexpected validation error")
        return jsonify({"error": "Internal server error"}), 500


if __name__ == "__main__":
    # Bind loopback-only in development so the scanner is not reachable
    # from other hosts. debug=True is acceptable for local learning use.
    app.run(host="127.0.0.1", port=5000, debug=True)
