# Phase 1 — Minimal CLI, Validation, and Safe Scope

- Status: COMMITTED
- Started: 2026-10-10
- Completed for review: 2026-10-10
- User approval: Approved on 2026-10-10
- Git commit(s): 12d853f "feat: Phase 1 — CLI, validation, and safe scope"

## 1. Goal and agreed scope

**Goal:** Create a reliable CLI entry point and prevent accidental out-of-scope scanning before any network probes are implemented.

**Scope agreed with user:**

- Establish the minimal file layout with a CLI entry point (`netscan_lite.py`).
- Implement `argparse` options for targets, subnets, port ranges, scan modes, and report format.
- Implement robust input validation for IP addresses, subnets, and port ranges.
- Implement an explicit target allow policy that rejects public/unauthorized addresses before any network probes can occur.
- Provide useful help output and clear validation error messages.
- Create unit tests to prove rejected targets do not trigger network probes (validation logic is tested independently).
- No actual network scanning is implemented in this phase.

## 2. Work completed

### Files created

| File | Responsibility |
|------|----------------|
| `netscan_lite.py` | CLI entry point with argparse, input validation, and target authorization checks |
| `tests/__init__.py` | Test package initialization |
| `tests/test_validation.py` | Unit tests for validation and authorization logic |

### Implementation details

**CLI argument parsing (`parse_arguments`):**
- `--target`: Single target IP address (mutually exclusive with `--subnet`)
- `--subnet`: Subnet in CIDR notation (mutually exclusive with `--target`)
- `--ports`: Port range (e.g., "1-100") or comma-separated ports (e.g., "22,80,443")
- `--mode`: Scan mode selection (`tcp` or `udp`, default: `tcp`)
- `--output`: Report format (`json` or `csv`, optional)
- `--timeout`: Connection timeout in seconds (default: 1.0)

**Target authorization (`is_authorized_target`):**
- Accepts loopback addresses (127.0.0.0/8)
- Accepts private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- Rejects link-local addresses (169.254.0.0/16) by default
- Rejects public/global IP addresses
- Rejects invalid IP address formats

**Port range validation (`validate_port_range`):**
- Accepts single ports (e.g., "80")
- Accepts port ranges (e.g., "1-100")
- Validates ports are between 1 and 65535
- Ensures start port ≤ end port
- Rejects ranges larger than 1000 ports to prevent resource exhaustion

**Subnet validation (`validate_subnet`):**
- Validates CIDR notation using Python's `ipaddress` module
- Rejects subnets larger than 256 addresses (/24 or smaller)
- Rejects public subnets (only private or loopback allowed)

**Validation order in `main()`:**
1. Port validation first (fail fast on invalid input)
2. Target/subnet authorization (reject unauthorized targets before any success messages)
3. Display authorized configuration summary

**Unit tests (`test_validation.py`):**
- 15 tests covering all validation functions
- Tests for authorized targets (loopback, private); rejected targets (public, link-local)
- Tests for rejected targets (public IPs, invalid addresses)
- Tests for port range validation (valid ranges, invalid formats, out-of-range ports)
- Tests for subnet validation (valid subnets, invalid formats, size limits, public subnets)

## 3. Files changed and their responsibilities

| File | Action | Responsibility |
|------|--------|----------------|
| `netscan_lite.py` | Created | CLI entry point, validation, and authorization logic |
| `tests/__init__.py` | Created | Test package initialization |
| `tests/test_validation.py` | Created | Unit tests for validation and authorization |

No network scanning code was created in this phase. The implementation validates input and prevents unauthorized scanning, but does not perform any network probes.

## 4. How it works — teach-back

### Why a CLI is needed before scanning

Before we can scan networks, we need a way for the user to specify:
- What to scan (target IP or subnet)
- Which ports to check
- How to scan (TCP or UDP)
- Where to save results (JSON or CSV)

The `argparse` module provides a standard way to parse command-line arguments and generate help messages. This makes the tool easy to use and self-documenting.

### Input validation prevents errors and accidents

Without validation, a user could:
- Type an invalid IP address (e.g., "999.999.999.999")
- Specify ports outside the valid range (e.g., port 0 or 70000)
- Request scanning millions of ports at once (e.g., "1-65535")
- Attempt to scan public internet addresses

Validation catches these mistakes early and provides clear error messages before any network activity occurs.

### Target authorization protects against unauthorized scanning

The tool is designed for educational use on authorized lab networks only. Scanning public internet addresses without permission is illegal and unethical.

The `is_authorized_target` function implements an explicit allow policy:
- **Allow:** Loopback (for testing on your own machine)
- **Allow:** Private ranges (for lab networks you control)
- **Reject:** Link-local (169.254.0.0/16) — not in the default authorized scope
- **Reject:** Everything else (public IPs, multicast, reserved ranges)

This check happens **before** any network code would run, ensuring the tool cannot accidentally scan unauthorized targets.

### Port range limits prevent resource exhaustion

A port range like "1-65535" would attempt to scan 65,535 ports. Even with a 1-second timeout, this could take hours and consume significant system resources.

The validation limits ranges to 1000 ports maximum, preventing accidental excessive scans while still allowing useful ranges like "1-100" or "8000-9000".

### Unit tests prove the logic works correctly

The test suite validates that:
- Authorized targets are accepted
- Unauthorized targets are rejected with clear reasons
- Invalid inputs are caught and reported
- Edge cases (empty ranges, out-of-bounds values) are handled

These tests run in milliseconds and don't require network access, proving the validation logic is sound before we add actual network scanning in Phase 2.

## 5. Decisions and rationale

| Decision | Rationale |
|----------|-----------|
| Validate ports before targets | Port validation is simpler and faster; fail fast on malformed input before more complex checks |
| Reject port ranges > 1000 | Prevents accidental resource exhaustion while allowing practical ranges |
| Restrict subnets to ≤256 addresses | /24 or smaller subnets are reasonable for lab use; larger subnets could take too long |
| Use Python's `ipaddress` module | Standard library provides robust IP validation and classification (private, loopback, etc.) |
| Make target/subnet mutually exclusive | Simplifies the CLI; either scan one host or a subnet, not both at once |
| No network probes in Phase 1 | Establishes safety boundaries first; scanning implementation is Phase 2 |
| Validate authorization before printing success messages | Prevents partial success output when validation fails; cleaner error handling |

## 6. Verification and test evidence

### Unit test results

**Command:** `py tests/test_validation.py`

**Output:**
```
...............
----------------------------------------------------------------------
Ran 15 tests in 0.001s

OK
```

All 15 unit tests passed, validating:
- Loopback and private address authorization; link-local rejected
- Public address rejection
- Invalid address format rejection
- Single port and port range validation
- Port range limits (1-65535, max 1000 ports)
- Subnet validation (format, size limits, public subnet rejection)

### CLI help output

**Command:** `py netscan_lite.py --help`

**Result:** Help message displayed correctly with all options, examples, and authorization notice.

### Validation error tests

**Test 1: Public IP rejection**
```
Command: py netscan_lite.py --target 8.8.8.8 --ports 80
Output: Error: Target rejected - Public or unauthorized address
        Only loopback and private IP addresses are authorized.
Exit code: 1
```

**Test 2: Invalid port (port 0)**
```
Command: py netscan_lite.py --target 127.0.0.1 --ports 0
Output: Error: Port must be between 1 and 65535: 0
Exit code: 1
```

**Test 3: Port range too large**
```
Command: py netscan_lite.py --target 127.0.0.1 --ports 1-2000
Output: Error: Port range too large (max 1000 ports): 1-2000
Exit code: 1
```

**Test 4: Subnet too large**
```
Command: py netscan_lite.py --subnet 8.0.0.0/8 --ports 1-100
Output: Error: Subnet too large (max 256 addresses): 8.0.0.0/8
Exit code: 1
```

### Authorized target tests

**Test 5: Loopback target**
```
Command: py netscan_lite.py --target 127.0.0.1 --ports 80
Output: Target authorized: 127.0.0.1 (Loopback address)
        Port range: 80-80 (1 ports)
        Scan mode: tcp
        Timeout: 1.0s

        Phase 1: CLI and validation complete. Scanner implementation will be added in Phase 2.
        No network probes were performed in this phase.
Exit code: 0
```

**Test 6: Private IP target**
```
Command: py netscan_lite.py --target 192.168.1.1 --ports 1-100
Output: Target authorized: 192.168.1.1 (Private IP address)
        Port range: 1-100 (100 ports)
        Scan mode: tcp
        Timeout: 1.0s

        Phase 1: CLI and validation complete. Scanner implementation will be added in Phase 2.
        No network probes were performed in this phase.
Exit code: 0
```

**Test 7: Subnet target**
```
Command: py netscan_lite.py --subnet 192.168.1.0/24 --ports 1-100
Output: Subnet authorized: 192.168.1.0/24
        Port range: 1-100 (100 ports)
        Scan mode: tcp
        Timeout: 1.0s

        Phase 1: CLI and validation complete. Scanner implementation will be added in Phase 2.
        No network probes were performed in this phase.
Exit code: 0
```

**Test 8: Comma-separated ports**
```
Command: py netscan_lite.py --target 127.0.0.1 --ports 22,80,443
Output: Target authorized: 127.0.0.1 (Loopback address)
        Ports to scan: 3 ports
        Scan mode: tcp
        Timeout: 1.0s

        Phase 1: CLI and validation complete. Scanner implementation will be added in Phase 2.
        No network probes were performed in this phase.
Exit code: 0
```

### No network probes performed

As confirmed by the output message in all successful runs: "No network probes were performed in this phase." The implementation validates input and configuration but does not connect to any network targets.

## 7. Setbacks, root causes, and resolutions

### Setback 1: Exception handling for invalid IP addresses

**Issue:** Initial implementation caught `AddressValueError` and `NetmaskValueError` from `ipaddress` module, but Python's `ip_address()` function raises a generic `ValueError` for invalid addresses.

**Root cause:** Incorrect exception type in the `except` clause.

**Resolution:** Changed exception handling to catch `ValueError` instead of specific `ipaddress` exceptions. Also removed unused imports (`AddressValueError`, `NetmaskValueError`).

### Setback 2: Test failure for subnet size validation

**Issue:** Test case `validate_subnet("10.0.0.0/8")` failed because a /8 subnet has 16,777,216 addresses, exceeding the 256-address limit.

**Root cause:** Test used a subnet that was too large for the validation rules.

**Resolution:** Changed test to use a /24 subnet (`10.0.0.0/24`) which has 256 addresses and passes validation.

### Setback 3: Error message ordering

**Issue:** When both target authorization and port validation failed, the error messages appeared in the wrong order (target authorization message before port validation error).

**Root cause:** Validation order in `main()` checked target authorization before port validation.

**Resolution:** Reordered validation to check ports first (simpler, faster validation) before target authorization. This provides cleaner error messages and fails fast on malformed input.

## 8. Safety and limitations

### Safety checks implemented

- **Explicit target allow policy:** Only loopback and private addresses are authorized. Link-local (169.254.0.0/16), multicast, reserved, and all global/public addresses are rejected with a clear error message.
- **Port range limits:** Maximum 1000 ports per scan to prevent resource exhaustion.
- **Subnet size limits:** Maximum 256 addresses per subnet scan.
- **Port bounds:** Ports must be between 1 and 65535.
- **No network probes:** Phase 1 only validates input; no network connections are attempted.

### Limitations

- **No actual scanning:** The tool validates configuration but does not perform any network probes. Scanning implementation is Phase 2.
- **No host discovery:** Subnet scanning is not yet implemented; only subnet validation exists.
- **No UDP scanning:** UDP mode is accepted as an argument but not implemented.
- **No report generation:** JSON and CSV output options are accepted but not implemented.
- **No concurrency:** Single-threaded validation only; concurrent scanning will be added in Phase 2.

### Authorization scope

The current authorization policy allows:
- Loopback (127.0.0.0/8): For testing on the local machine
- Private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16): For lab networks the user controls
- Link-local (169.254.0.0/16): Rejected by default — not in the authorized scope

The policy rejects:
- Public IP addresses (e.g., 8.8.8.8, 1.1.1.1)
- Invalid IP address formats

This matches the user-authorized testing scope from Phase 0.

## 9. Remaining work

**Phase 2:** TCP connect scanner implementation
- Implement bounded-timeout TCP connect checks using `socket`
- Distinguish successful connections from other results
- Map common TCP ports to service-name hints
- Add bounded concurrency after a correct baseline exists

**Phase 3:** Result model, service/banner identification, and reports
- Define a stable result structure
- Implement banner identification with bounded reads
- Write JSON and CSV reports with appropriate fields

**Phase 4:** UDP probing
- Add UDP probes with finite timeouts
- Interpret responses conservatively (silence = ambiguous)

**Phase 5:** Host discovery
- Add subnet parsing and bounded host iteration
- Use platform-aware ping method

**Phase 6:** Integration, test coverage, and measured evaluation
- Integrate all components
- Add regression tests
- Measure scan duration under controlled conditions

**Phase 7:** Course documentation and demonstration
- Write/update README.md
- Explain networking concepts
- Prepare demonstration evidence

**Flask UI:** Mandatory deliverable to be built after core scanning functionality is complete.

## 10. User review and approval

- User approval: **Approved on 2026-10-10.**
- The report and the implementation (`netscan_lite.py`, `tests/`) were reviewed and approved for commit.
- The phase was committed as 12d853f after approval.

## 11. Git workflow and commit evidence

- **Committed as 12d853f.** The following files were staged and committed:
  - `netscan_lite.py`
  - `tests/__init__.py`
  - `tests/test_validation.py`
  - `phase1.md`
  - `DEV.md` (updated phase tracker and development log)
- Commit message: `feat: Phase 1 — CLI, validation, and safe scope`
- No push to GitHub occurred without explicit user authorization.

## 12. Revision notes and viva questions

### Key concepts

- **CLI argument parsing:** Using `argparse` to parse command-line arguments and generate help messages.
- **Input validation:** Checking user input is valid before processing (IP addresses, ports, subnets).
- **Explicit allow policy:** Only accepting specific authorized targets and rejecting everything else by default. Link-local is rejected by default, not automatically allowed, because it is auto-configured and not necessarily under user control.
- **Fail fast:** Validating simple checks first (ports) before complex checks (target authorization) to provide clear error messages.
- **Unit testing:** Testing validation logic independently without network access to prove correctness.
- **Resource limits:** Bounding port ranges and subnet sizes to prevent accidental resource exhaustion.

### Likely viva questions

**Q: Why validate ports before targets?**
A: Port validation is simpler and faster. Checking ports first allows us to fail fast on malformed input before doing more complex IP address validation. This provides cleaner error messages.

**Q: What happens if someone tries to scan a public IP like 8.8.8.8?**
A: The tool rejects it with an error message: "Target rejected - Public or unauthorized address." The authorization check happens before any network code would run, so no probes are sent.

**Q: What happens for link-local addresses like 169.254.x.x?**
A: They are rejected by default with "Link-local address not in authorized scope." Link-local is auto-configured and not necessarily under the user's control, so it is not automatically authorized; any change here must be approved and recorded.

**Q: Why limit port ranges to 1000 ports?**
A: Scanning 65,535 ports (the full range) could take hours and consume significant system resources. A 1000-port limit allows practical scans while preventing accidental excessive scans.

**Q: Does Phase 1 actually scan any networks?**
A: No. Phase 1 only validates input and configuration. It checks that the target is authorized, ports are valid, and the configuration is reasonable. No network probes are performed until Phase 2.

**Q: What changed in Phase 2?**
A: Phase 2 refactored validation/authorization into `netscan/validation.py` so the CLI and Flask app share one source of truth, implemented the TCP connect scanner with distinct open/closed/unknown results, and added the mandatory Flask dashboard with server-side authorization and validation before any probe.

**Q: How do the unit tests prove the tool won't scan unauthorized targets?**
A: The tests verify that `is_authorized_target` returns `False` for public IPs and `True` for authorized targets. Since the CLI exits with an error before any scanning code runs (which doesn't exist yet in Phase 1), we can prove rejected targets cannot trigger network probes.

**Q: What's the difference between `--target` and `--subnet`?**
A: `--target` specifies a single IP address to scan. `--subnet` specifies a network range in CIDR notation (e.g., 192.168.1.0/24). They are mutually exclusive to simplify the CLI.

**Q: Why use Python's `ipaddress` module instead of string parsing?**
A: The `ipaddress` module is part of the standard library and provides robust, well-tested IP address validation and classification (e.g., `is_private`, `is_loopback`). It handles edge cases and IPv6 correctly, which manual string parsing might miss.
