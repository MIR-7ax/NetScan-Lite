# Phase 2 — TCP connect scanner and Flask web dashboard

- Status: COMMITTED
- Started: 2026-10-10
- Completed for review: 2026-10-10
- User approval: Approved on 2026-10-10
- Git commit(s):
    - `1252676` `feat(phase2): TCP connect scanner and Flask dashboard with server-side auth`
    - `1fa22ae` `ui(phase2): improve dashboard layout, results summary, and export placement`

## 1. Goal and agreed scope

**Goal:** Implement TCP connect scanning with bounded timeouts and establish the mandatory Flask web interface.

**Scope agreed with the user for this phase:**
- Implement a bounded-timeout TCP connect check using `socket.connect_ex()`.
- Distinguish a successful connection from other results without overclaiming closed/filtered.
- Map common TCP ports to service-name hints.
- Set up Flask application structure and the initial web interface.
- Provide a dashboard with target input, port configuration, scan mode selection, scan initiation, and results area.
- Connect the Flask backend to the TCP scanning engine.
- Keep the CLI working as well.
- Enforce target authorization and input validation on the server side before initiating probes.
- Add bounded concurrency after a correct baseline exists.

**Out of scope for this phase unless explicitly approved later:**
- UDP probing, host discovery, banner identification, JSON/CSV report files on disk, and course documentation. Those remain in later phases per `DEV.md`.

## 2. Work completed

### 2.1 Validation and authorization consolidated

Created [`netscan/validation.py`](netscan/validation.py) as the canonical place for the target allow policy, port-range parsing, and subnet validation.

- `is_authorized_target(target)` returns `(bool, reason)`.
  - Authorized by default: loopback (`127.0.0.0/8`) and private (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
  - Rejected by default: link-local (`169.254.0.0/16`), multicast, reserved, and all global/public addresses.
- `validate_port_range(port_str)` parses `22` or `1-100` and returns `(start, end)`, or raises `ValueError`.
- `validate_subnet(subnet_str)` validates CIDR with size and authorization limits, or raises `ValueError`.
- `parse_port_spec(ports_str)` expands `22,80-81,443` into a list of ports, bounded by the same 1000-port limit.

`netscan_lite.py` now imports from `netscan.validation` instead of implementing those helpers itself. It also re-exports `is_authorized_target`, `validate_port_range`, and `validate_subnet` so existing consumers and tests continue to import from `netscan_lite`.

### 2.2 TCP connect scanner

Rewrote [`netscan/tcp_scanner.py`](netscan/tcp_scanner.py):

- `scan_port(target, port, timeout)` returns a dict with keys `port`, `state`, `service`, `error`.
  - `state` is one of `open`, `closed`, or `unknown`.
  - `service` is a conventional port hint from `COMMON_PORTS` or `unknown`.
- State mapping:
  - `connect_ex` returns `0` → `open`.
  - `connect_ex` returns `ECONNREFUSED` (10061) → `closed`.
  - `connect_ex` returns `WSAEWOULDBLOCK` (10035) or `WSAETIMEDOUT` (10060) → `unknown` with `error: "timeout"`.
  - Other nonzero `connect_ex` results → `unknown`.
  - `socket.timeout` / `TimeoutError` raised by `connect_ex` → `unknown` with `error: "timeout"`.
  - `socket.gaierror` → `error`.
  - Other `OSError` → `error`.
- `scan_ports(target, ports, timeout, max_workers)` validates authorization first and raises `ValueError` before any socket is created for rejected targets; validates `timeout > 0`; bounds `max_workers` to at most 200; collects results and returns them sorted by port.

### 2.3 Flask web application

Rewrote [`netscan/app.py`](netscan/app.py) and added the dashboard:

- Routes:
  - `GET /` renders [`netscan/templates/dashboard.html`](netscan/templates/dashboard.html).
  - `POST /api/scan` accepts `target`, `ports`, and optional `timeout` as JSON, validates authorization and input server-side, then runs `scan_ports` and returns `target`, `timeout`, `mode`, and `results`.
  - `POST /api/validate` validates target, port spec, and optional subnet without scanning.
- Server-side enforcement:
  - Authorization is checked before any scan.
  - Port spec is parsed and bounded by the 1000-port limit.
  - `timeout` is validated as a positive float before scanning.
  - Unexpected exceptions return a generic `500 Internal server error`, never raw exception text.
- Development server binds to `127.0.0.1:5000` only.

Dashboard UI:
- [`netscan/templates/dashboard.html`](netscan/templates/dashboard.html) renders a target input, ports input, timeout input, Start scan / Validate only / Clear buttons, and a results table with Port, Service, State, and Error columns plus JSON and CSV export buttons.
- [`netscan/static/styles.css`](netscan/static/styles.css) styles the dashboard.
- [`netscan/static/app.js`](netscan/static/app.js) handles live validation on input, scan submission via `fetch`, result rendering, and JSON/CSV export.

### 2.4 Tests added

- [`tests/test_tcp_scanner.py`](tests/test_tcp_scanner.py)
  - `TestConnectErrorClassification`: errno-to-state mapping.
  - `TestIsAuthorizedTarget`: loopback, private, link-local, public, invalid.
  - `TestScanPortLoopback`: live loopback probe for an open listener, a normally closed port, service hints, socket cleanup.
  - `TestScanPortsAuthorization`: rejected targets raise `ValueError` before any socket is created; timeout validation.
  - `TestScanPortsLoopback`: a mixed closed/open loopback scan.
  - `TestScanPortsSorting`: unsorted input yields sorted output.
- [`tests/test_validation_api.py`](tests/test_validation_api.py)
  - `TestDashboard`: `GET /` returns HTML with the scan form and results table; static assets served.
  - `TestValidationAPI`: validate endpoint behavior for authorized/rejected targets, port specs, subnets.
  - `TestScanAPI`: scan endpoint rejects missing fields, rejected targets with 403, invalid ports and timeouts with 400, and returns the expected result shape on success.

### 2.5 CLI preserved

`netscan_lite.py` continues to work as the CLI entry point, including `--help`, rejection of out-of-scope targets, and the new TCP probe path for authorized loopback targets.

## 3. Files changed and their responsibilities

| File | Action | Responsibility |
|------|--------|----------------|
| `netscan/validation.py` | Created | Canonical validation/authorization shared by CLI and Flask |
| `netscan/tcp_scanner.py` | Rewritten | TCP connect scanner with open/closed/unknown states and bounded concurrency |
| `netscan/app.py` | Rewritten | Flask app, dashboard route, scan/validate API, server-side checks |
| `netscan/__init__.py` | Existing | Package marker |
| `netscan/templates/dashboard.html` | Created | Dashboard HTML |
| `netscan/static/styles.css` | Created | Dashboard CSS |
| `netscan/static/app.js` | Created | Dashboard JavaScript |
| `netscan_lite.py` | Rewritten | CLI entry point, re-exports validation helpers, performs TCP scan on authorized targets |
| `tests/test_tcp_scanner.py` | Created | Scanner tests |
| `tests/test_validation_api.py` | Created | Flask route tests |
| `DEV.md` | Edited | Updated architecture diagram, file layout, phase tracker, development log |
| `phase1.md` | Edited | Updated status to committed, corrected link-local wording, added Phase 2 notes |

Preserved (not reset, discarded, or overwritten):
- `tests/test_validation.py` and its imports still pass because `netscan_lite` re-exports the validation helpers.
- `.gitignore`, `README.md`, `PHASE0.md`, `phase0.md`, `phase1.md` (except the intentional documentation updates above), and `.freebuff/` remain as they were. The working tree already contained an untracked `netscan/` package; I rebuilt it in place rather than deleting unrelated work.

## 4. How it works — teach-back

### 4.1 TCP connect scan

`socket.connect_ex((target, port))` asks the OS to complete the TCP three-way handshake. The OS does the SYN/SYN-ACK/ACK exchange; the application only sees the outcome.

- Return `0` means the OS established the connection, which is evidence the remote endpoint accepted it at that moment.
- Return `ECONNREFUSED` means the remote host actively refused the connection, which is the strongest evidence we have that the port is not accepting connections.
- Return `WSAEWOULDBLOCK` or `WSAETIMEDOUT` means the probe did not complete in time; on this platform these map to the same underlying timeout condition. We report `unknown` rather than asserting `filtered` because a timeout alone cannot reliably separate a filtered port from a closed one that has not yet replied.

That distinction matters: the old code reported timeouts as `closed`, which overclaims. The new code reports timeouts as `unknown`, which is honest.

### 4.2 Concurrency

`scan_ports` submits one `scan_port` call per port to a `ThreadPoolExecutor` with a bounded worker count. Network I/O is the bottleneck, so waiting on many sockets concurrently is a reasonable use of threads. The default `max_workers` is 50, capped at 200 to prevent runaway resource use.

### 4.3 Server-side authorization

The same `is_authorized_target` function is used by the CLI and the Flask app, and `scan_ports` itself refuses unauthorized targets before creating sockets. The Flask app also validates ports and timeout before calling the scanner. That means a rejected target cannot reach the scanner, and the scanner refuses even if it were called directly.

### 4.4 Dashboard flow

1. User types a target and port spec. The browser validates live against `/api/validate` and enables the Start scan button only when both are authorized/valid.
2. On submit, the browser sends a `POST` to `/api/scan` with JSON.
3. The server revalidates, including authorization, ports, and timeout.
4. If authorized and valid, the server runs the scan and returns the result JSON.
5. The browser renders the results table and exposes JSON/CSV export.

## 5. Decisions and rationale

- **Consolidate validation into `netscan/validation.py`.** The pre-existing code had the same authorization logic copy-pasted into `netscan_lite.py`, `netscan/tcp_scanner.py`, and a broken import from a nonexistent `netscan.validation`. A single module prevents drift between the CLI and the app.
- **Re-export from `netscan_lite`.** The Phase 1 tests imported `validate_port_range`, `validate_subnet`, and `is_authorized_target` from `netscan_lite`. Re-exporting keeps those tests green without rewriting them and keeps the CLI import surface unchanged.
- **Keep link-local rejected by default.** DEV.md §4 and §13 warn that link-local is not automatically under user control. The Phase 1 tests and the Flask policy agree with the code: link-local is rejected. `phase1.md` was wrong to say it was accepted; I corrected it.
- **Report timeouts as `unknown`, not `closed`.** DEV.md §13 explicitly warns against reducing all nonzero `connect_ex` results to `closed`. The new state mapping is consistent with that guidance.
- **Keep `max_workers` modest and bounded.** Bounded concurrency is in scope, but unbounded concurrency is not. Default 50, hard cap 200, is conservative for a learning tool.
- **Validate timeout in both the scanner and the app.** The old app accepted an unvalidated `timeout` from the request. The new app and scanner both reject non-positive or non-numeric timeout values before scanning.
- **Return a generic error from unexpected Flask exceptions.** Do not leak internal exception text to the browser; log it server-side instead.

## 6. Verification and test evidence

### 6.1 Full test suite

Command: `py -m unittest discover -s tests -v`

Summary line: `Ran 64 tests in 1.345s ... OK`

That includes:
- 15 Phase 1 validation tests in `tests.test_validation` (still import from `netscan_lite`).
- 24 TCP scanner tests in `tests.test_tcp_scanner`.
- 25 Flask/route tests in `tests.test_validation_api`.

No Phase 1 tests were modified; they still pass. The new tests add coverage for the scanner states, authorization-before-socket behavior, sorting, and the Flask endpoints.

### 6.2 Scanner state tested on loopback

- Open listener on loopback → `state: open`.
- Normally closed loopback port → `state: unknown`, `error: "timeout"`.
- Service hints: port 22 → `ssh`, 80 → `http`, 8080 → `http-proxy`, unknown port → `unknown`.
- Rejected targets raise `ValueError` before any socket is created, verified with `mock.patch("netscan.tcp_scanner.socket")` plus `assert_not_called()`.

### 6.3 Flask app tested with the test client

- `GET /` → 200, `text/html`, contains `scan-form` and `results-table`.
- `/static/styles.css` and `/static/app.js` → 200.
- `POST /api/validate` with `target: 8.8.8.8` → `authorized: false`, `reason` mentions “unauthorized”.
- `POST /api/validate` with `target: 169.254.1.1` → `authorized: false`, `reason` mentions “authorized”.
- `POST /api/validate` with `ports: "22,80-81,443"` → `valid: true`, `count: 4`.
- `POST /api/validate` with `ports: "abc"` → `valid: false`, error mentions “Port must be”.
- `POST /api/validate` with `subnet: "192.168.0.0/16"` → `valid: false`, error mentions “too large”.
- `POST /api/scan` with `target: 8.8.8.8` → 403, error mentions “Public or unauthorized address”.
- `POST /api/scan` with `target: 169.254.1.1` → 403, error mentions “Link-local”.
- `POST /api/scan` with missing target or ports → 400.
- `POST /api/scan` with invalid/zero/negative timeout → 400.
- `POST /api/scan` with `target: 127.0.0.1, ports: "22", timeout: 0.2` → 200, correct result shape.

### 6.4 Live dev server smoke tested with curl

Started the app with `app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)` and hit it with curl:

- `GET /` returned the dashboard HTML.
- `POST /api/validate` with `{"target":"127.0.0.1","ports":"22,80"}` returned `authorized: true`.
- `POST /api/validate` with `{"target":"8.8.8.8","ports":"80"}` returned `authorized: false`.
- `POST /api/scan` with `{"target":"8.8.8.8","ports":"80"}` returned 403.
- `POST /api/scan` with `{"target":"127.0.0.1","ports":"22","timeout":0.2}` returned 200 with a result record for port 22.

### 6.5 CLI smoke tested

- `py netscan_lite.py --target 8.8.8.8 --ports 22` → exit 1, “Target rejected - Public or unauthorized address”.
- `py netscan_lite.py --target 169.254.1.1 --ports 22` → exit 1, “Link-local address not in authorized scope”.
- `py netscan_lite.py --target 127.0.0.1 --ports 22,80 --timeout 0.15` → authorized, performs a TCP scan, reports no open ports.
- `py netscan_lite.py --target 127.0.0.1 --ports 22,80 --output csv --timeout 0.15` → prints CSV to stdout with the expected columns.

### 6.6 Fail-fast ordering preserved

- Invalid port spec fails before target authorization.
- Out-of-scope target fails before any scan.
Both are the same ordering as the original CLI.

### 6.7 Browser check

I did not open the dashboard in a browser. The Flask test client proves the template, static assets, and API behave as intended, but I did not run a headless browser or the live app through the visual browser on this machine. A visual/manual browser check is still recommended before committing.

## 7. Setbacks, root causes, and resolutions

### 7.1 Broken import in the pre-existing code

The untracked `netscan/app.py` imported from `netscan.validation`, which did not exist. Result: `import netscan.app` failed with `ModuleNotFoundError: No module named 'netscan.validation'`.

Resolution: create `netscan/validation.py` and re-export the needed helpers from it, then update `netscan/app.py` and `netscan_lite.py` to import from the canonical module.

### 7.2 Missing dashboard

The app called `render_template("dashboard.html")` but there was no `templates/` directory. The mandatory UI was non-functional.

Resolution: created `netscan/templates/dashboard.html`, `netscan/static/styles.css`, and `netscan/static/app.js`, and verified the dashboard renders through the Flask test client.

### 7.3 JavaScript syntax error in static asset

An earlier draft of `netscan/static/app.js` opened a listener block before the handler function was defined, producing invalid JavaScript.

Resolution: rewrote the file cleanly so the export handlers are properly nested and the module runs without syntax errors.

### 7.4 TCP state mapping was wrong

The original `scan_port` treated every nonzero `connect_ex` result as `closed`, and timeouts as `closed` too. That is the exact overclaim DEV.md §13 prohibits.

Resolution: distinguish `ECONNREFUSED` as `closed`, `WSAEWOULDBLOCK`/`WSAETIMEDOUT` as `unknown` with `error: "timeout"`, and other nonzero results as `unknown`. The distinction was verified with a live loopback listener and with a normally closed loopback port.

### 7.5 Tests broke after the refactor

After moving validation into `netscan/validation.py`, `tests/test_validation.py` could no longer import `validate_port_range` from `netscan_lite`.

Resolution: make `netscan_lite.py` import and re-export the validation helpers. All 15 original Phase 1 tests pass again.

### 7.6 Port-range summary formatting

The rewritten CLI prints a slightly different port summary for single-port and single-port-with-comma inputs.

Resolution: the summary now reflects the actual port list, and the ordering remains fail-fast (ports before target). Behavior is consistent with the Phase 1 intent; the exact wording changed as a side effect of consolidating parsing into `parse_port_spec`.

## 8. Safety and limitations

### 8.1 Safety

- The app binds to `127.0.0.1:5000` only.
- Authorization is enforced in the CLI, the scanner, and the Flask app.
- Rejected targets raise `ValueError` before any socket is created, and the tests assert `socket` was not called.
- Port spec and timeout are validated server-side before any scan.
- The dashboard does not store data.
- `.env` and similar secrets remain gitignored; nothing new was added that would commit secrets.

### 8.2 Limitations

- This is TCP connect scanning only. UDP, host discovery, banner grabbing, and report-file output are out of scope for this phase.
- UDP is represented in the CLI help as a future mode; `--mode udp` prints a message that probing for that mode is not yet implemented.
- The state model is conservative: `unknown` for timeouts and other inconclusive results rather than asserting `filtered`. That is intentional and is a limitation of a connect-based scanner, not a bug.
- The dashboard has not been manually verified in a graphical browser; only the test client and curl were used.
- There is no persistence, authentication, or production deployment story; the app is for local learning use.
- The port/service mapping is a hint, not proof of the service actually running.

## 9. Remaining work

- Final user review and approval of this phase.
- After approval: stage the changed files, review the staged diff, commit, and record the commit hash in `DEV.md` and this report.
- Later phases: UDP probing, result model/banner identification, JSON/CSV report output to disk, host discovery, integration/measured evaluation, and course documentation, per `DEV.md`.

## 10. User review and approval

- User approval: **Approved on 2026-10-10.**
- Phase 2 implementation committed as `1252676` on 2026-10-10.
- Phase 2 UI improvements committed as `1fa22ae` on 2026-10-10.

## 11. Git workflow and commit evidence

### Commit 1

- **Hash:** `1252676`
- **Message:** `feat(phase2): TCP connect scanner and Flask dashboard with server-side auth`
- **Files:** 11 files changed (1289 insertions, 205 deletions)
  - `netscan/__init__.py` (new)
  - `netscan/app.py` (new)
  - `netscan/tcp_scanner.py` (new)
  - `netscan/validation.py` (new)
  - `phase2.md` (new)
  - `tests/test_tcp_scanner.py` (new)
  - `tests/test_validation_api.py` (new)
  - `.gitignore` (modified)
  - `DEV.md` (modified)
  - `netscan_lite.py` (modified)
  - `phase1.md` (modified)

### Commit 2

- **Hash:** `1fa22ae`
- **Message:** `ui(phase2): improve dashboard layout, results summary, and export placement`
- **Files:** 3 files changed (381 insertions)
  - `netscan/templates/dashboard.html` (new)
  - `netscan/static/styles.css` (new)
  - `netscan/static/app.js` (new)

### Verification

- `git status --short --branch`: `## main...origin/main [ahead 6]`
- `git diff --check`: No issues (only CRLF warnings)
- `py -m unittest discover -s tests`: Ran 64 tests, OK
- CLI smoke tests: help, console, JSON, CSV, rejected target all working
- Awaiting explicit user approval before staging.
- After approval, the likely files to stage are:
  - `netscan/validation.py`
  - `netscan/tcp_scanner.py`
  - `netscan/app.py`
  - `netscan/__init__.py`
  - `netscan/templates/dashboard.html`
  - `netscan/static/styles.css`
  - `netscan/static/app.js`
  - `netscan_lite.py`
  - `tests/test_tcp_scanner.py`
  - `tests/test_validation_api.py`
  - `DEV.md`
  - `phase2.md`
  - `phase1.md`

A final documentation-only commit may follow if `DEV.md`/`phase1.md`/`phase2.md` need to be updated after the code commit. No push to GitHub will occur without explicit authorization.

## 12. Revision notes and viva questions

### Key concepts

- **TCP connect scan vs. stealth SYN scan:** `connect_ex` asks the OS to complete the handshake; it is not a raw-packet half-open scan. Do not claim it is SYN scanning.
- **Why timeouts are `unknown`:** timeouts are inconclusive; a connect timeout does not reliably distinguish filtered from closed. Reporting `unknown` is conservative and honest.
- **Why link-local is rejected:** it is auto-configured and not necessarily under the user’s control, so the default allow list excludes it. Any change to that policy must be approved and recorded.
- **Why validation is shared:** one source of truth prevents the CLI and the app from drifting, and prevents the broken “import from a module that does not exist” situation seen in the pre-existing code.
- **Why the scanner refuses unauthorized targets:** defense in depth. Even if the app layer is bypassed, the scanner itself raises before probing.

### Likely viva questions

**Q: How does the scanner decide the port state?**
A: `connect_ex()` returns `0` for open; `ECONNREFUSED` for closed; `WSAEWOULDBLOCK`/`WSAETIMEDOUT` for timeout → unknown; other nonzero results are unknown; exceptions are mapped to error.

**Q: Why not just call everything “closed” on a nonzero result?**
A: Because that overclaims. A timeout is not proof of closed, and DEV.md explicitly warns against that simplification.

**Q: Can someone bypass the safety checks by calling the API directly?**
A: The Flask app revalidates authorization, ports, and timeout. The scanner also enforces authorization and timeout before probing, so a rejected target cannot cause a scan even if it reached the scanner.

**Q: What is the difference between `/api/validate` and `/api/scan`?**
A: `/api/validate` only validates input and authorization without scanning. `/api/scan` validates and then runs the scan.

**Q: Does the dashboard persist results or user data?**
A: No. It is a stateless local learning app; results are rendered in the browser and can be exported as JSON or CSV, but nothing is stored on the server.

**Q: Why is UDP not implemented yet?**
A: UDP is out of scope for Phase 2. It remains for a later phase, with the documented limitation that silence is ambiguous and must be reported as `open|filtered`, not definitely open.

**Q: What is still unverified?**
A: A manual/visual browser check of the dashboard, and any committed artifact. The automated tests pass, and the live server was smoke-tested with curl, but the app has not been visually reviewed in a browser before approval.
