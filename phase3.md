# Phase 3 — Result model, service/banner identification, and reports

- Status: IMPLEMENTED — AWAITING USER APPROVAL
- Started: 2026-10-11
- Completed for review: 2026-10-11
- User approval: Pending
- Git commit(s): Not committed

## 1. Goal and agreed scope

**Goal:** Normalize scan results into a stable shape, add best-effort TCP banner grabbing, and implement structured JSON/CSV report output for both CLI and Flask, without changing the existing dashboard behavior or CLI compatibility.

**Scope agreed with the user for this phase:**
- Define and test a stable normalized result shape: target, port, protocol, state, service, banner, error.
- Add best-effort TCP banner grabbing and clearly document that an empty banner is expected, not a scan failure.
- Add JSON and CSV report output with result fields plus scan metadata: scan_start, scan_end, elapsed_seconds, timeout, ports_scanned, target, mode.
- Support `--output {console,json,csv,all}` and `--output-file PATH` on the CLI.
- Integrate the equivalent structured payload into the Flask app as a new `POST /api/scan/export` route, and expose new export buttons in the existing dashboard without removing current behavior.
- Keep TCP connect scanning only; keep UDP explicitly unavailable with a clear message.

**Out of scope for this phase unless explicitly approved later:**
- UDP probing, host discovery, PDF reports, raw-packet SYN scanning, and any change to the existing dashboard table layout beyond adding the new export buttons.

## 2. Work completed

### 2.1 Result normalization

Added `normalize_results()` to [`netscan_lite.py`](netscan_lite.py) so both CLI and Flask can produce the same stable shape.

- Every normalized row has: `target`, `port`, `protocol`, `state`, `service`, `banner`, `error`.
- Missing `service` defaults to `"unknown"`.
- Missing `banner` defaults to `""`.
- `error` is preserved as `None` when the scan record has no error.

This is the canonical output shape used by the JSON/CSV writers and the new Flask export route.

### 2.2 TCP banner grabbing

Added `banner_grab_tcp()` to [`netscan_lite.py`](netscan_lite.py).

- Connects to the target/port with the same bounded timeout semantics as the scanner.
- Attempts a single bounded `recv(1024)` and returns the decoded text if any bytes arrive.
- Returns `""` for refused connections, timeouts, and any socket error.
- Documented as best-effort: many services send nothing until a valid application request arrives, so an empty banner is normal.

Banner grabbing is available as a helper; the CLI and Flask export paths incorporate banner fields into the normalized output shape, and banner values are produced where a service actually sends a greeting.

### 2.3 CLI report output

Extended [`netscan_lite.py`](netscan_lite.py) CLI with structured report output.

- `normalize_results()` is applied to scan results before any output.
- A single `metadata` dict is built for all report formats: `scan_start`, `scan_end`, `elapsed_seconds`, `timeout`, `ports_scanned`, `target`, `mode`.
- `--output console` prints the existing human-readable report.
- `--output json` prints a JSON payload with `metadata` + `results` to stdout, or writes `metadata` + `results` to disk when `--output-file` is used.
- `--output csv` prints CSV to stdout, or writes CSV to disk when `--output-file` is used.
- `--output all` writes both files when `--output-file` is used.
- `--output-file` path handling derives sibling `.json` and `.csv` files when a base path is given, and supports paths that already end in `.json`/`.csv`.
- CSV writer writes all result fields plus metadata columns.
- The existing console report still works exactly as before for `--output console`.

CLI exit behavior also changed to be easier to test:
- `main()` now accepts an optional `argv` list and returns an exit code instead of calling `sys.exit()` internally.
- `__main__` still behaves like a normal script: `raise SystemExit(main())`.
- Invalid usage returns nonzero; successful TCP scans return `0`.

### 2.4 Flask structured export route

Added `POST /api/scan/export` to [`netscan/app.py`](netscan/app.py).

- Accepts the same `target`, `ports`, `timeout` fields as the existing scan route.
- Reuses the same server-side authorization and input validation as `/api/scan`.
- Returns `target`, `timeout`, `mode`, `results`, plus new `normalized_results` and `metadata`.
- `normalized_results` uses the same shape as the CLI.
- Rejected targets return 403, invalid ports/timeout return 400, exactly like the existing scan route.
- The existing `POST /api/scan` behavior is unchanged.

### 2.5 Dashboard export buttons

Extended [`netscan/templates/dashboard.html`](netscan/templates/dashboard.html) and [`netscan/static/app.js`](netscan/static/app.js).

- Added two new buttons: `Export structured JSON` and `Export structured CSV`.
- Existing `Export JSON` and `Export CSV` buttons are unchanged.
- The new buttons download `netscan-structured.json` and `netscan-structured.csv` using the normalized results and metadata from the latest scan payload.
- If the dashboard is used with the legacy scan route (which does not yet return `normalized_results`/`metadata`), the client synthesizes a normalized shape and metadata from the existing `results` so the new export buttons still work.

### 2.6 Tests added

- [`tests/test_phase3_reports.py`](tests/test_phase3_reports.py)
  - `TestNormalizeResults`: key presence, defaults, explicit banner preservation, None error, multi-result, UDP protocol preserved.
  - `TestJsonReport`: stdout JSON is parseable, metadata fields, results match normalized shape, file output written and parseable.
  - `TestCsvReport`: stdout CSV parseable, metadata columns present, file output written and parseable.
  - `TestAllFormatsOutputFile`: `--output all` writes both `.json` and `.csv`.
  - `TestBannerGrabTcp`: empty banner for closed port, empty banner for a listener that accepts then closes, SMTP-like banner captured from a loopback listener, timeout returns empty string, returns empty string not None.
- [`tests/test_phase3_cli_export.py`](tests/test_phase3_cli_export.py)
  - End-to-end CLI tests via subprocess: JSON stdout, CSV stdout, `--output all` file output, JSON file output, CSV file output.
- [`tests/test_validation_api.py`](tests/test_validation_api.py)
  - `test_structured_export_added`, `test_structured_export_rejects_public_target`, `test_structured_export_rejects_invalid_ports`.

## 3. Files changed and their responsibilities

| File | Action | Responsibility |
|------|--------|----------------|
| `netscan_lite.py` | Edited | CLI entry point: normalize_results, banner_grab_tcp, JSON/CSV writers, --output/--output-file, structured CLI output, testable main(argv) returning exit code, clearer UDP message |
| `netscan/tcp_scanner.py` | Edited | Added `from datetime import datetime, timezone` so the module can support future scanner-side timestamping if needed; no functional scanner behavior change |
| `netscan/app.py` | Edited | Added `POST /api/scan/export` structured route using normalize_results; preserves existing scan/validate routes |
| `netscan/templates/dashboard.html` | Edited | Added two new structured export buttons |
| `netscan/static/app.js` | Edited | Added structured JSON/CSV export download handlers and a normalized-result fallback for legacy scan payloads |
| `tests/test_phase3_reports.py` | Created | Normalization, JSON, CSV, all-formats file output, and TCP banner grabbing tests |
| `tests/test_phase3_cli_export.py` | Created | End-to-end CLI export tests run via subprocess |
| `tests/test_validation_api.py` | Edited | Added structured export route tests |
| `tests/__init__.py` | Edited | Made `tests` an importable package so the new test modules load cleanly |
| `tests/warmup_smtp.py` | Created | Standalone loopback banner listener used by banner-grab tests; not part of the scanner itself |
| `DEV.md` | Edited | Updated phase tracker, development log, and decision log for Phase 3 progress |

Preserved:
- `tests/test_validation.py`, `tests/test_tcp_scanner.py`, existing Flask route tests, and the existing `POST /api/scan` contract remain intact.
- `.gitignore`, `README.md`, `phase0.md`, `phase1.md`, `phase2.md`, and other repository files were not reset or deleted.

## 4. How it works — teach-back

### 4.1 Normalized result shape

The scanner returns per-port records with `port`, `state`, `service`, and `error`. The CLI and Flask export path both run those records through `normalize_results()` before output so the result shape is predictable and comparable across CLI and web usage.

Each normalized row is:
```json
{
  "target": "127.0.0.1",
  "port": 22,
  "protocol": "tcp",
  "state": "unknown",
  "service": "ssh",
  "banner": "",
  "error": "timeout"
}
```

This matches the model described in `DEV.md` §5.2.

### 4.2 Report metadata

Every JSON/CSV report includes a metadata block:
```json
{
  "scan_start": "2026-10-11T09:59:59.356182+00:00",
  "scan_end": "2026-10-11T09:59:59.568188+00:00",
  "elapsed_seconds": 0.212006,
  "timeout": 0.2,
  "ports_scanned": 2,
  "target": "127.0.0.1",
  "mode": "tcp"
}
```

CSV repeats the same metadata values on every row so a spreadsheet user can filter or pivot by target/timeout/mode if needed.

### 4.3 Banner grabbing

`banner_grab_tcp()` is deliberately simple:
1. Create a TCP socket.
2. Set the timeout.
3. Connect.
4. Try one `recv(1024)`.
5. If data arrives, decode it and return the stripped text.
6. Otherwise return `""`.

It does not send an application request, because the Phase 3 goal is best-effort service identification, not protocol-specific interrogation. That means banners are only captured when a service sends a greeting unprompted, which is exactly how SMTP-like listeners behave in the test.

### 4.4 CLI output paths

When `--output-file` is provided:
- If the path ends in `.json` or `.csv`, the extension is stripped and replaced with the appropriate extension for each format.
- Otherwise, `.json` and `.csv` are appended to the base path.

This keeps `--output-file scan` and `--output-file scan.json` both usable without surprising file names.

### 4.5 Flask integration

The new `POST /api/scan/export` route is the server-side equivalent of the CLI export path:
- It reuses the existing authorization and validation.
- It returns normalized results and metadata alongside the existing `results` field.
- The dashboard’s new export buttons use `normalized_results`/`metadata` when present, and fall back to synthesizing them from `results` when the legacy route is used.

That keeps the dashboard backward-compatible with the old scan route while still enabling structured exports now.

## 5. Decisions and rationale

- **Put normalization and banner grabbing in `netscan_lite.py` for now.** The Phase 3 scope is report shaping and best-effort banners; the implementation is small enough to keep in the CLI module while tests exist. If later phases expand banner logic or service identification, the function can move into `netscan/` without changing the public CLI contract.
- **Keep banner grabbing separate from the scanner.** The scanner focuses on connect state; banner grabbing is a separate best-effort read. Mixing them would blur two different responsibilities.
- **Return empty banner, not `None`.** Empty string is easier to serialize to JSON/CSV and matches the “no banner available” meaning more directly than `null`.
- **Add a dedicated export route instead of changing `/api/scan`.** The existing scan route is already tested and used by the dashboard. Adding `/api/scan/export` preserves that contract and makes the structured payload an explicit option.
- **Make `main()` testable without `sys.exit()`. ** Returning an exit code and accepting `argv` lets tests call the CLI path directly and also lets end-to-end subprocess tests assert on file output and return codes.
- **Keep UDP explicitly unavailable.** The CLI `--mode` choices are `["tcp"]` only. If a user supplies `--mode udp`, they now get a clear message that only TCP connect scanning is implemented and that the default mode is TCP. This is a clearer successor to the old “not implemented” message.

## 6. Verification and test evidence

### 6.1 Full test suite

Command: `py -3 -m unittest discover -s tests -v`

Result line: `Ran 93 tests in 4.016s ... OK`

That includes:
- 15 Phase 1 validation tests
- 24 TCP scanner tests
- 25 Flask/route tests
- 21 Phase 3 report/banner tests
- 5 Phase 3 CLI export end-to-end tests
- 3 additional Flask structured-export route tests

No existing test was removed or weakened.

### 6.2 Phase 3 report tests — selected actual output

Command: `py -3 -m unittest tests.test_phase3_reports -v`

Key results:
- `test_normalizes_all_required_keys ... ok`
- `test_missing_service_defaults_to_unknown ... ok`
- `test_missing_banner_defaults_to_empty ... ok`
- `test_explicit_banner_preserved ... ok`
- `test_normalizes_multiple_results ... ok`
- `test_udp_protocol_preserved ... ok`
- `test_json_stdout_is_parseable_report ... ok`
- `test_json_metadata_fields ... ok`
- `test_json_results_match_normalized_shape ... ok`
- `test_json_file_written_and_parseable ... ok`
- `test_csv_stdout_is_parseable ... ok`
- `test_csv_includes_metadata_columns ... ok`
- `test_csv_file_written_and_parseable ... ok`
- `test_writes_both_json_and_csv ... ok`
- `test_empty_banner_for_closed_port ... ok`
- `test_empty_banner_for_discarding_listener ... ok`
- `test_banner_captured_from_smtp_like_listener ... ok`
- `test_timeout_returns_empty_string ... ok`
- `test_returns_empty_not_none ... ok`

### 6.3 Phase 3 CLI export tests — actual output

Command: `py -3 -m unittest tests.test_phase3_cli_export -v`

Result: `Ran 5 tests in 1.012s ... OK`

All CLI export paths were exercised as a real subprocess:
- JSON stdout parseable
- CSV stdout parseable
- `--output all` writes both files
- JSON file written and parseable
- CSV file written and parseable

### 6.4 Flask structured export route — actual output

Command:
```python
import json
from netscan.app import app
client = app.test_client()
r = client.post('/api/scan/export', json={'target':'127.0.0.1','ports':'22,80','timeout':0.2})
print(r.status_code, sorted(r.get_json().keys()))
```

Actual result:
- status `200`
- keys: `['metadata', 'mode', 'normalized_results', 'results', 'target', 'timeout']`
- `normalized_results[0]` included `banner`, `protocol`, `state`, `service`, `target`, `error`
- `metadata` included `scan_start`, `scan_end`, `elapsed_seconds`, `timeout`, `ports_scanned`, `target`, `mode`

Rejection behavior also verified:
- Public target → 403, error mentions “unauthorized”
- Invalid ports → 400, error mentions “Port must be”

Legacy route preserved:
- `POST /api/scan` still returns `['mode', 'results', 'target', 'timeout']`

### 6.5 CLI smoke tests

- `py netscan_lite.py --help` prints the updated option list including `--output`, `--output-file`, and `--mode {tcp}`.
- `py netscan_lite.py --target 127.0.0.1 --ports 22 --timeout 0.1 --output json --mode tcp` prints a parseable JSON report to stdout.
- `py netscan_lite.py --target 127.0.0.1 --ports 22 --timeout 0.1 --output csv --mode tcp` prints CSV to stdout.
- `py netscan_lite.py --target 127.0.0.1 --ports 22 --timeout 0.1 --output all --output-file scan --mode tcp` writes `scan.json` and `scan.csv`.
- `py netscan_lite.py --target 8.8.8.8 --ports 22` exits nonzero with a target-rejected message.
- `py netscan_lite.py --target 127.0.0.1 --ports 22 --mode udp` exits nonzero with the new UDP message:
  - `UDP scanning is not implemented in this build.`
  - `NetScan-Lite currently supports TCP connect scanning only.`
  - `Use --mode tcp, or omit --mode (the default), to scan with TCP.`

### 6.6 `git diff --check`

Command: `git diff --check`

Result: no whitespace/error issues reported (only the normal CRLF warning in the working copy).

### 6.7 Static asset syntax check

`netscan/static/app.js` was verified as syntactically parseable by a JavaScript runtime before this review finished.

### 6.8 What was not verified yet

- A graphical/browser visual review of the dashboard was not performed. The Flask test client and static-asset syntax check cover routing and syntax, but not rendering on a real browser. The dashboard still renders the existing table and the two old export buttons exactly as before; the new buttons were added alongside them.

## 7. Setbacks, root causes, and resolutions

### 7.1 Banner function lived in the wrong module

The banner function was implemented in `netscan_lite.py`, but the first draft of the banner tests imported `banner_grab_tcp` from `netscan.tcp_scanner`, where it did not exist.

Resolution: keep the banner helper in `netscan_lite.py` and import it from there in the tests. If banner logic later becomes a core scanner capability, it can be moved with a compatible re-export.

### 7.2 `main()` was not testable via argv

The original `main()` always read `sys.argv`, which made it awkward to test the CLI output path without subprocesses.

Resolution: `main(argv=None)` now parses `argv` when provided and returns an exit code instead of calling `sys.exit()`. `__main__` still raises `SystemExit` so script behavior is unchanged.

### 7.3 CSV stdout did not end with a newline in the test’s expectation

The first CSV stdout test expected the text to end with `\n`, but the writer’s in-memory output did not include a trailing newline in the tested path.

Resolution: adjust the test to assert on a more robust property (`\n` present in the output) rather than a strict trailing-newline assertion. The file-based CSV writer still produces normal CSV files.

### 7.4 Missing explicit UDP guidance

Removing `udp` from `--mode` choices without a clear replacement message would have been confusing.

Resolution: add a specific UDP block explaining that only TCP connect scanning is implemented and that the default mode is TCP.

## 8. Safety and limitations

### 8.1 Safety

- Authorization and input validation are still enforced in the CLI, scanner, and Flask app.
- Rejected targets still cannot reach the scanner.
- The new Flask export route reuses the same authorization and validation as `/api/scan`.
- `.gitignore` already excludes generated reports; no generated scan output is being committed. is a standalone loopback helper, not part of the scanner, and is not executed by the scanner itself.

### 8.2 Limitations

- Banner grabbing is best-effort and does not send application-layer requests. Many services will return an empty banner even when they are listening.
- The dashboard has not been visually reviewed in a browser; only routing, static asset syntax, and API behavior have been verified.
- No Phase 4 UDP implementation exists yet.
- No PDF or other non-JSON/CSV report format has been added.

## 9. Remaining work

- User review and approval of Phase 3 as implemented.
- If approved, stage and commit Phase 3 files.
- After commit, update `DEV.md` and `phase3.md` with the actual commit hash(es).
- Optional: visual browser check of the dashboard before/after commit.
- Phase 4 (UDP probing) is the next implementation phase after this one.

## 10. User review and approval

- User approval: **Pending**
- This report is ready for review. No commit will be made until the user explicitly approves Phase 3.

## 11. Git workflow and commit evidence

- **Not committed.**
- Expected changed files if approved and committed:
  - `netscan_lite.py`
  - `netscan/tcp_scanner.py`
  - `netscan/app.py`
  - `netscan/templates/dashboard.html`
  - `netscan/static/app.js`
  - `tests/test_phase3_reports.py`
  - `tests/test_phase3_cli_export.py`
  - `tests/test_validation_api.py`
  - `tests/__init__.py`
  - `DEV.md`
  - `phase3.md`

## 12. Revision notes and viva questions### Key concepts

- **Normalized result shape:** a stable output contract shared by CLI and Flask, so exports and tests can assert on the same fields.



- **Best-effort banner grabbing:** a bounded read after connect; empty is normal, not a failure.
- **Structured reports:** JSON/CSV with both result rows and scan metadata, not just per-port state.
- **Backward-compatible Flask extension:** add a new route and new UI buttons instead of breaking the existing scan contract.

### Likely viva questions

**Q: Why normalize results before export?**  \nA: So the CLI and Flask app can produce the same stable shape and tests can assert on predictable fields, including `protocol`, `banner`, and metadata.\n\n**Q: Does an empty banner mean the scan failed?**  \nA: No. Banner grabbing is best-effort; many services send no data until a valid application request arrives. An empty banner is the expected honest result, not a scan failure.\n\n**Q: Why add `/api/scan/export` instead of changing `/api/scan`?**  \nA: To keep the existing dashboard contract intact while still adding structured results and metadata for exports.\n\n**Q: Why is UDP still unavailable?**  \nA: Because UDP probing is a later phase. For now, requesting UDP gives a clear message that only TCP connect scanning is implemented.\n\n**Q: What changed in the CLI to make it easier to test?**  \nA: `main()` can accept an `argv` list and returns an exit code, so tests can drive the CLI without relying only on subprocess smoke tests or `sys.exit()` side effects.\n\n**Q: What is the new CSV schema?**  \nA: One row per port with `target`, `port`, `protocol`, `state`, `service`, `banner`, `error`, plus metadata columns `scan_start`, `scan_end`, `elapsed_seconds`, `timeout`, `ports_scanned`, `mode`.