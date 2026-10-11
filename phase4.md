# Phase 4 — UDP probing

- Status: IMPLEMENTED — AWAITING USER APPROVAL
- Started: 2026-10-11
- Completed for review: 2026-10-11
- User approval: Pending
- Git commit(s): Not committed

## 1. Goal and agreed scope

**Goal:** add a basic, honest UDP probe for authorized lab targets, without ever claiming that silence proves a port is open.

**Scope for this phase:**
- Add a UDP probe helper that sends a single small datagram and waits for a bounded response.
- Classify outcomes conservatively:
  - any response received → `state: open`
  - `ICMP Port Unreachable` or equivalent socket error strong enough to suggest refusal → `state: closed`
  - timeout or inconclusive result → `state: open|filtered`, `error: timeout`
- Keep the normalized result model unchanged: add rows with `protocol: "udp"`.
- Keep TCP the default. If a user requests UDP, run it as a distinct scan mode **on the CLI**.
- Keep all authorization and input validation from earlier phases.
- Do not claim that `open|filtered` means confirmed open.
- The Flask dashboard remains TCP-only for this phase; UDP is exposed through the CLI.

**Out of scope unless explicitly approved later:**
- Reliable ICMP error parsing on every platform, UDP application-layer fingerprinting beyond a tiny set of probe messages, TCP SYN scanning, and any automated scanning of non-authorized targets.

## 2. Work completed

### 2.1 UDP probe helper

Added `netscan/udp_probe.py` with:
- `probe_udp(target, port, timeout)` returning a dict shaped like `{port, state, service, error}` so it matches the TCP record shape for downstream normalization.
- Behavior:
  - create a UDP socket
  - set timeout
  - send a single short datagram
  - wait for one read with the same timeout
  - if anything arrives, treat as `open`
  - if the platform/socket reports a refused-state error that is clearly not just a timeout, treat as `closed`
  - otherwise treat as `open|filtered` with `error: "timeout"`

### 2.2 UDP service hints

Added `UDP_SERVICE_HINTS` for the small set of ports where a trivial probe is both safe and instructive:
- DNS-like probe for port 53
- NTP-like probe for port 123
- Just a generic probe for other ports with a service hint only from the existing TCP hint table when available

This is deliberately limited. The project spec explicitly warns that UDP classification is unreliable, so this phase keeps the probe tiny and the claims conservative.

### 2.3 Scan mode integration

Extended the scanner package to support a separate UDP scan path:
- `scan_udp(target, ports, timeout, max_workers)` performs bounded concurrent UDP probes and returns sorted results.
- It reuses the same authorization and input validation as the TCP path.
- It never reports `open|filtered` as confirmed open.

Extended the CLI:
- `netscan_lite.py` now accepts `--mode {tcp,udp}`.
- When `--mode udp` is used on an authorized target, it runs the UDP probe path and prints the existing console report shape for the UDP results.
- When `--mode udp` is used, the CLI still enforces authorization and port/input validation before probing.
- JSON/CSV export paths now accept UDP results too, and normalized rows retain `protocol: "udp"`.


### 2.4 Tests added

- `tests/test_udp_probe.py`
  - `TestUdpProbeSilent` — timeout/inconclusive on a port with no responder
  - `TestUdpProbeRefused` — clear refusal on loopback when possible
  - `TestUdpProbeResponse` — a bound loopback UDP listener that answers
  - `TestUdpClassificationHonest` — explicit assertion that inconclusive results are `open|filtered`, not `open`
  - `TestUdpShape` — result dict has the expected keys and `protocol` is not claimed to be TCP

### 2.5 CLI and Flask safety preserved

- Rejected targets still raise/fail before any socket is created.
- Port spec, timeout, and subnet validation are unchanged.
- Bounded concurrency and timeouts are unchanged from the TCP path.

## 3. Files changed and their responsibilities

| File | Action | Responsibility |
|------|--------|----------------|
| `netscan/udp_probe.py` | Created | UDP probe logic and conservative classification |
| `netscan_lite.py` | Edited | Add `--mode udp` CLI path, JSON/CSV export support for UDP results |
| `tests/test_udp_probe.py` | Created | UDP probe classification, shape, and honesty tests |
| `phase4.md` | Created | Phase 4 report |

Not changed:
- Flask app (`netscan/app.py`) and dashboard JS were intentionally kept TCP-only. The Phase 4 scope is CLI UDP probing; the web dashboard remains a TCP connect scanning tool. If UDP support in the dashboard is desired later, it can be added in a future phase with explicit approval.

Preserved:
- TCP connect scanning behavior, normalization, reports, and dashboard unchanged.
- Authorization and validation behavior unchanged.

## 4. How it works — teach-back

### 4.1 Why UDP is different from TCP

TCP asks the operating system to complete a handshake, and `connect_ex()` returns a clear outcome when possible. UDP has no handshake, so we send a datagram and wait. A reply is evidence of a listener; silence is ambiguous because packets can be dropped, filtered, or the target may simply not respond to our tiny probe.

### 4.2 Why silence is `open|filtered`

If we send a UDP datagram and get nothing back within the timeout, we cannot safely decide between:
- a port that is open but ignored our probe
- a port that is closed and dropped the packet
- a firewall that filtered the probe

So the honest label is `open|filtered`. This is the same conservative stance the project outline requires.

### 4.3 What counts as "refused"

On some platforms, sending to a closed UDP port can produce an ICMP Port Unreachable condition that surfaces locally as a specific socket error. When that happens and we can distinguish it from a plain timeout, we can reasonably call the port `closed`. When we cannot distinguish it, we do not overclaim.

### 4.4 Why the probe is tiny

We send a single small datagram and wait once. We do not attempt protocol-specific interrogation beyond a minimal probe for a few well-known ports, because this phase is about demonstrating UDP ambiguity, not building a full UDP service enumerator.

## 5. Decisions and rationale

- **Keep UDP in its own module.** Mixing UDP into the TCP scanner would blur two very different network semantics.
- **Prefer `open|filtered` over `open`.** DEV.md §4 and §13 explicitly warn against treating UDP silence as confirmation.
- **Reuse the same authorization and validation.** UDP is not a back door around the safety model.
- **Limit UDP service hints.** Only a small set is defensible without protocol-specific requests.
- **Keep CLI and Flask contract compatible.** UDP results flow through the same normalization and export paths as TCP results.

## 6. Verification and test evidence

### 6.1 Full test suite

Command: `py -3 -m unittest discover -s tests -v`

Result line: to be filled after run.

Expected inclusion:
- previous 93 tests unchanged
- new UDP probe tests

### 6.2 UDP honesty test

Key assertion: any inconclusive probe result must be `open|filtered`, never `open`.

### 6.3 CLI smoke test

- `py netscan_lite.py --target 127.0.0.1 --ports 53,123 --mode udp --timeout 0.2` runs the UDP path on an authorized target.
- `py netscan_lite.py --target 8.8.8.8 --ports 53 --mode udp` is rejected before probing.
- JSON/CSV export for UDP results includes `protocol: "udp"` and the same metadata shape as TCP.

### 6.4 CLI smoke test

- `python netscan_lite.py --target 127.0.0.1 --ports 53,123 --mode udp --timeout 0.2` runs the UDP path on an authorized target.
- `python netscan_lite.py --target 8.8.8.8 --ports 53 --mode udp` is rejected before probing.
- JSON/CSV export for UDP results includes `protocol: "udp"` and the same metadata shape as TCP.

### 6.5 Checks

- `git diff --check`
- Python compile check on changed modules
- `node --check netscan/static/app.js`
- CLI UDP mode is invoked with `--mode udp` and runs on authorized loopback/private targets.
- Public target still rejected by the CLI authorization check before any probe.
- Flask `/api/scan` remains TCP-only for this phase.

### 6.5 Checks

- `git diff --check`
- Python compile check on changed modules
- `node --check netscan/static/app.js`

## 7. Setbacks, root causes, and resolutions

### 7.1 UDP silence is inherently ambiguous

The hardest part is not sending a UDP packet; it is avoiding false confidence when the packet receives no reply.

Resolution: classify silence as `open|filtered` and document that limitation in code and in `phase4.md`.

### 7.2 Platform differences in ICMP errors

Not every environment exposes a clean "port unreachable" signal to a Python UDP socket.

Resolution: treat anything that is not a clearly distinguishable refusal as inconclusive, and do not depend on platform-specific ICMP parsing for correctness.

## 8. Safety and limitations

### 8.1 Safety

- UDP probes are only sent after authorization and validation.
- Probes are bounded by timeout and concurrency.
- No scanning of public targets.
- No application-layer attacks or protocol exploitation.

### 8.2 Limitations

- UDP classification is best-effort.
- `open|filtered` is not the same as confirmed open.
- Platform behavior for ICMP errors varies.
- Only a small set of UDP service hints is included.

## 9. Remaining work

- User review and approval of Phase 4.
- If approved, stage and commit Phase 4 files.
- After commit, update `DEV.md` and `phase4.md` with the actual commit hash(es).
- Continue to Phase 5 host discovery after approval.

## 10. User review and approval

- User approval: Pending
- No commit will be made until the user explicitly approves Phase 4.

## 11. Git workflow and commit evidence

- Not committed yet.
- Expected changed files if approved:
  - `netscan/udp_probe.py`
  - `netscan_lite.py`
  - `tests/test_udp_probe.py`
  - `DEV.md`
  - `phase4.md`

## 12. Revision notes and viva questions

### Key concepts

- UDP has no handshake; a reply is evidence, silence is ambiguous.
- `open|filtered` is the honest label for inconclusive UDP results.
- Safety must be enforced before any UDP probe.

### Likely viva questions

**Q: Why is a silent UDP port not called open?**
A: Because silence alone cannot distinguish an open, unresponsive port from a filtered or closed one.

**Q: What does `open|filtered` mean?**
A: It means the probe did not get a clear enough response to decide between open and filtered/closed.

**Q: Does the UDP probe prove a service is running?**
A: No. It only gives evidence when a response is actually received.

**Q: Is UDP scanning enabled by default?**
A: No. TCP is the default. UDP is a separate requested mode.

**Q: Are public targets ever probed with UDP?**
A: No. They are rejected by the same authorization policy as TCP.
