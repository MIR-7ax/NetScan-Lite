# DEV.md --- NetScan-Lite

> **Ground-truth project specification, development log, phase tracker,
> learning guide, and AI-agent operating contract.**

## 1. Mandatory instructions for every AI coding agent

**Read this entire file before inspecting, planning, creating, editing,
running, or deleting project files.** Treat it as the primary source of
truth. If the repository contains additional files, inspect them and
compare their actual state with this document before making changes.

### 1.1 Initial repository state

At project start, the repository is expected to contain **only this
`DEV.md` file** and Git repository metadata. It is already a GitHub
repository. Do not assume source code, dependencies, tests, a virtual
environment, a GUI, or any completed implementation exists.

First actions: 1. Run `git status --short --branch`,
`git log -5 --oneline`, and list the repository files. 2. Confirm the
active branch, working-tree state, and whether a remote is configured
(`git remote -v`). Do not expose credentials embedded in remote URLs. 3.
Read this file completely. 4. Compare the observed repository state
against the phase tracker below. 5. Report the current state and
proposed next small step to the user before beginning a substantial
implementation. 6. Do not overwrite user work, discard changes, reset
branches, force-push, or change Git history.

If the repository state differs from this expected starting point,
**inspect and report the difference; do not assume it is an error or
delete anything**.

### 1.2 Work in small, verifiable steps

-   Work phase by phase and task by task. Explain the purpose of each
    meaningful change in plain language so the user can learn the
    networking and Python concepts, not merely receive code.
-   Before editing, state the intended scope, files expected to change,
    and how the result will be verified.
-   Implement only the agreed phase/scope. Do not silently add features,
    change the stack, or expand the project into the larger PenTestX
    platform.
-   Prefer simple, readable Python and standard-library modules. Avoid
    unnecessary dependencies and abstractions.
-   After each meaningful step, run relevant checks/tests and report
    actual results. Do not say a test passed unless it was run and
    passed.
-   If a check cannot be run, state why and give the exact unverified
    item.
-   Do not represent placeholders, simulated data, mocked functionality,
    or unimplemented features as working.
-   Never fabricate scan results, timing measurements, test results,
    completed tasks, or user approval.
-   Explain important decisions, alternatives considered, setbacks, root
    causes, and how each setback was resolved or left open.
-   If a design decision changes, update this document's decision log
    and phase plan.
-   Keep the user informed without flooding them with repeated setup
    instructions.

### 1.3 Approval and Git commit gate --- mandatory

**A phase is not approved merely because the agent says it is complete.
The user must explicitly approve the phase.**

1.  Finish the phase's agreed implementation and verification.
2.  Update `DEV.md` with actual work, explanations, test results,
    setbacks/resolutions, decisions, and current status.
3.  Create the phase report `phase[N].md` for that completed phase (see
    Section 8). The report must agree with the code, test output, and
    `DEV.md`.
4.  Show the user a concise completion summary, test evidence,
    changed-file list, and report location. Ask for explicit approval.
5.  **Do not commit before explicit user approval of that phase.**
    Silence, continued conversation, a request for a fix, or the agent's
    own assessment is not approval.
6.  If the user requests changes, make them, rerun the relevant checks,
    update `DEV.md` and the phase report, and ask for approval again.
7.  Once the user explicitly approves, inspect `git diff` and
    `git status`; stage only the files belonging to the approved phase,
    review the staged diff, and create a descriptive commit.
8.  After the commit, verify `git status` and `git log -1 --oneline`.
    Update `DEV.md` and the phase report with the actual commit hash and
    commit outcome. These documentation changes must also be included in
    Git: after approval has been given for the phase, make a final
    documentation commit if needed, or amend the phase commit only if
    doing so is safe, transparent, and does not rewrite shared history.
    Prefer a separate documentation commit to avoid ambiguity.
9.  Report the exact commit hash(es), files committed, and whether the
    working tree is clean. Do not push to GitHub unless the user
    explicitly asks or has already established a clear standing
    instruction to push.
10. If a commit fails, report the real error and resolve it without
    bypassing safeguards. Never use `--no-verify`, force-push, or
    destructive Git commands merely to make the workflow pass.

**Approval is per phase.** Approval of one phase does not authorize
commits for later phases. Emergency fixes and documentation changes
outside the approved phase still require transparent scope handling; ask
before committing them unless the user explicitly authorizes them.

### 1.4 Keep this file as living ground truth

Update this file during development---not just at the end. Maintain: -
Current phase and status. - What has actually been implemented and
why. - File/module responsibilities and data flow. - Commands run and
their actual results. - Tests performed and gaps remaining. - Setbacks,
root causes, fixes, and unresolved issues. - Decisions and the reasons
behind them. - Scope changes and user approvals. - Phase report
links/names and commit hashes. - A beginner-friendly explanation that
another AI or the user can use to reconstruct the project's state and
learn what happened.

Do not erase useful history to make the project look cleaner. Correct
mistakes transparently and preserve meaningful decision history.

------------------------------------------------------------------------

## 2. Project identity and purpose

**Project name:** NetScan-Lite --- Custom TCP/UDP Port Scanner & Network
Mapper\
**Course context:** Computer Networks (CN) mini project\
**Relationship to larger project:** Educational, standalone scanning
sub-module intended to teach the principles behind the
port-and-service-discovery portion of PenTestX.

### 2.1 Problem and goal

Network tools such as Nmap automate host discovery, port scanning, and
service identification. NetScan-Lite implements a deliberately smaller
version in Python so the student can understand what happens underneath
the tool rather than simply invoking Nmap.

The core learning goal is to demonstrate TCP/IP, ports, sockets, TCP
connection establishment, UDP's connectionless behavior, ICMP-based
discovery, concurrent network I/O, and structured scan reports.

### 2.2 Intended outcomes

When the relevant phases are complete, the project should be able to: -
Discover responsive hosts in an explicitly authorized private lab
subnet, using a clearly documented discovery method. - Perform a TCP
connect scan over a user-selected port range. - Perform a basic UDP
probe and represent uncertain results honestly. - Attempt basic
service/banner identification where a service actually sends a
response. - Map common port numbers to conventional service names. -
Scan multiple ports concurrently with bounded concurrency and
timeouts. - Export results to JSON and CSV. - Offer a straightforward
command-line interface. - Optionally provide a minimal Flask interface
only if the user approves it and the core course scope is complete. -
Include sample evidence from an owned/local lab target and a short
explanation of networking concepts and measured performance.

These are **planned outcomes, not claims that the implementation
currently exists**.

------------------------------------------------------------------------

## 3. Scope and boundaries

### 3.1 In scope

1.  **Host discovery:** test whether hosts in an explicitly authorized
    private subnet respond to the selected discovery method. A ping
    failure does not prove that a host is offline; ICMP may be blocked.
2.  **TCP connect scanning:** use Python's `socket` API and
    `connect_ex()` to ask the operating system to establish a TCP
    connection. A successful connection normally means the port accepted
    the connection.
3.  **UDP probing:** send a protocol-appropriate or carefully documented
    probe and interpret responses conservatively. UDP has no TCP-style
    handshake, and silence alone cannot distinguish an open port from a
    filtered port.
4.  **Service mapping:** map common port numbers to conventional service
    labels. A port number is a hint, not proof of the service actually
    running.
5.  **Banner identification:** attempt a short, bounded read only when
    appropriate. Many services do not send data until a valid
    application request is sent; an empty banner is not a scan failure.
6.  **Concurrency:** use bounded threads or another justified
    standard-library approach to avoid waiting for every port
    sequentially.
7.  **Reporting:** export structured results to JSON and CSV, including
    target, port, protocol, state, service hint, banner when available,
    and useful scan metadata.
8.  **CLI:** accept a target or subnet, port range, scan modes, timeouts
    where appropriate, and report format.10. **Learning/documentation:** explain implementation, observed
     results, limitations, and verified timing comparisons.

### 3.2 Out of scope unless explicitly approved

-   CVE/vulnerability correlation or exploitation.
-   Metasploit, OWASP ZAP, automated Wireshark capture, or full PenTestX
    functionality.
-   Credential attacks, brute force, stealth/evasion, or scanning public
    targets.
-   Database persistence, authentication, production web deployment, or
    a complex frontend.
-   PDF report generation.
-   TCP SYN/half-open scanning as a required feature. It is an optional
    stretch goal because raw packet handling and administrative
    privileges/platform differences add complexity.
-   Any dependency or feature that is not needed to demonstrate the
    stated CN learning objectives.

### 3.3 Technology choices

-   **Language:** Python 3.10+ (use the installed compatible Python
    version and document it).
-   **Core networking:** `socket`.
-   **Concurrency:** `concurrent.futures.ThreadPoolExecutor` initially,
    unless a measured or technical reason justifies another approach.
-   **IP/subnet handling:** `ipaddress`.
-   **CLI:** `argparse`.
-   **Reports:** standard-library `json` and `csv`.
-   **Host discovery:** a platform-aware system `ping` fallback may be
    used; Scapy is optional only if approved and justified.-   **Web UI:** Flask, developed incrementally alongside the scanning engine starting in Phase 2. The Phase 2 dashboard is mandatory and already committed (commit 1fa22ae).
 -   **Testing:** Python standard-library `unittest` or another agreed
    lightweight framework.

Do not add React, FastAPI, a database, Docker, or external scanning
libraries to the core scanner without an explicit scope decision.

------------------------------------------------------------------------

## 4. Safety and authorization requirements

This tool is for learning and authorized lab use only.

-   Default to loopback and private lab addresses. Recommended targets
    are `127.0.0.1`, a VM the user owns, or a host-only/NAT lab network
    the user controls.
-   Before sending probes, validate the target and subnet and enforce
    the approved scope. Reject public/global targets by default.
-   Do not assume `ipaddress.ip_address(...).is_private` alone is a
    complete policy check: loopback, link-local, multicast, reserved,
    and other special ranges need deliberate handling. Define and test
    an explicit allow policy.
-   Validate subnet size and port ranges to prevent accidental huge
    scans or resource exhaustion.
-   Use finite timeouts, bounded concurrency, clear progress, and safe
    error handling.
-   Do not require administrator/root privileges for the core TCP
    connect scanner. If a stretch feature requires elevated privileges,
    explain why and request explicit approval before implementing it.
-   Never scan a third-party system without explicit authorization from
    its owner.
-   Avoid aggressive rates. Do not implement stealth, evasion, or bypass
    behavior.
-   Display a clear message explaining why an out-of-scope target was
    rejected.
-   Do not store credentials or secrets in source control. Inspect
    `.gitignore` and never commit environment secrets.
-   Tests should primarily use mocks, loopback sockets, or a
    deliberately configured lab VM. Avoid tests that unexpectedly scan a
    real network.

**Important technical distinction:** TCP connect scanning delegates the
TCP handshake to the operating system. It is not the same as a
raw-packet SYN scan. UDP silence is ambiguous; do not label every silent
UDP port as definitely open.

------------------------------------------------------------------------

## 5. Architecture and data flow

Planned logical flow:

``` text
User
  |
  v
CLI argument parsing and input validation (Phase 1: IMPLEMENTED)
  |
  +--> Target/subnet authorization checks (Phase 1: IMPLEMENTED)
  |
  +--> Host discovery (optional; only when a subnet is supplied) [Phase 5]
  |
  v
Per-host scan coordinator [Phase 2]
  |  +--> TCP connect scanner [Phase 2]
   |
   +--> Flask web dashboard (mandatory deliverable) [Phase 2]
   |
   +--> UDP probe scanner (if requested) [Phase 4]
  |
  +--> Service-name mapping and optional banner identification [Phase 3]
  |
  v
Normalized scan results [Phase 3]
  |
  +--> Console summary [Phase 3]
  +--> JSON report [Phase 3]
  +--> CSV report [Phase 3]

```

The implementation may start in one file for simplicity, then be split
into modules only when the code and tests justify it. Any architectural
change must be recorded in the decision log.

### 5.1 Actual file layout (after Phase 1)

The following files have been created:

``` text
NetScan-Lite/
├── DEV.md
├── phase0.md
├── phase1.md
├── README.md
├── .gitignore
├── netscan_lite.py        # CLI entry point with argparse, validation, and authorization
├── tests/
│   ├── __init__.py
│   └── test_validation.py # Unit tests for validation and authorization logic
└── reports/               # created when needed for scan evidence
```

The implementation uses a single-file design (`netscan_lite.py`) for Phase 1.
If the code grows complex in later phases, it may be split into modules
(e.g., `netscan/` package) as justified by the implementation.

### 5.2 Normalized result model

As features are added, keep a consistent result shape. At minimum, each
port result should identify: - `target` - `port` - `protocol` (`tcp` or
`udp`) - `state` (for example, `open`, `closed`, `filtered`,
`open|filtered`, or `error`, only where evidence supports the label) -
`service` (a conventional port-based hint or `unknown`) - `banner`
(string or empty when unavailable)

Scan metadata may include start/end timestamps, elapsed duration,
timeout, selected ports, tool version, and error details. Never imply
that a service label or banner proves a vulnerability.

------------------------------------------------------------------------

## 6. Technical concepts the agent must teach

When implementing a concept, briefly explain it to the user and connect
it to the code and observed output.

### 6.1 TCP connect scan

TCP normally establishes a connection with a three-way handshake: SYN,
SYN-ACK, ACK. Calling `socket.connect()` or `connect_ex()` asks the
operating system to establish the connection; the OS handles the
handshake. A successful connection is evidence that the remote endpoint
accepted it at that time. A timeout or error does not always prove a
port is closed; firewalls and network conditions matter.

### 6.2 UDP scan

UDP does not establish a TCP-style connection. A UDP application may
reply to a valid request, while a closed UDP port may cause an ICMP Port
Unreachable response. A timeout is inconclusive and is commonly reported
as `open|filtered` rather than definitely open. ICMP error delivery
differs by operating system and environment, so the implementation must
document its limitations.

### 6.3 Host discovery

A ping sweep sends ICMP echo requests (or uses the documented platform
ping utility) and checks for responses. Hosts may block echo requests
and still be active. Therefore report "responded" or "no response," not
an unsupported claim that a host is definitively online/offline.

### 6.4 Service names and banners

Well-known port mappings such as TCP 22 → SSH, TCP 80 → HTTP, and TCP
443 → HTTPS are conventions. Services can use nonstandard ports. Banner
grabbing is best-effort: some services send a greeting immediately;
others require a valid request or do not expose a banner.

### 6.5 Concurrency and performance

Bounded concurrency allows multiple network operations to wait at the
same time, reducing total elapsed time for I/O-bound work. Too many
workers can overload the machine or target. Performance comparisons must
use the same target, port range, timeout, environment, and scan logic;
record actual measured values rather than predicting them.

------------------------------------------------------------------------

## 7. Phased implementation plan

**Phase statuses must be updated from evidence.** Initially all phases
are `NOT STARTED`; do not mark a phase complete because its plan has
been written.

Status vocabulary: `NOT STARTED` → `IN PROGRESS` →
`IMPLEMENTED — AWAITING USER APPROVAL` → `APPROVED — COMMIT PENDING` →
`COMMITTED`. A phase may instead be `BLOCKED` or `REVISED`.

### Phase 0 --- Repository reconnaissance and project contract

**Goal:** establish the real starting state and working agreement.

Tasks: - Inspect Git status, recent history, branch, remote, and
repository files. - Confirm only `DEV.md` plus Git metadata exists, or
document the actual differences. - Verify Python availability without
installing unnecessary packages. - Confirm the authorized testing
approach and agree on the initial implementation step.

Verification: - Record commands and outputs relevant to repository state
and Python version. - No scanner implementation is claimed in this
phase.

Deliverable: updated `DEV.md` state and `phase0.md` only when the user
agrees Phase 0 is a completed reportable phase.

### Phase 1 --- Minimal CLI, validation, and safe scope

**Goal:** create a reliable entry point and prevent accidental
out-of-scope scanning.

Tasks: - Establish the minimal file layout. - Implement `argparse`
options and robust validation for targets, subnets, port ranges, scan
modes, and report format. - Implement and test the explicit target allow
policy before network probes can occur. - Provide useful help and clear
validation errors.

Verification: - Help output works. - Invalid addresses, malformed
ranges, invalid ports, and out-of-scope targets are rejected. - Unit
tests prove rejected targets do not trigger network probes.

Deliverable: `phase1.md` after implementation and verification.

### Phase 2 --- TCP connect scanner and Flask web dashboard

**Goal:** scan a user-selected port range on an authorized lab host, and
provide the mandatory Flask web dashboard for local learning use.

Tasks: - Implement a bounded-timeout TCP connect check using `socket`. -
Distinguish a successful connection from other results without
overclaiming closed/filtered states. - Map common TCP ports to
service-name hints. - Add bounded concurrency after a correct baseline
exists. - Build and commit the Flask dashboard (target input, port
configuration, scan initiation, results display, JSON/CSV export) with
server-side authorization and validation. - Keep the CLI working.

Verification: - Test TCP states: connect -> open, ECONNREFUSED -> closed,
timeout -> unknown. - Test timeouts, socket cleanup, and bounded
concurrency. - Test the Flask dashboard via the test client: validate
route, scan route, static assets, dashboard HTML. - Reject out-of-scope
targets with 403 and never create sockets for them. - Verify commit
1fa22ae adds the dashboard UI.

Deliverable: `phase2.md` and the Flask dashboard package
(`netscan/` module with `app.py`, `tcp_scanner.py`, `validation.py`,
and the dashboard HTML/CSS/JS), already committed.

### Phase 3 --- Result model, service/banner identification, and reports

**Goal:** normalize results and save useful JSON/CSV output.

Tasks: - Define a stable result structure. - Implement cautious banner
identification with bounded reads and clear failure handling. - Write
JSON and CSV reports with appropriate fields and metadata. - Ensure
output paths and filenames are safe and understandable.

Verification: - Parse generated JSON and CSV and compare their records
with the actual scan results. - Test empty results, missing banners,
errors, and filenames. - Do not claim that banner identification is
universal or vulnerability detection.

Deliverable: `phase3.md`.

### Phase 4 --- UDP probing

**Goal:** implement a basic, honest UDP scan for authorized lab targets.

Tasks: - Add UDP probes with finite timeouts. - Interpret application
replies and available ICMP/error indications carefully. - Represent
silence as ambiguous (`open|filtered`) rather than definitely open. -
Document platform-specific limitations.

Verification: - Use loopback or an explicitly authorized lab service. -
Unit-test state interpretation independently of real network behavior. -
Document cases that cannot be reliably classified.

Deliverable: `phase4.md`.

### Phase 5 --- Host discovery

**Goal:** discover hosts that respond in an approved private subnet.

Tasks: - Add subnet parsing and bounded host iteration. - Use a
documented, platform-aware ping method or an approved optional
dependency. - Limit subnet size and concurrency. - Report no response as
inconclusive, not proof that the host is offline.

Verification: - Test subnet parsing and scope restrictions. - Verify
command construction and error handling. - Perform real discovery only
on the user's own authorized lab network.

Deliverable: `phase5.md`.

### Phase 6 --- Integration, test coverage, and measured evaluation

**Goal:** make the components work together and establish credible
evidence.

Tasks: - Integrate target/subnet selection, TCP/UDP modes, service
hints, result normalization, and report output. - Add regression tests
and user-facing usage examples. - Measure scan duration under
controlled, repeatable conditions. - Record environment, selected ports,
timeouts, and limitations.

Verification: - Run the complete test suite. - Run a bounded
demonstration against loopback or an authorized lab VM. - Validate
generated reports and compare reported results with observed output. -
Record actual timing results and methodology.

Deliverable: `phase6.md`.

### Phase 7 --- Course documentation and demonstration

**Goal:** prepare a clear CN mini-project submission.

Tasks: - Write/update `README.md` with setup, safe usage, examples,
architecture, limitations, and report locations. - Explain TCP's
three-way handshake, UDP ambiguity, ICMP discovery, service mapping, and
concurrency. - Prepare a short technical write-up and safe demonstration
evidence. - Optionally implement a minimal Flask UI only if the user
explicitly approves it.

Verification: - Follow the documented instructions from a clean
environment where practical. - Check all commands and
screenshots/evidence against actual behavior. - Confirm the submission
does not imply unsupported capabilities.

Deliverable: `phase7.md`.

### Optional Phase 8 --- TCP SYN scan

Only begin after the core project is complete and the user explicitly
approves the selected extension. Do not bundle SYN scanning with the
Flask UI scope automatically. Document platform and privilege
requirements before implementation.

------------------------------------------------------------------------

## 8. Phase completion reports

For every phase that is implemented, verified, and ready for the user's
review, create a Markdown report at the repository root named exactly
`phase[N].md`, where `[N]` is the numeric phase, e.g. `phase1.md`,
`phase2.md`.

Do not create a report that falsely claims a phase is complete. If a
phase is blocked or partially implemented, record that state in
`DEV.md`; create or update the phase report only when it helps
transparently document the work, and label it clearly as incomplete.
Never reuse one phase's report for another phase.

Each report must include:

1.  Phase number, title, current status, and date.
2.  Goal and scope agreed with the user.
3.  Work completed, with file paths and explanations of what each change
    does.
4.  Why the implementation/design was chosen and relevant alternatives.
5.  How the feature works, step by step, in beginner-friendly language.
6.  Commands run and actual test results, including failures.
7.  Setbacks encountered, root cause, fix/workaround, and any unresolved
    limitations.
8.  Safety checks and evidence for the authorized test scope.
9.  What remains incomplete and what the next phase depends on.
10. User approval status and date, recorded only after explicit
    approval.
11. Git commit hash(es), commit message(s), and status, recorded only
    after commits actually happen.
12. A short "teach me / revise me" section with key concepts, code
    paths, and likely viva questions with accurate answers.

The report is a historical record of that phase. If later fixes change
its behavior, update the report transparently or add a dated follow-up
note; do not quietly rewrite history.

### Report template

Use this structure for every `phase[N].md`:

``` markdown
# Phase N — [Title]

- Status: [IN PROGRESS / IMPLEMENTED — AWAITING USER APPROVAL / APPROVED — COMMIT PENDING / COMMITTED / BLOCKED]
- Started: [date or Not recorded]
- Completed for review: [date or Not yet]
- User approval: [Not requested / Pending / Approved on date]
- Git commit(s): [Not committed / hash and message]

## 1. Goal and agreed scope
## 2. Work completed
## 3. Files changed and their responsibilities
## 4. How it works — teach-back
## 5. Decisions and rationale
## 6. Verification and test evidence
## 7. Setbacks, root causes, and resolutions
## 8. Safety and limitations
## 9. Remaining work
## 10. User review and approval
## 11. Git workflow and commit evidence
## 12. Revision notes and viva questions
```

------------------------------------------------------------------------

## 9. Required Git workflow

### 9.1 Before work

Run and inspect:

``` bash
git status --short --branch
git log -5 --oneline
git remote -v
```

Never assume the tree is clean. Preserve unrelated user changes.

### 9.2 During implementation

-   Make focused, understandable changes.
-   Review diffs regularly with `git diff`.
-   Do not stage generated reports or scan outputs indiscriminately.
    Inspect every file before deciding whether it belongs in source
    control.
-   Update `.gitignore` when necessary, without hiding source files or
    useful documentation.
-   Do not include secrets, personal network data, or sensitive scan
    outputs in commits.

### 9.3 Phase review gate

Before requesting approval:

``` bash
git status --short
git diff --check
git diff
```

Run the applicable tests and include the actual results in the phase
report. Show a concise file list and summary to the user. Wait for
explicit approval.

### 9.4 After approval

-   Confirm the user's approval applies to the exact phase and changes
    being committed.

-   Stage only the reviewed files, for example:

    ``` bash
    git add DEV.md phaseN.md path/to/approved/source.py path/to/approved/tests
    git diff --cached --check
    git diff --cached
    ```

-   Commit with a descriptive message, such as:

    ``` bash
    git commit -m "feat: implement TCP connect scanning"
    ```

    Use a message that accurately reflects the work; examples are not
    mandatory formats.

-   Verify:

    ``` bash
    git status --short --branch
    git log -1 --oneline
    ```

-   Record the resulting hash and final status in `DEV.md` and
    `phaseN.md`. Commit any final documentation-only changes
    transparently. Do not claim the documentation is committed if it is
    not.

-   Do not push without authorization.

------------------------------------------------------------------------

## 10. Current phase tracker

**Initial status:** all implementation phases are `NOT STARTED` until
verified work changes them.

  -----------------------------------------------------------------------
  Phase             Scope             Initial status    Report
  ----------------- ----------------- ----------------- -----------------
  0                 Repository        COMMITTED         `phase0.md`
                    reconnaissance
                    and project
                    contract

  1                 CLI, input        COMMITTED         `phase1.md`
                    validation, safe
                    scope

  2                 TCP connect       NOT STARTED       `phase2.md`
                    scanner

  3                 Result model,     IN PROGRESS        `phase3.md` (draft in
                    banner             progress)           working tree; not
                    identification,                                    committed)
                    JSON/CSV

  4                 UDP probing       COMMITTED          `phase4.md` (commit bf61b35)

  5                 Host discovery    NOT STARTED       `phase5.md`

  6                 Integration,      NOT STARTED       `phase6.md`
                    tests, measured
                    evaluation

  7                 Course            NOT STARTED       `phase7.md`
                    documentation and
                    demonstration

  8                 Optional          NOT STARTED       `phase8.md` if
                    extension, only                     selected
                    if approved
  -----------------------------------------------------------------------

Update this table whenever the status changes. Do not mark phases
complete based on planned work.

------------------------------------------------------------------------

## 11. Development log

Append dated entries as work happens. Keep entries factual and concise;
link to phase reports for details.

  ----------------------------------------------------------------------------------------------------
  Date         Phase        Work/decision   Verification/evidence   Setback or       Approval/commit
                                                                    unresolved item
  ------------ ------------ --------------- ----------------------- ---------------- -----------------
  2026-10-10   0            Repository      Cloned GitHub repo;     Git status,      Approved on
                            reconnaissance  inspected Git state,    log, remote      2026-10-10;
                            and project     read DEV.md, verified    inspected;       committed as
                            contract        Python 3.13.5; updated    Python version    4a0e58d.
                                            .gitignore to protect    verified.
                                            secrets; updated DEV.md
                                            with Flask UI requirement
                                            and phase tracker.

  2026-10-10   1            CLI, input      Created netscan_lite.py  15 unit tests    Approved on
                            validation,     with argparse CLI,      passed;          2026-10-10;
                            safe scope      input validation,       help output       committed as
                                            target authorization     verified;         12d853f.
                                            policy, port/subnet      validation
                                            validation, and unit    errors tested.
                                            tests.

  2026-10-11   3            Result model,   Added result normalization,  93 unit tests   Pending user
                            banner            JSON/CSV report functions,   pass (Phase 1 +   review before
                            identification,   best-effort TCP banner       Phase 2 + Phase   committing
                            JSON/CSV          grabbing, and CLI/Flask     3 subsets);     Phase 3.
                            reporting         structured export route     added tests for
                                            (/api/scan/export) plus      normalization,
                                            CLI export smoke tests      JSON, CSV, file
                                            (tests/                output, banner
                                            test_phase3_reports.py,    grabbing, and
                                            tests/test_phase3_cli_     structured export
                                            export.py, plus Flask     route; no
                                            route tests). Banner is    dashboard visual
                                            best-effort (empty is     browser review
                                            normal). CLI now returns   performed.
                                            exit code so callers can
                                            test success/failure.  2026-10-11   4            UDP probing    Created netscan/udp_probe.py   103 unit tests   Approved;
                           (CLI only; Flask   with probe_udp, scan_udp,     pass (Phase 1 +   committed as
                           stays TCP-only)    and CLI --mode udp path in     Phase 2 + Phase   bf61b35.
                                               netscan_lite.py; added         3 + Phase 4       Flask dashboard
                                               tests/test_udp_probe.py.       subsets); added   intentionally kept
                                               UDP silence classified as       UDP honesty,       TCP-only.
                                               open|filtered, not open.       shape, and
                                               CLI UDP smoke tests             response tests
                                               verified; Flask dashboard      passed.
                                               intentionally kept TCP-only.


  2026-10-10   Project      Defined         Specification           Repository       No phase approval
               definition   NetScan-Lite    documented;             state, Python    or commit
                            scope, learning implementation not yet  environment, Git recorded.
                            goals, safety   verified.               branch/remote,
                            boundary, phase                         and existing
                            plan, report                            files must be
                            and approval                            inspected by the
                            workflow in                             agent before
                            `DEV.md`.                               coding.

  ----------------------------------------------------------------------------------------------------

------------------------------------------------------------------------

## 12. Decision log

Record decisions that affect scope, architecture, safety, dependencies,
or behavior. Add dates and reasons; do not silently reverse earlier
choices.

  -----------------------------------------------------------------------------
  Date              Decision             Rationale         Consequence/status
  ----------------- -------------------- ----------------- --------------------
  2026-10-10        Keep the core        The course        Initial project
                    scanner Python-first objective is to   direction;
                    and based on the     learn socket      implementation not
                    standard-library     programming and   yet verified.
                    `socket` API.        networking        
                                         behavior, not     
                                         wrap an existing  
                                         scanner.          

  2026-10-11        CLI and Flask        CLI and Flask now   Phase 3 tests
                    share a structured   share a normalized   cover JSON/CSV
                    result shape and     result shape and     output, metadata,
                    export path          export path           and best-effort
                    (Phase 3)            (Phase 3). Dashboard  TCP banners.
                                         export buttons added
                                         under existing UI.

  2026-10-11        UDP probing (CLI     Added UDP probe     103 unit tests pass   UDP silence is
                    only; Flask stays    module and CLI       (Phase 1 + 2 + 3 +   inherently
                    TCP-only)            --mode udp support   Phase 4); UDP probe   ambiguous; only
                                        in netscan_lite.py;  honesty and shape     a response proves
                                        Flask intentionally   verified; Flask        open.
                                        kept TCP-only.       dashboard stays
                                                           TCP-only for now.
  2026-10-10        Use TCP connect      Connect scanning  SYN scanning
                    scanning as the      is easier to      requires a separate
                    required TCP method; explain and       explicit scope
                    treat raw-socket SYN avoids making     decision.
                    scanning as          elevated          
                    optional.            privileges a core 
                                         requirement.      

  2026-10-10        Treat UDP silence as A missing UDP     State interpretation
                    inconclusive         response does not must preserve
                    (`open|filtered`).   prove that the    uncertainty.
                                         port is open.     

  2026-10-10        Require explicit     The user wants to Mandatory Git gate
                    user approval before review each       for every phase.
                    each phase commit.   completed phase
                                         before its work
                                         is committed.

  2026-10-10        Flask web UI is      User explicitly   Final application
                    mandatory deliverable requested the     must include a
                    (not optional)      final app must     Flask dashboard.
                                         include a Flask
                                         web dashboard.

  2026-10-10        Validate ports       Port validation    Fail fast on
                    before targets       is simpler and      malformed input
                                         faster; fail fast   before complex
                                         on malformed       IP validation.
                                         input.

  2026-10-10        Limit port ranges    Prevent accidental  Bounded resource
                    to 1000 ports        resource            usage for all
                                         exhaustion while    scans.
                                         allowing practical
                                         ranges.

  2026-10-10        Restrict subnets     /24 or smaller      Prevents
                    to ≤256 addresses    subnets are         excessive subnet
                                         reasonable for      scans.
                                         lab use.

  2026-10-10        Use Python's         Standard library    Robust IP
                    ipaddress module     provides robust     validation and
                    for validation       IP validation and   classification.
                                         classification.
  -----------------------------------------------------------------------------

------------------------------------------------------------------------

## 13. Known caveats in the original project outline

The original project idea is the source of the intended scope, but
reference pseudocode is not automatically production-ready. The agent
must verify and address these points during implementation:

-   The host-discovery pseudocode uses `platform.system()` but omits
    `import platform`.
-   Ping flags and timeout semantics differ between Windows and
    Unix-like systems; command construction must be platform-aware and
    tested.
-   A blanket `is_private` check may admit or mishandle special-purpose
    ranges depending on Python's address classification. Implement an
    explicit, documented allow policy.
-   The sample TCP banner function reads from a connected socket before
    sending an application request. It may return an empty string or
    time out for services that wait for a request; this is normal and
    must be handled.
-   The sample UDP function cannot reliably classify every port as open
    or closed. Platform-specific ICMP error behavior and valid
    application probes matter.
-   A UDP result record must include `protocol="udp"`; a report schema
    that only says `port/state/service/banner` is insufficient when TCP
    and UDP results are combined.
-   `connect_ex()` returns an error code; avoid reducing all nonzero
    results to "closed" without preserving the distinction between
    refusal, timeout, and other failures where feasible.
-   Thread counts and subnet sizes must be bounded. A `/24` example does
    not justify allowing arbitrarily large subnet sweeps.
-   The proposed architecture's "TCP SYN/ACK handshake" label describes
    the TCP connect behavior only loosely; the operating system
    completes the handshake when using `connect()`. Do not describe it
    as a custom raw-packet SYN scanner.
-   Sample code and example ports are illustrative. Real open ports,
    banners, scan duration, and test outcomes must come from actual runs
    against an authorized target.

------------------------------------------------------------------------

## 14. Final operating rule

At every handoff, another AI agent or the user should be able to answer
from `DEV.md` and the phase reports:

-   What is this project and why does it exist?
-   What is implemented now, and what is only planned?
-   Which files implement each behavior?
-   How does the implementation work?
-   What was tested, and what evidence exists?
-   What went wrong, why, and how was it handled?
-   What remains incomplete or uncertain?
-   Which phase is next?
-   Has the user approved the current phase?
-   What was committed, and what is the exact commit hash?

If these questions cannot be answered accurately, update the
documentation before moving to the next phase.
