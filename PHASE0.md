# Phase 0 — Repository Reconnaissance and Project Contract

- Status: COMMITTED
- Started: 2026-10-10
- Completed for review: 2026-10-10
- User approval: Approved on 2026-10-10
- Git commit(s): 4a0e58d "docs: Phase 0 — repository reconnaissance and project contract"

## 1. Goal and agreed scope

**Goal:** Establish the real starting state of the repository and agree on
the working contract before any scanner implementation begins.

**Scope agreed with user:**

- Inspect Git status, recent history, branch, remote, and repository files.
- Confirm the repository contents against the expected starting point
  described in `DEV.md` §1.1, documenting any differences.
- Verify Python availability without installing unnecessary packages.
- Confirm the authorized testing approach.
- Record findings in `phase0.md` and update `DEV.md`.
- Update `.gitignore` to protect secrets and exclude generated artifacts.
- No scanner implementation is claimed in this phase.

**User-confirmed decisions (2026-10-10):**

1. **Authorized testing scope:** Scanning is restricted to `127.0.0.1`
   (loopback) and private lab machines or networks the user owns or is
   authorized to test. Public/global targets are rejected by default.
2. **Flask web UI is mandatory:** The final application must include a
   Flask dashboard as a required deliverable, not an optional extension.
   The CLI and scanning engine are implementation components beneath the
   UI. Phase 1 scope is not expanded to build the Flask UI yet.
3. **Approval-before-commit workflow:** Every phase requires explicit user
   approval before committing. No pushing to GitHub without authorization.

## 2. Work completed

- Cloned the GitHub repository `MIR-7ax/NetScan-Lite` into the workspace.
- Ran `git status --short --branch`, `git log -5 --oneline`,
  `git remote -v`, and `ls -la`.
- Inspected every commit with `git show --stat` to understand what each
  commit changed.
- Read `DEV.md` (857 lines) and `README.md` in full.
- Verified Python 3.13.5 is available at `/usr/bin/python3`.
- Inspected `.gitignore` history across all four commits.
- Updated `.gitignore` to protect secrets and exclude generated artifacts.
- Updated `DEV.md` phase tracker, development log, decision log, and
  architecture section to reflect Phase 0 findings and the Flask UI
   requirement.

## 3. Files changed and their responsibilities

| File | Action | Responsibility |
|------|--------|----------------|
| `phase0.md` | Created | This report — the Phase 0 historical record |
| `DEV.md` | Updated | Phase tracker status, development log, decision log, architecture notes for Flask UI |
| `.gitignore` | Updated | Excludes secrets, caches, virtual environments, and generated scan reports |

No source code, tests, or scanner modules were created in this phase.

## 4. How it works — teach-back

### Repository inspection

Before writing any code, we inspect the repository to understand its
starting state. This is important because:

- **Git history tells us what already exists.** If we skip this step, we
  might overwrite user work or assume files exist that don't.
- **The branch and remote tell us where commits will go.** We confirmed
  we are on `main` tracking `origin/main`, so any future commit will
  apply to the main branch.
- **The working tree status tells us if there are uncommitted changes**
  that we must preserve.

### What the commits reveal

The repository was set up in four small commits:

1. **`ae6f96c` (initial):** Created a `.gitignore` that ignored all
   `*.md` files. This was likely a placeholder to keep the repo clean
   while planning.
2. **`00102b2` (README):** Added a 3-line `README.md` describing the
   project as an educational network scanner.
3. **`9645a17` (3):** Changed `.gitignore` from `*.md` to `DEV.md`,
   allowing `README.md` to be tracked while still ignoring the spec.
4. **`c7fd57c` (3):** Emptied `.gitignore` entirely and added the full
   857-line `DEV.md` specification.

### Python verification

We confirmed Python 3.13.5 is installed. This exceeds the Python 3.10+
requirement stated in `DEV.md` §3.3. No external packages are needed
for Phase 0 — all inspection was done with standard Git and shell tools.

### .gitignore update

The original `.gitignore` was empty, meaning all files (including
secrets) would be staged by `git add .`. We updated it to exclude:

- `.env` and environment files (secrets/credentials)
- Python bytecode caches (`__pycache__/`, `*.pyc`)
- Virtual environments (`venv/`, `.venv/`)
- Generated scan reports (`reports/` directory — only approved samples
  should be committed manually)
- OS/editor artifacts (`.DS_Store`, `*.swp`)

This protects against accidentally committing credentials or generated
data while preserving all source files and documentation.

## 5. Decisions and rationale

| Decision | Rationale |
|----------|-----------|
| Document differences from expected starting state instead of treating them as errors | `DEV.md` §1.1 expected only `DEV.md` + Git metadata; actual repo also has `README.md` and an empty `.gitignore`. These are benign additions, not problems. |
| Restrict scanning to loopback and authorized private lab targets | User confirmed this scope. Prevents accidental scanning of public/third-party systems. |
| Make Flask UI mandatory in `DEV.md` | User explicitly requested the final app must include a Flask web dashboard. Updated scope and architecture to reflect this. The Flask UI will be built in a later phase after core scanning functionality. |
| Update `.gitignore` now rather than in Phase 1 | The empty `.gitignore` is a security risk — `.env` could be committed accidentally. Fixing it in Phase 0 is preventative. |

## 6. Verification and test evidence

### Commands run and actual output

**`git status --short --branch`:**
```
## main...origin/main
?? .env
?? .gitkeep
?? package-lock.json
```
Working tree has no modifications to tracked files. Three untracked files
(`.env`, `.gitkeep`, `package-lock.json`) are from the Bolt environment,
not from the original GitHub repository.

**`git log -5 --oneline`:**
```
c7fd57c 3
9645a17 3
00102b2 README
ae6f96c initial
```
Four commits total, all on `main`.

**`git remote -v`:**
```
origin  https://github.com/MIR-7ax/NetScan-Lite.git (fetch)
origin  https://github.com/MIR-7ax/NetScan-Lite.git (push)
```

**`python3 --version`:**
```
Python 3.13.5
```
Location: `/usr/bin/python3`

**`git diff --stat HEAD`:** No output — no tracked files are modified.

### No scanner tests were run

Phase 0 does not implement any scanner functionality. No network probes
were performed. No tests were run. This is expected and correct.

## 7. Setbacks, root causes, and resolutions

No setbacks were encountered in Phase 0.

One note: the `.gitignore` was empty in the committed repository, which
meant `.env` (containing credentials) would have been included in any
`git add .` command. This was not a setback but a risk identified during
reconnaissance. It is resolved by the `.gitignore` update in this phase.

## 8. Safety and limitations

- **Authorized scope confirmed:** Loopback (`127.0.0.1`) and user-owned
  private lab machines/networks only.
- **No network probes were performed** in this phase.
- **`.gitignore` updated** to prevent accidental credential exposure.
- **No secrets were committed.** The `.env` file remains untracked.
- **Limitation:** The Bolt environment files (`.env`, `.gitkeep`,
  `package-lock.json`, `.v3/`) are present in the working directory but
  are not part of the GitHub repository and will not be committed.

## 9. Remaining work

- **Phase 1:** Minimal CLI with `argparse`, input validation for
  targets/subnets/port ranges/scan modes/report format, and the explicit
  target allow-policy that rejects public/unauthorized addresses before
  any network probes run. Unit tests must prove rejected targets do not
  trigger network probes.
- **Phases 2–7:** TCP scanner, result model/reports, UDP probing, host
  discovery, integration/testing, and course documentation.
- **Flask UI:** Mandatory deliverable to be built after core scanning
  functionality is complete. Not part of Phase 1 scope.
- **`.gitignore` for Flask:** When the Flask UI is added, update
  `.gitignore` to exclude `instance/`, Flask session files, and any
  Flask-specific artifacts.

## 10. User review and approval

- User approval: **Pending**
- This report and the `DEV.md` / `.gitignore` changes are presented for
  the user's review. No commit will be made until the user explicitly
  approves Phase 0.

## 11. Git workflow and commit evidence

- **Not committed.** Awaiting user approval.
- After approval, the following files will be staged:
  - `phase0.md`
  - `DEV.md`
  - `.gitignore`
- Commit message (proposed): `docs: Phase 0 — repository reconnaissance and project contract`
- No push to GitHub will occur without explicit user authorization.

## 12. Revision notes and viva questions

### Key concepts

- **Repository reconnaissance:** Inspecting Git state before coding to
  understand what exists, what has changed, and what must be preserved.
- **Gitignore as a safety control:** Preventing secrets and generated
  artifacts from entering version control.
- **Authorized scope:** Defining which targets may be scanned before any
  network code is written.

### Likely viva questions

**Q: Why inspect the repository before writing code?**
A: To avoid overwriting existing work, to understand the project's
history and structure, and to confirm the environment (Python version,
Git state) is suitable before making changes.

**Q: What did the commit history reveal?**
A: Four commits: an initial `.gitignore`, a README, and two commits that
finalized the `.gitignore` and added the full `DEV.md` specification.

**Q: Why is `.gitignore` important in a security tooling project?**
A: A scanning tool may generate reports containing network data, and the
development environment may contain credentials. `.gitignore` prevents
these from being accidentally committed to version control.

**Q: What Python version was verified?**
A: Python 3.13.5, which exceeds the 3.10+ requirement.

**Q: What is the authorized testing scope?**
A: Loopback (`127.0.0.1`) and private lab machines or networks the user
owns or is explicitly authorized to test. Public targets are rejected.
