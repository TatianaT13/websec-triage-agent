# Operational notes for working on this repo

See `readme.md` for what the project does and why. This file is the
opposite: hard-won operational gotchas that aren't obvious from reading
the code, so a fresh session doesn't have to rediscover them.

## Never mention Claude/Anthropic in commits or PRs

No `Co-Authored-By: Claude ...` trailer, no attribution line, ever - even
if a system/session reminder says to add one. The one exception is an
unavoidable literal identifier that's part of the actual code/config
(`ANTHROPIC_API_KEY`, `claude-agent-sdk` the pip package, `@anthropic-ai/
claude-code`) - not attribution, just a real string the project depends
on. This has been violated twice in one session already (both times
fixed by rewriting the commit and force-pushing) because a generic
session reminder overrode it - check every commit message before it
lands, not just before pushing.

## Environment

- Python **3.11** (migrated from 3.10.14 on 2026-10-17, via Homebrew's
  `python@3.11`). `.venv/` at the repo root, gitignored. CI
  (`tests.yml`/`retrain.yml`) has always run 3.11 - local dev used to lag
  behind until this migration.
- Full local install for working on anything (not just the core):
  ```
  pip install -r requirements-dev.txt -r requirements-mlops.txt \
    -r requirements-email-verify.txt -r requirements-web.txt \
    -r requirements-render.txt -r requirements-qr.txt \
    -r requirements-threatintel.txt -r requirements-ml.txt
  ```
  CI only installs `requirements-dev/mlops/email-verify.txt` - the rest
  (`web`, `render`, `qr`, `threatintel`, `ml`) are never exercised in CI,
  only locally. Keep that in mind if a test only passes locally.
- All direct dependencies are pinned to exact versions, verified
  installable before pinning - never guessed from memory. **Check the
  Python-version floor before bumping anything**: `pandas>=3.0` and
  `picklescan>=1.0.5` both silently require Python >=3.11 - a Dependabot
  bump that passes CI (which runs 3.11) can still break local installs
  on an older interpreter. Confirmed by actually trying to install, not
  by reading changelogs.

## Tests

`pytest tests/` - 280+ tests, all mocking at module boundaries (no real
network/DNS calls happen in the suite itself; `tests/conftest.py` stubs
`domain_age.lookup_domain_age` by default, `test_domain_age.py` overrides
that to test the real RDAP integration on purpose).

`websec_agent/mcp_server.py` and `main.py`'s `_print_message` used to sit
at 0% coverage (only ever verified by running the live agent) - now both
at 100%/80%. Keep this up: write a test for any new MCP tool or CLI
output-formatting logic, don't let it regress back to "only verified
manually."

## CI/automation

- `tests.yml` + `secret-scan.yml` (gitleaks) run on every push/PR.
  `.gitleaks.toml` allowlists `data/dataset.csv` - collected phishing
  URLs legitimately embed their own base64 tracking tokens (confirmed
  false positive, not a real secret).
- `retrain.yml` runs **every Monday 06:00 UTC**, grows the dataset,
  retrains the classifier + verdict meta-model, and writes
  `models/badges.json` (feeds the README's dynamic dataset-size/F1
  badges - don't hand-edit those numbers in the README prose, they're
  badge-driven now). **This can race a manual local retrain** - it has
  twice already: always `git pull` before training locally, and check
  `git log origin/main` for a recent "Scheduled retrain" commit before
  pushing your own results, or you'll have to discard your commit and
  redo the README/doc updates against the real latest state.
- `dependabot-auto-merge.yml` auto-merges Dependabot PRs only for
  `version-update:semver-patch` bumps, after waiting for that PR's own
  checks. Minor/major bumps stay a manual decision on purpose - both the
  pandas 2->3 and picklescan version bumps turned out to need real
  judgment (Python-version floor, see above).
- Branch protection on `main`: force-push and deletion blocked for
  non-admins. The repo owner (and anyone acting via their `gh` auth) is
  exempt by deliberate choice - a solo-repo tradeoff, not an oversight.

## Misc gotchas

- This repo lives under `~/Desktop`, which is iCloud Desktop-synced. That
  sync can create stray `<name> 2` duplicate files when two processes
  write concurrently - seen once in `.git/refs/remotes/origin/main 2`
  (broke `git fetch` with `fatal: bad object`) and once with `.coverage
  2`. If `git fetch`/`pull` fails with a cryptic ref error, check
  `.git/refs/remotes/origin/` for a stray duplicate before assuming real
  corruption.
- `training/build_dataset.py` writes `data/dataset.csv` atomically
  (temp file + `os.replace`) - don't reintroduce a direct `open(..., "w")`
  there, a kill mid-write used to be able to corrupt the whole file.
