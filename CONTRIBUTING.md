# Contributing to basic-ipfs

Thanks for your interest! This project keeps a *very* tight scope on purpose:
five operations, plus lifecycle management. PRs that grow the API beyond that
will likely be redirected to a downstream library.

## Setup

```bash
git clone https://github.com/lukeprofits/basic_ipfs
cd basic_ipfs
python -m venv .venv
source .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Running tests

```bash
# Fast, no daemon, no network — runs in ~1s.
pytest tests/test_unit.py tests/test_download.py

# End-to-end with a real Kubo daemon. First run downloads ~115 MB.
pytest tests/test_basic.py

# Concurrency stress (~10s).
pytest tests/test_concurrency.py

# Full suite minus the gated two-node test.
pytest --ignore=tests/test_two_node.py

# Two-node integration (slow, network-flaky).
IPFS_E2E=1 pytest tests/test_two_node.py
```

## Bumping the Kubo version

```bash
# 1. Refresh the SHA-512 table from dist.ipfs.tech for every supported
#    platform. Verify the diff before committing.
python scripts/refresh_checksums.py v0.41.0

# 2. Bump KUBO_VERSION in basic_ipfs/__init__.py.

# 3. Run the full suite locally to confirm the new binary works.
pytest

# 4. Update CHANGELOG.md, commit, tag, push.
```

The CI matrix automatically tests on Linux/macOS/Windows with cached
downloads — but local validation catches things before they hit CI.

## Style

- No new public APIs without discussion. Open an issue first.
- No new dependencies without a clear, narrow justification. Today's
  runtime deps are `requests` + `platformdirs`. That should be the ceiling.
- Comments explain **why**, not what. Code says what.
- Errors must say what the user should do next. "X failed" is not enough.
- Match the existing exception hierarchy (`IPFSError` and friends) for any
  new failure modes.
- Add a unit test (`tests/test_unit.py`) for any new helper, and an
  end-to-end test (`tests/test_basic.py`) for any new public behavior.

## Releasing

Maintainers only.

```bash
# Bump version in pyproject.toml AND basic_ipfs/__init__.py.
git tag v0.X.Y
git push --tags
# The release workflow takes it from here.
```

PyPI publishing uses **trusted-publisher OIDC** — no API token in repo
secrets. Configure once at:
<https://pypi.org/manage/project/basic-ipfs/settings/publishing/>
