# Changelog

All notable changes to `basic-ipfs` are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project follows
[Semantic Versioning](https://semver.org/).

## [0.2.1] — 2026-04-29

This release closes a set of privacy and supply-chain gaps surfaced by an
external security review. All public-API changes are backward compatible.

### Added
- `provide` keyword on `add()` / `announce()` (defaults to `True`). Set
  `provide=False` to skip the DHT announce — content remains addressable
  by CID but its presence on this node is not advertised. Useful for
  staging private data before deciding whether to publish.
- `rotate_identity()` (also `basic-ipfs rotate-identity`) — generates a
  new libp2p keypair, severing peer-ID linkability with prior runs. Pins
  and config are preserved; the old key is archived in the keystore.
  Daemon must be stopped.
- `lockdown_mode()` (also `basic-ipfs lockdown`) — one-shot helper that
  disables DHT (`Routing.Type=none`), bootstrap dialing
  (`Bootstrap=[]`), gateway fetch (`Gateway.NoFetch=true`), and pins
  `Addresses.Swarm` to loopback. The right starting point for
  encrypted-content stores, local caches, and air-gapped pipelines.
- `GATEWAY_HOST` / `GATEWAY_PORT` config vars (default
  `127.0.0.1:8080`). Override when running multiple nodes on one host.
- `SWARM_ADDRESSES` config variable. When set, applied to
  `Addresses.Swarm` before daemon launch — e.g.
  `["/ip4/127.0.0.1/tcp/4001"]` for loopback-only on multi-tenant hosts.
- Privacy model section in `SECURITY.md` and a Privacy section in
  `README.md`. Default-mode usage joins the public IPFS network; this is
  now stated plainly with the available mitigations.
- CI: `pip-audit` job; `lint` job running `ruff` and `mypy`.
  `.github/dependabot.yml` for weekly pip + actions updates.
- Test for offsite-redirect rejection during binary download.

### Changed
- **Auto-download checksum policy is now strict.** Versions without a
  baked-in SHA-512 in `kubo_checksums.py` raise `IPFSBinaryNotFound`
  rather than fetching a digest from the same origin as the archive
  (which adds no security against an origin compromise). Pin
  `KUBO_VERSION` to a value already in the table, or commit a hash for
  the new version.
- SHA-512 comparison now uses `hmac.compare_digest` (constant-time).
- Binary download follows redirects only within `dist.ipfs.tech`. Any
  off-host redirect raises `IPFSBinaryNotFound`.
- Auto-installed Kubo binary is owner-execute only (was world-execute).
- Daemon log file is created mode `0o600` on POSIX. Repo directory is
  set to mode `0o700` on first init.
- Daemon no longer launches with `--enable-pubsub-experiment` /
  `--enable-namesys-pubsub`. The public API does not use pubsub.
- Archive extraction enforces a per-member size cap (512 MB) and a path
  depth cap (4) — defense-in-depth against malicious archives.
- README no longer claims "no public gateway, no third-party services."
  The default daemon dials Protocol Labs / Cloudflare bootstrap nodes
  and may fall back to public gateways for unknown CIDs.

### Removed
- Network-fetched `.sha512` fallback path. See note above; verification
  is now baked-in only.

### Security
- Constant-time digest comparison.
- Origin-pinned redirects.
- Strict checksum policy.
- Tighter file modes on the binary, the log, and the repo directory.

## [0.2.0] — 2026-04-25

This is the production-readiness release. The public API is unchanged in name
and signature, but several internals were rewritten and a few semantics were
tightened. See **Behavior changes** below if you depend on those.

### Added
- **Baked-in SHA-512 table** for all supported Kubo versions
  (`basic_ipfs/kubo_checksums.py`). Verifies the auto-downloaded binary
  against a hash that ships inside the wheel — closes the gap where an
  attacker controlling `dist.ipfs.tech` could swap both the archive and its
  `.sha512` companion. Falls back to network-fetched checksum (with an INFO
  log) for versions not in the table.
- New exception classes: `IPFSPortInUse`, `IPFSRepoLocked`, `IPFSRepoCorrupt`.
  Raised with actionable messages instead of opaque startup errors.
- `StatusDict` (TypedDict) export — typed return value for `status()`.
- `Node` class — proper PEP-8 name for the context manager.
  `node = Node` alias preserved.
- `linux-riscv64` to the supported platform list.
- Disk-space preflight (~300 MB) before auto-download.
- Atomic install: download → verify SHA-512 → extract to `.partial` →
  `os.replace` into place. No half-written binary on interruption.
- Provenance file (`bin/<platform>/.provenance.json`) recording version,
  source URL, SHA-512, and how it was verified.
- `py.typed` marker — type checkers now see precise hints from this package.
- `@typing.overload` on `get()` — `get(cid)` returns `bytes`, `get(cid, path)`
  returns `None`.
- Daemon log rotation: stderr goes to `<repo>/basic_ipfs_daemon.log`,
  rotated at 5 MB.
- Helpful errors for unsupported platforms, 32-bit ARM, and Alpine/musl —
  each names exactly what to do next.
- `scripts/refresh_checksums.py` — bumps the checksum table for a new
  Kubo version.
- `scripts/bench.py` — micro-benchmark for tracking add/get throughput.
- New test files: `tests/test_unit.py` (no daemon), `tests/test_download.py`
  (mocked HTTP), `tests/test_concurrency.py` (32-thread stress),
  `tests/test_two_node.py` (gated on `IPFS_E2E=1`).
- GitHub Actions: matrix CI, OIDC trusted-publisher release, weekly
  regression cron.

### Changed
- **`is_pinned()` and `get_all_pins()` are now consistent.** Both report only
  *recursive* pins. A child of a pinned folder is no longer reported as
  "pinned" — it's only locally available, which `exists()` already covers.
  This was the inconsistency where `is_pinned(child)` could return `True`
  while `child` did not appear in `get_all_pins()`.
- The Kubo daemon's `stdout`/`stderr` are no longer captured via
  `subprocess.PIPE` — that produced a deadlock when the OS pipe buffer
  filled (~64 KB). `stdout` → DEVNULL, `stderr` → rotating file.
- HTTP downloader uses a session with retries (`total=3`,
  `backoff_factor=2`, retry on 502/503/504/520/522/524).
- `IPFSManager` is now a plain class; the previous custom `__new__`-based
  singleton was removed. Lifecycle is governed by a module-level lock.
- `stop()` is thread-safe.
- `swarm.key` is written with mode `0o600` on POSIX. A warning is logged
  if an existing key is group/world-readable.
- `add()` / `announce()` accept any `os.PathLike`, not just `str` and `Path`.
- Internal helper renamed: `_to_cid_list` → `_as_str_list` (and used for
  multiaddrs too, with corrected `TypeError` messages).
- `connect_to_nodes()` now batches through the manager directly instead of
  iterating in Python.
- `add_folder()` now uses the HTTP `/api/v0/add` multipart endpoint
  directly instead of fork-execing the `ipfs` CLI. No subprocess overhead
  per call. CID parity with the old fork-exec path is verified in tests.
- Pure type-only re-exports (`Any`, `Iterable`, `Union`) are stripped from
  the module namespace so `basic_ipfs.<TAB>` only surfaces real public API.
- README cleanup: documented `basic_ipfs.pins()` was an out-of-date name;
  the canonical Python API is `get_all_pins()`. README now matches the
  module. (The CLI subcommand `basic-ipfs pins` is unchanged — short forms
  are conventional in CLIs.)
- Source distributions now include `CHANGELOG.md`, `SECURITY.md`, and
  `CONTRIBUTING.md` (via `MANIFEST.in`) for downstream packagers building
  from source.

### Fixed (release infra)
- Release workflow's `SOURCE_DATE_EPOCH` was set from
  `github.event.head_commit.timestamp` (an ISO-8601 string). Setuptools
  needs Unix epoch seconds — it now resolves the value via
  `git log -1 --pretty=%ct` after a full `fetch-depth: 0` checkout.

### Fixed
- `exists(cid)` (backed by `block_exists` → `block/stat`) now passes
  `offline=true` to Kubo. Previously, calling `exists()` for a CID that
  wasn't local could block the API for the full timeout while Kubo tried
  to fetch the block from peers — contradicting the documented "available
  in the local node" semantics.
- Long-running daemon could hang on its next `stderr` write once the
  unbuffered Python `subprocess.PIPE` filled.
- `IPFSManager` could leak a half-initialised state if two threads raced
  through `start()`.
- Under-pressure: a flaky download-progress log line could fire several
  times per 10% boundary.
- `_addr_score` no longer raises on malformed multiaddrs (now returns -1).
- Failed extraction during install used to leave a partial file at the
  destination path; the new atomic-rename design prevents this.

### Removed
- The `IPFSManager._instance` / `_lock` class-level singleton machinery.
  External code that constructed `IPFSManager()` and relied on getting the
  same object back across calls should switch to `basic_ipfs.start()` /
  `basic_ipfs._get_manager()` (the latter is intentionally underscore-private,
  but stable).

### Behavior changes that may affect you
- `is_pinned(cid)` for a CID that's only an *indirect* pin (a descendant of a
  recursive pin) now returns `False`. If you need the old "is it pinned in
  any sense" answer, combine `is_pinned(cid) or exists(cid)`.

## [0.1.0] — 2026-04-19
- Initial release.
