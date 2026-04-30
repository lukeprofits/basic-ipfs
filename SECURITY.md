# Security

Found a vulnerability? Open a private security advisory on GitHub via the
**Security** tab (or
<https://github.com/lukeprofits/basic-ipfs/security/advisories/new>). Don't
open a public issue.

Only the latest released `0.2.x` gets fixes. Upgrade if you're on `0.1.x`.

## What `basic-ipfs` actually verifies

When `basic-ipfs` auto-downloads a Kubo binary on first use, it:

1. Computes the SHA-512 of the downloaded archive.
2. Compares it (constant-time, `hmac.compare_digest`) against the hash
   baked into the wheel at `basic_ipfs/kubo_checksums.py`. The hash was
   committed and reviewed when the version was added to the table; it
   ships inside the wheel under PyPI's release infrastructure.
3. Refuses to install if the version is not in the table. A previous
   release would have fallen back to fetching `dist.ipfs.tech/.../.sha512`
   over TLS, but that adds no security against an origin compromise — an
   attacker controlling `dist.ipfs.tech` swaps both files together. New
   Kubo versions must have their hash committed before they can be
   installed.

The verification is **fail-closed** in both directions: a mismatch refuses
to install, and a missing baked hash refuses to install.

## What it does *not* verify

- It does not verify a Sigstore signature for Kubo releases. (Kubo upstream
  does not yet publish reproducible Sigstore attestations for every release.)
- It does not pin the TLS certificate of `dist.ipfs.tech`.
- It does not encrypt or sign content you publish to IPFS — addressing is
  hash-based, not authenticated. Use the **private network** features
  (`create_private_network` / `join_private_network`) if you need isolation.

## Privacy model

`basic-ipfs` runs an unmodified Kubo daemon. **Default-mode usage joins the
public IPFS network** with all the privacy properties — and limitations —
that implies. Read this section before publishing sensitive data.

What the default daemon does:

- **Joins the public DHT.** `Routing.Type` defaults to Kubo's standard
  setting (DHT participant). The node will answer DHT queries from
  arbitrary peers and record provider records for any CIDs it holds.
- **Dials Protocol Labs / Cloudflare bootstrap nodes** at startup, using
  Kubo's stock `Bootstrap` list. They learn your IP and peer ID.
- **Listens on `0.0.0.0:4001`** for inbound TCP/QUIC peers (the API on
  port 5001 is restricted to `127.0.0.1`; the swarm port is not).
- **Announces every CID you `add()`.** The HTTP `/api/v0/add` call uses
  Kubo's default `provide=true`. The CID is published to the DHT so other
  peers can find your node as a provider.
- **Fetches via gossip + DHT + gateway fallback.** A `get(cid)` for
  content not local will broadcast a want for that CID, which is
  observable by every peer you talk to and may fall back to public HTTP
  gateways operated by third parties.
- **Persists peer ID.** The repo (and therefore the keypair generating
  your peer ID) is created once and reused. All operations over the
  lifetime of the install are linkable to one stable identity.

What you can do about it:

- Pass `provide=False` to `add()` / `announce()` to skip the DHT
  announce. The content is still addressable by CID — peers who already
  know the CID can still fetch it via bitswap — but no provider record is
  published.
- For non-public data, use a **private network**:
  ```python
  key = basic_ipfs.create_private_network()  # before the first IPFS call
  ```
  The daemon will refuse connections from any peer without the matching
  256-bit swarm key, isolating your group from the public network.
- Set `basic_ipfs.REPO_PATH` to a directory with mode `0o700` if other
  local users should not be able to read your pins, peer ID, or
  daemon log (which contains every CID accessed).
- For air-gapped or fully-offline use, configure Kubo directly via
  `ipfs config Routing.Type none`, `ipfs config Bootstrap '[]'`, and
  `ipfs config Addresses.Swarm '["/ip4/127.0.0.1/tcp/4001"]'` after
  `create_private_network()`.

What `basic-ipfs` does **not** provide:

- Anonymity. Your IP and peer ID are visible to every peer you connect
  to. There is no Tor or mixnet integration.
- Content encryption. CIDs are content hashes, not encrypted blobs. If
  you need confidentiality, encrypt before `add()`.
- Forward-secret identities. `rotate_identity()` issues a new peer ID
  and preserves the old key in the keystore so you can re-sign IPNS
  records, but it does **not** retroactively unlink past activity:
  - Provider records published to the public DHT under the old peer ID
    remain queryable until they expire (Kubo TTL is ~24 h, sometimes
    longer in practice).
  - Connected peers and bootstrap nodes have already observed your IP
    paired with the old peer ID — rotation does not redact their logs.
  - Pinned CIDs themselves are unchanged, so any party that previously
    linked your old peer ID to a content set can still match the new
    peer ID by re-querying the same CIDs.
  Rotation severs *future* linkability; treat the previous peer ID as
  permanently outed for everything you did under it.

## Manual verification

```bash
# Inspect the binary's provenance:
cat <site-packages>/basic_ipfs/bin/<platform>/.provenance.json

# Re-verify against the dist channel:
cd <site-packages>/basic_ipfs/bin/<platform>
sha512sum ipfs   # or shasum -a 512 ipfs on macOS
curl -sf https://dist.ipfs.tech/kubo/<version>/kubo_<version>_<platform>.tar.gz.sha512
```

Both digests are over the **archive**, not the extracted binary, so to fully
re-verify you must re-download the archive.

## Hardening recommendations

- Set `basic_ipfs.REPO_PATH` to a directory whose mode is `0o700` if other
  local users should not read your pins or swarm key.
- Verify any swarm key shared between machines was transferred over a
  channel you trust (signed messaging, in-person, etc.). It's a 256-bit
  symmetric secret that controls network membership.
- For air-gapped environments, pre-place the verified Kubo binary at
  `<site-packages>/basic_ipfs/bin/<platform>/ipfs` before the first call.
  `basic-ipfs` will use it without contacting the network.
