# basic-ipfs

An intentionally tiny IPFS library for Python. Zero setup, real Kubo node under the hood.

### Description

`basic-ipfs` does exactly five things:

- Add a file or bytes to [IPFS](https://ipfs.tech/) and pin it (returns a [CID](https://docs.ipfs.tech/concepts/content-addressing/))
- Announce a file or bytes to IPFS without pinning (returns a CID — content may be GC'd)
- Get content back by CID (as bytes, or written to disk)
- Pin one CID or a list of CIDs (so they never get garbage-collected)
- Unpin one CID or a list of CIDs (idempotent — safe to re-run)

It also runs and manages a real [Kubo](https://github.com/ipfs/kubo) node for you — auto-downloaded on first use, auto-shutdown on exit. No daemon to install, no config files to edit, no accounts. (See [Privacy](#privacy) below — the default daemon does join the public IPFS network.)

I made `basic-ipfs` because no other Python packages make it this simple. Every existing client assumes you already have an IPFS daemon running. This one just works.

If it does exactly what you need → great, use it. If it doesn't → don't use it. Simple as that.

### Install

```
pip install basic-ipfs
```

First call downloads the Kubo binary (~115 MB, SHA-512 verified) into the package directory and starts it as a background subprocess. The daemon stops automatically when your program exits.

### Usage

```python
import basic_ipfs

# Add — pins content permanently so it's never garbage-collected
cid = basic_ipfs.add("photo.jpg")
cid = basic_ipfs.add(b"hello world")

# Pass provide=False to skip the public-DHT announce (content stays
# locally addressable, but its presence is not broadcast)
cid = basic_ipfs.add(b"private data", provide=False)

# Announce — adds to IPFS without pinning; content may be GC'd later
cid = basic_ipfs.announce("photo.jpg")
cid = basic_ipfs.announce(b"temporary data")

# Get — returns bytes, or writes to disk if you pass an output path
data = basic_ipfs.get(cid)
basic_ipfs.get(cid, "copy.jpg")

# Pin — one CID, or a whole list (one HTTP round-trip per ~500 CIDs)
basic_ipfs.pin(cid)
basic_ipfs.pin([cid1, cid2, cid3, ...])

# Unpin — same shape, always idempotent
basic_ipfs.unpin(cid)
basic_ipfs.unpin([cid1, cid2, cid3, ...])

# List all pinned CIDs
cids = basic_ipfs.get_all_pins()   # → ['Qm...', 'baf...', ...]

# Debug info
basic_ipfs.status()   # {peer_id, agent_version, repo_size_bytes, pinned_cids, ...}
```

That's the core API. There are also helpers for networking, private
networks, identity rotation, and lockdown — see [Privacy](#privacy).

Explicit lifecycle, if you want it (you usually don't — the daemon starts lazily on the first call and stops on process exit):

```python
basic_ipfs.start()
basic_ipfs.stop()

with basic_ipfs.node():
    basic_ipfs.add(b"hi")
```

All failures raise `basic_ipfs.IPFSError`. Subclasses, all with actionable messages:

- `IPFSBinaryNotFound` — Kubo missing and auto-download failed (no network, disk full, unsupported platform).
- `IPFSDaemonTimeout` — daemon didn't reach a healthy state in 60 s.
- `IPFSOperationError` — an `/api/v0/...` call returned an error.
- `IPFSPortInUse` — `API_PORT` (default 5001) is bound by something that isn't ours. Set `basic_ipfs.API_PORT` to something free.
- `IPFSRepoLocked` — another Kubo daemon already owns the repo. One process per repo.
- `IPFSRepoCorrupt` — repo on disk failed a sanity check. Investigate; don't auto-delete.

### CLI

Installing the package also adds a `basic-ipfs` command:

```
basic-ipfs status
basic-ipfs add photo.jpg                 # prints the CID, pins content
basic-ipfs announce photo.jpg            # prints the CID, no pin (may be GC'd)
basic-ipfs add-folder ./mydir            # recursive add + pin
basic-ipfs get <cid> [output-path]       # stdout or file
basic-ipfs pin <cid> [<cid> ...]
basic-ipfs unpin <cid> [<cid> ...]
basic-ipfs is-pinned <cid>               # exit 0 if pinned, 1 if not
basic-ipfs exists <cid>                  # exit 0 if locally available
basic-ipfs pins                          # list all pinned CIDs
basic-ipfs gc                            # run garbage collection

# Networking
basic-ipfs peers                         # list connected peers
basic-ipfs my-addr                       # this node's shareable multiaddrs
basic-ipfs connect <multiaddr>           # dial a peer

# Privacy
basic-ipfs create-private-network        # generate swarm key (run before first op)
basic-ipfs join-private-network <key>    # join an existing private network
basic-ipfs network-key                   # print this node's swarm key
basic-ipfs rotate-identity               # new peer ID; daemon must be stopped
basic-ipfs lockdown                      # disable DHT, bootstrap, gateway fetch
```

### Config

Override module variables **before** the first call if you want non-defaults:

```python
import basic_ipfs

basic_ipfs.APP_NAME = "MyApp"              # changes default repo location
basic_ipfs.REPO_PATH = "/mnt/data/ipfs"    # or pin an exact path
basic_ipfs.KUBO_VERSION = "v0.40.1"        # must be in kubo_checksums.py
basic_ipfs.API_PORT = 5099                 # if 5001 is taken
basic_ipfs.GATEWAY_PORT = 8099             # if 8080 is taken (or running 2 nodes)
basic_ipfs.SWARM_ADDRESSES = ["/ip4/127.0.0.1/tcp/4001"]  # loopback-only swarm
basic_ipfs.STORAGE_MAX = "100GB"           # repo size cap ("" = unlimited)
```

Default repo location is `~/.local/share/basic_ipfs/ipfs_repo` (`platformdirs` picks the right path per OS).

### Two-node example

Anything you `add()` on one machine can be `get()`-ed on another that knows
your peer address. Smallest possible demo:

```python
# Node A
import basic_ipfs
basic_ipfs.start()
ipv4, _ = basic_ipfs.my_node_multiaddress()
print("share this with node B:", ipv4)
cid = basic_ipfs.add(b"hello from A")
print("share this CID:", cid)
input("press enter to stop…")
```

```python
# Node B
import basic_ipfs
basic_ipfs.start()
basic_ipfs.connect_to_node("<ipv4 from node A>")
print(basic_ipfs.get("<cid from node A>"))   # → b"hello from A"
```

For an isolated network where only your nodes can see each other, use
`create_private_network()` on the first node and `join_private_network(key)`
on the rest, both *before* `start()`. See [Privacy](#privacy) below.

### Troubleshooting

**`IPFSPortInUse` on startup.** Something else is on port 5001 (often another
IPFS daemon you forgot about, or some unrelated dev service). Either stop it,
or pick a different port *before* the first call:

```python
import basic_ipfs
basic_ipfs.API_PORT = 5099
```

**`IPFSRepoLocked` on startup.** Another `basic-ipfs`-using process owns the
repo. Run only one process per repo — or set `basic_ipfs.REPO_PATH` to a
different path before starting.

**Auto-download fails (corporate proxy / firewall).** The downloader honors
the standard environment variables:

```bash
HTTPS_PROXY=http://corp-proxy:3128 \
REQUESTS_CA_BUNDLE=/etc/ssl/corp-ca.pem \
python your_script.py
```

If outbound access to `dist.ipfs.tech` is blocked, pre-place the binary at
`<site-packages>/basic_ipfs/bin/<platform>/ipfs` (or `ipfs.exe` on Windows)
and `basic-ipfs` will skip the download entirely. Supported platform
strings: `linux-amd64`, `linux-arm64`, `linux-riscv64`, `darwin-amd64`,
`darwin-arm64`, `windows-amd64`.

**Alpine / musl Linux.** Kubo upstream ships glibc binaries only.
`apk add gcompat` may be enough; otherwise place a musl-compatible
`ipfs` binary at the path above.

**32-bit ARM (Raspberry Pi 3 and older).** Kubo no longer publishes 32-bit
ARM builds. Run a 64-bit OS (e.g. Raspberry Pi OS 64-bit) on Pi 4/5.

**Slow first run.** Auto-download is ~115 MB. Subsequent starts are fast
(daemon comes up in ~1–3 s). The binary lives inside the package directory
so a `pip uninstall` cleans it up.

**Want to inspect the daemon log.** It's at
`<repo>/basic_ipfs_daemon.log` (rotated at 5 MB, one `.old` kept).

### Security

Auto-download is verified against an SHA-512 hash baked into the wheel
(`basic_ipfs/kubo_checksums.py`) using a constant-time compare. Versions
not in the table are refused — fetching a digest from the same origin as
the archive adds no real protection, so the install is fail-closed. The
download also pins its redirect target to `*.ipfs.tech`. See
[`SECURITY.md`](SECURITY.md) for the full threat model and how to verify
manually.

### Privacy

**By default, the daemon joins the public IPFS network.** That has real
consequences you should understand before publishing anything sensitive:

- **CIDs are advertised.** `add()` announces the content's CID to the
  public DHT. Anyone monitoring the DHT (and crawlers do) can record that
  your node holds that CID. Pass `provide=False` to skip the announce —
  the content is still addressable, but its presence is not broadcast.
- **`get()` is observable.** Fetching an unknown CID dials peers and may
  fall back to public gateways operated by third parties (Protocol Labs,
  Cloudflare). Those parties learn what you asked for.
- **Peer ID is persistent.** The repo is created once and reused, so all
  your IPFS activity over time is linkable to one stable peer ID.
- **Bootstrap nodes are third parties.** The daemon dials Kubo's stock
  bootstrap list on startup (Protocol Labs / Cloudflare hosts).
- **Swarm port is exposed.** Kubo listens on `0.0.0.0:4001` for inbound
  peers; on a multi-tenant or hostile LAN, treat that port like any other
  public service.

For non-public data, you have three escape hatches — pick what fits:

```python
import basic_ipfs

# 1. Per-call: skip the DHT announce on a single add()
cid = basic_ipfs.add(b"private", provide=False)

# 2. Private network: only peers with the same 256-bit swarm key can
#    connect. Run BEFORE start() / the first IPFS operation.
key = basic_ipfs.create_private_network()
# share key + multiaddr with peers via a trusted channel

# 3. Lockdown: disable the public DHT, bootstrap dialing, gateway
#    fetch, and pin the swarm listener to loopback. Right starting
#    point for encrypted-content stores or air-gapped pipelines.
basic_ipfs.lockdown_mode()

# Bonus: rotate the libp2p keypair to sever peer-ID linkability with
# prior runs (daemon must be stopped first; pins are preserved).
new_peer_id = basic_ipfs.rotate_identity()
```

A private network refuses connections from any peer without the matching
swarm key, so the DHT/bootstrap concerns above do not apply. See
[`SECURITY.md`](SECURITY.md) for the full threat model.

### How it works

`basic-ipfs` bundles the reference IPFS implementation — [Kubo](https://github.com/ipfs/kubo), the Go daemon maintained by Protocol Labs — and runs it as a subprocess. Your Python calls are translated into HTTP requests to Kubo's local `/api/v0` endpoint.

- **Auto-download:** the Kubo binary fetches from `dist.ipfs.tech` on first use, checksum-verified, and cached. The Python wheel itself stays tiny (~28 KB, `py3-none-any`) because it ships no binaries.
- **Content is immutable:** a CID is a hash of the content. The same bytes always produce the same CID, anywhere in the world.
- **Pinning is persistence:** Kubo garbage-collects unpinned content. `pin()` marks content permanent. `unpin()` undoes that.
- **PyInstaller / Briefcase friendly:** respects `sys._MEIPASS`, so bundled apps find the binary correctly.

### Contributing

If you want to add functionality, open a PR. I'll merge it if it keeps the library simple and matches the existing patterns.

### License

MIT. See [LICENSE](LICENSE).
