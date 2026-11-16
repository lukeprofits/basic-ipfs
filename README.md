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

First call downloads the Kubo binary (~115 MB, SHA-512 verified) into your per-user data directory (`~/.local/share/basic_ipfs/bin/<platform>/ipfs` on Linux; `platformdirs` picks the right path per OS) and starts it as a background subprocess. The daemon stops automatically when your program exits.

### Usage

```python
import basic_ipfs

# Add — pins content permanently so it's never garbage-collected
cid = basic_ipfs.add("photo.jpg")
cid = basic_ipfs.add(b"hello world")

# provide=False skips the immediate announce. Kubo's default strategy
# still announces every block it holds on its daily round: to keep
# something out of the DHT, see "What your node tells the world it has".
cid = basic_ipfs.add(b"private data", provide=False)

# Announce — adds to IPFS without pinning; content may be GC'd later
cid = basic_ipfs.announce("photo.jpg")
cid = basic_ipfs.announce(b"temporary data")

# Just compute the CID locally — does NOT store, pin, or announce anything.
# Useful for previewing the CID of content you have not yet decided to publish.
cid = basic_ipfs.compute_cid_locally(b"hello world")
cid = basic_ipfs.compute_cid_locally("photo.jpg")

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
basic-ipfs add-folder ./mydir            # recursive add + pin (skips dotfiles; --hidden includes them)
basic-ipfs compute-cid photo.jpg         # prints the CID, stores nothing, announces nothing
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

### A node of your own

The module-level functions share one daemon. A program that wants its own --
or several on one machine -- makes a manager and gives it its own repo and
ports:

```python
import basic_ipfs

node = basic_ipfs.IPFSManager(
    port=5611,             # API
    repo="/var/lib/myapp/ipfs",
    gateway_port=8611,
    swarm_port=4611,       # the port other nodes reach it on
)
node.start()
cid = node.add(b"hello")
print(node.peer_id())
node.stop()                # yours to stop: only the shared daemon stops itself at exit
```

Anything left out follows the module settings above.

### Streams: one program talking to another

Two programs on two machines can talk through their IPFS daemons: an
encrypted pipe that reaches nodes behind home routers the way IPFS does.
Start the daemon with `streams=True`; one side listens, the other forwards.

```python
# Machine A -- your program listens on local port 9001
a = basic_ipfs.IPFSManager(streams=True)
a.start()
a.stream_listen("chat", 9001)        # "chat" streams from peers arrive on 127.0.0.1:9001
print(a.peer_id())                   # give this to B
```

```python
# Machine B -- connect to 127.0.0.1:9002 and you are talking to the program on A
b = basic_ipfs.IPFSManager(streams=True)
b.start()
b.stream_forward("chat", 9002, "<peer ID of A>")
```

`stream_close("chat")` closes the listeners and forwards of that name,
`stream_close("chat", port=9002)` only the forward on that local port, and
`stream_close()` closes them all.

Two things to know. The listening side is **not told which peer connected**:
if your program cares who it is talking to, it must check that itself, with
signatures. The forwarding side does know, because it reaches the peer it
named or nobody. And this is a Kubo feature still marked experimental
(`Libp2pStreamMounting`), which is why it is off unless you ask.

### Topics: many programs hearing each other

A topic is a name. Any node may publish to it, and every node listening on it
hears what is published. Start the daemon with `topics=True`.

```python
node = basic_ipfs.IPFSManager(topics=True)
node.start()

def heard(data, sender):          # bytes, and the peer ID that published them
    print(sender, data)

stop = node.topic_listen("weather", heard)
node.topic_publish("weather", b"rain")
stop()
```

Three things to know. A message reaches the listeners your node is connected
to, directly or through other listeners, so two nodes that have never met
need to connect first (`swarm_connect`). Nothing is stored: a node that
starts listening later has missed it. And this is Kubo's experimental pubsub
(`Pubsub.Enabled`), which Kubo's maintainers describe as tuned for IPNS and
may change, which is why it is off unless you ask.

### Adding a file in place

An ordinary `add` copies the file into the node's repository. For a large
file that is already where you want it -- on another drive, say -- the node
can leave it there and serve it from where it is. Start the daemon with
`in_place=True`.

```python
node = basic_ipfs.IPFSManager(repo="/home/me/node/ipfs", in_place=True)
node.start()
cid = node.add("/home/me/node/films/big.mkv", in_place=True)
```

Five things to know. The file must be in the folder that holds the
repository (`/home/me/node` above) or below it; a link there to a folder on
another drive counts, so `ln -s /mnt/big /home/me/node/big` and then
`node.add("/home/me/node/big/film.mkv", in_place=True)` works. The file must
stay as it is: moved, changed or on an unplugged drive, reads of it fail
until it is back, and the node carries on. Unpinning never deletes the file;
that is yours to do. (`node.cat(cid, local_only=True)` reads only what this
node has and never fetches from another node, so it tells you whether the
file is still there: if it is not, the read fails or comes back short.)
Bytes the repository already holds are not taken from the file, which would
then be a copy nobody reads; `node.discard(cid)` deletes the repository's
copy first. And this is Kubo's experimental filestore
(`Experimental.FilestoreEnabled`), which is why it is off unless you ask.

### Blocks one at a time

For a program that builds its own DAG nodes: `block_put(data, codec="dag-pb")`
stores one block and returns its CID; `block_get(cid)` reads one back (from
the network if this node lacks it, unless `local_only=True`). A block is not
pinned by being put: `pin_add(cid, recursive=False)` keeps that block alone
and nothing it links to, and `pin_rm(cid, recursive=False)` lets it go.
`provide(cid)` tells the DHT this node has it, and
`find_providers(cid, limit=20)` asks the DHT which peers say they have it
(peer IDs, this node's own included if it announced it).

### What your node tells the world it has

Kubo announces to the DHT **every block it has**, again every day: that is its
`Provide.Strategy` of `"all"`, and `add(..., provide=False)` does not change
it. Anyone can then look up a CID and find your node. For a program whose
node holds things it must not be seen to hold, start the daemon with
`provide_strategy="mfs"`: then only what is in the node's MFS is announced,
and `mfs_add(cid, "/shown/<cid>")` / `mfs_remove(path)` are how you choose.
`"mfs"` announces every block under what is listed; `"mfs+entities"` only
the root of each file, one record per file however large.

```python
node = basic_ipfs.IPFSManager(provide_strategy="mfs")
node.start()
cid = node.add(b"for everyone")
node.mfs_add(cid, f"/shown/{cid}")    # announced, and kept from GC
node.mfs_remove(f"/shown/{cid}")      # no longer announced
```

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
`<user_data_dir>/basic_ipfs/bin/<platform>/ipfs` (or `ipfs.exe` on Windows)
and `basic-ipfs` will skip the download entirely. The bundled
`<site-packages>/basic_ipfs/bin/<platform>/ipfs` path is also honoured
for PyInstaller / Briefcase deploys. Supported platform strings:
`linux-amd64`, `linux-arm64`, `linux-riscv64`, `darwin-amd64`,
`darwin-arm64`, `windows-amd64`.

**Alpine / musl Linux.** Kubo upstream ships glibc binaries only.
`apk add gcompat` may be enough; otherwise place a musl-compatible
`ipfs` binary at the path above.

**32-bit ARM (Raspberry Pi 3 and older).** Kubo no longer publishes 32-bit
ARM builds. Run a 64-bit OS (e.g. Raspberry Pi OS 64-bit) on Pi 4/5.

**Slow first run.** Auto-download is ~115 MB. Subsequent starts are fast
(daemon comes up in ~1–3 s). The binary lives in `platformdirs.user_data_dir("basic_ipfs")`
so it survives reinstalls. To wipe it, delete that directory.

**Want to inspect the daemon log.** It's at
`<repo>/basic_ipfs_daemon.log` (rotated at 5 MB, one `.old` kept).

### Security

Auto-download is verified against an SHA-512 hash baked into the wheel
(`basic_ipfs/kubo_checksums.py`) using a constant-time compare. Versions
not in the table are refused — fetching a digest from the same origin as
the archive adds no real protection, so the install is fail-closed. The
download also pins its redirect target to `dist.ipfs.tech` (and its
subdomains) at every hop in the chain — not just the final URL — and
requires HTTPS on every hop.

Two trust assumptions worth knowing before deploying on a shared host:

- **The local Kubo HTTP API on `127.0.0.1:5001` is unauthenticated.**
  Any process running as the same user can drive the full Kubo API,
  including `key/*` and `config`. Single-user dev boxes are fine;
  multi-tenant hosts need additional hardening (`API.Authorizations`).
- **`connect_to_node(multiaddr)` forwards its argument verbatim.** If
  your code feeds untrusted input into it, the daemon becomes an SSRF
  probe.

See [`SECURITY.md`](SECURITY.md) for the full threat model and how to
verify the binary manually.

### Privacy

**By default, the daemon joins the public IPFS network.** That has real
consequences you should understand before publishing anything sensitive:

- **CIDs are advertised.** `add()` announces the content's CID to the
  public DHT. Anyone monitoring the DHT (and crawlers do) can record that
  your node holds that CID. `provide=False` skips only the immediate
  announce: Kubo's default `Provide.Strategy` (`"all"`) announces every
  block on its daily round regardless. Start the daemon with
  `provide_strategy="mfs"` to announce only what you list.
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
