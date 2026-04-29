"""Tiny CLI: `basic-ipfs <subcommand>`."""

from __future__ import annotations

import argparse
import json
import sys

from . import (
    IPFSError,
    __version__,
    add,
    add_folder,
    announce,
    connect_to_node,
    connect_to_nodes,
    create_private_network,
    exists,
    garbage_collection,
    get,
    get_all_pins,
    get_private_network_key,
    is_pinned,
    join_private_network,
    lockdown_mode,
    my_node_multiaddress,
    peers,
    pin,
    rotate_identity,
    status,
    unpin,
)


def _cmd_status(args: argparse.Namespace) -> int:
    print(json.dumps(status(), indent=2))
    return 0


def _cmd_pins(args: argparse.Namespace) -> int:
    for cid in get_all_pins():
        print(cid)
    return 0


def _cmd_add(args: argparse.Namespace) -> int:
    source: str | bytes = args.path
    if args.path == "-":
        source = sys.stdin.buffer.read()
    cid = add(source)
    print(cid)
    return 0


def _cmd_announce(args: argparse.Namespace) -> int:
    source: str | bytes = args.path
    if args.path == "-":
        source = sys.stdin.buffer.read()
    cid = announce(source)
    print(cid)
    return 0


def _cmd_add_folder(args: argparse.Namespace) -> int:
    cid = add_folder(args.path)
    print(cid)
    return 0


def _cmd_get(args: argparse.Namespace) -> int:
    if args.output:
        get(args.cid, args.output)
        print(f"Wrote {args.output}", file=sys.stderr)
    else:
        sys.stdout.buffer.write(get(args.cid))
    return 0


def _cmd_pin(args: argparse.Namespace) -> int:
    pin(args.cid)
    for c in args.cid:
        print(f"Pinned {c}")
    return 0


def _cmd_unpin(args: argparse.Namespace) -> int:
    unpin(args.cid)
    for c in args.cid:
        print(f"Unpinned {c}")
    return 0


def _cmd_is_pinned(args: argparse.Namespace) -> int:
    pinned = is_pinned(args.cid)
    print("pinned" if pinned else "not pinned")
    return 0 if pinned else 1


def _cmd_exists(args: argparse.Namespace) -> int:
    found = exists(args.cid)
    print("exists" if found else "not found")
    return 0 if found else 1


def _cmd_gc(args: argparse.Namespace) -> int:
    garbage_collection()
    return 0


def _cmd_peers(args: argparse.Namespace) -> int:
    for addr in peers():
        print(addr)
    return 0


def _cmd_connect_to_node(args: argparse.Namespace) -> int:
    connect_to_node(args.addr)
    print(f"Connected {args.addr}")
    return 0


def _cmd_connect_to_nodes(args: argparse.Namespace) -> int:
    connect_to_nodes(args.addr)
    for a in args.addr:
        print(f"Connected {a}")
    return 0


def _cmd_create_private_network(args: argparse.Namespace) -> int:
    key = create_private_network()
    print(key)
    print("swarm.key written. Share the key above with nodes that should join.", file=sys.stderr)
    return 0


def _cmd_join_private_network(args: argparse.Namespace) -> int:
    join_private_network(args.key)
    print("swarm.key written.", file=sys.stderr)
    return 0


def _cmd_network_key(args: argparse.Namespace) -> int:
    key = get_private_network_key()
    if key is None:
        print("Not a private network (no swarm.key found).", file=sys.stderr)
        return 1
    print(key)
    return 0


def _cmd_rotate_identity(args: argparse.Namespace) -> int:
    new_id = rotate_identity(args.oldkey)
    print(new_id)
    print(f"Old key preserved as {args.oldkey!r}.", file=sys.stderr)
    return 0


def _cmd_lockdown(args: argparse.Namespace) -> int:
    lockdown_mode()
    print("Lockdown applied. Node will not talk to public IPFS.", file=sys.stderr)
    return 0


def _cmd_my_node_multiaddress(args: argparse.Namespace) -> int:
    ipv4, ipv6 = my_node_multiaddress()
    if ipv4:
        print(f"IPv4: {ipv4}")
    if ipv6:
        print(f"IPv6: {ipv6}")
    if not ipv4 and not ipv6:
        print("No shareable addresses found", file=sys.stderr)
        return 1
    return 0


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="basic-ipfs",
        description="Stupid-simple IPFS CLI. Runs a real Kubo node under the hood.",
    )
    p.add_argument("--version", action="version", version=f"basic-ipfs {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("status", help="Show node status")
    s.set_defaults(func=_cmd_status)

    ps = sub.add_parser("pins", help="List all pinned CIDs (one per line)")
    ps.set_defaults(func=_cmd_pins)

    a = sub.add_parser("add", help="Add a file (or stdin with '-') to IPFS and pin it")
    a.add_argument("path", help="File path, or '-' to read bytes from stdin")
    a.set_defaults(func=_cmd_add)

    an = sub.add_parser("announce", help="Add a file to IPFS without pinning (may be GC'd)")
    an.add_argument("path", help="File path, or '-' to read bytes from stdin")
    an.set_defaults(func=_cmd_announce)

    af = sub.add_parser("add-folder", help="Add a directory to IPFS recursively and pin it")
    af.add_argument("path", help="Directory path")
    af.set_defaults(func=_cmd_add_folder)

    g = sub.add_parser("get", help="Retrieve content by CID")
    g.add_argument("cid")
    g.add_argument("output", nargs="?", help="Output file path (default: stdout)")
    g.set_defaults(func=_cmd_get)

    pn = sub.add_parser("pin", help="Pin one or more CIDs")
    pn.add_argument("cid", nargs="+")
    pn.set_defaults(func=_cmd_pin)

    up = sub.add_parser("unpin", help="Unpin one or more CIDs")
    up.add_argument("cid", nargs="+")
    up.set_defaults(func=_cmd_unpin)

    ip = sub.add_parser("is-pinned", help="Check if a CID is pinned (exit 0=yes, 1=no)")
    ip.add_argument("cid")
    ip.set_defaults(func=_cmd_is_pinned)

    ex = sub.add_parser("exists", help="Check if a CID is locally available (exit 0=yes, 1=no)")
    ex.add_argument("cid")
    ex.set_defaults(func=_cmd_exists)

    gc = sub.add_parser("gc", help="Run garbage collection, freeing unpinned storage")
    gc.set_defaults(func=_cmd_gc)

    pr = sub.add_parser("peers", help="List connected peers (one multiaddr per line)")
    pr.set_defaults(func=_cmd_peers)

    cn = sub.add_parser("connect", help="Connect to a peer by multiaddr")
    cn.add_argument("addr")
    cn.set_defaults(func=_cmd_connect_to_node)

    cns = sub.add_parser("connect-nodes", help="Connect to multiple peers by multiaddr")
    cns.add_argument("addr", nargs="+")
    cns.set_defaults(func=_cmd_connect_to_nodes)

    ma = sub.add_parser("my-addr", help="Print this node's IPv4/IPv6 multiaddrs to share with others")
    ma.set_defaults(func=_cmd_my_node_multiaddress)

    cpn = sub.add_parser("create-private-network", help="Generate a swarm key and start a private network (run before start)")
    cpn.set_defaults(func=_cmd_create_private_network)

    jpn = sub.add_parser("join-private-network", help="Write a swarm key to join an existing private network (run before start)")
    jpn.add_argument("key", help="64-char hex key from create-private-network")
    jpn.set_defaults(func=_cmd_join_private_network)

    nk = sub.add_parser("network-key", help="Print the current swarm key (share with new members)")
    nk.set_defaults(func=_cmd_network_key)

    ri = sub.add_parser(
        "rotate-identity",
        help="Generate a new peer ID. Daemon must be stopped. Pins are preserved.",
    )
    ri.add_argument(
        "--oldkey", default="previous-self",
        help="Keystore name to preserve the old key under (default: previous-self)",
    )
    ri.set_defaults(func=_cmd_rotate_identity)

    ld = sub.add_parser(
        "lockdown",
        help="Disable DHT, bootstrap, gateway fetch, and non-loopback swarm. Daemon must be stopped.",
    )
    ld.set_defaults(func=_cmd_lockdown)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        rc: int = args.func(args)
        return rc
    except IPFSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except (FileNotFoundError, NotADirectoryError, IsADirectoryError, TypeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
