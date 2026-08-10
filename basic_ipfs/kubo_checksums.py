"""
Built-in SHA-512 checksums for Kubo binaries.

Why baked in: if dist.ipfs.tech is compromised, an attacker could swap both
the archive and its `.sha512` companion file. Verifying against a hash that
shipped inside the wheel — installed via signed PyPI metadata — closes that
gap. Versions not in this table are refused outright (fail-closed): fetching
a digest from the same origin as the archive would add no protection.

To populate a new version: ``python scripts/refresh_checksums.py <version>``
"""

# {kubo_version: {platform_key: sha512_hex}}
CHECKSUMS: dict[str, dict[str, str]] = {
    "v0.43.0": {
        "linux-amd64  ": "6af21cd24a307d94326807b3d3827064c74fb7122f83b6940af250e6ae40da250e0ec0e1f3551256b78cd204623ed56c32ce735bbe28bdcc787b36943c52458a",
        "linux-arm64  ": "aae6c766ec2436f27bbd2d6ab5f8de7d2ced4dc83abc5b54b17bd58a80c28f1ea2e38840305e22f08bd01c55cf8263745675da1bbda2ac0bcde268e9e61e3818",
        "linux-riscv64": "5c784e79f6a23ff6467fcd1de164fac0ef74e968579fce47595078feed9236dd0956568346e924c567ff9534d8f9836162bf133f4a9fa4b9e27087e1a70e1d7b",
        "darwin-amd64 ": "7edd038e9208b8024ef14329102a8bc40827c21337bb2d38ea52400c57a04e3c092086a11c9d342b85083a71df4bf77130fd676bdb68628b2d9e8e6f511ee305",
        "darwin-arm64 ": "2377bc886b340087b20d5a9bdd025e5a6ed4b7e910ac04fa0d0e26f5b7e189b31a33f6cc682c0aaec2695a65b8a38d1f5bfce505c2948c0ea08ee64009034ef6",
        "windows-amd64": "0486721fc406d36c9d70d16dc3984e70c50d5f1d1c890de3864a6904564080adb3f73546162ad30a8e1ee43024a18bf900fbda2b6c131197351ff2e8b9782178",
    },
    "v0.40.1": {
        "linux-amd64":   "86f9c07bca62d09839e53553df0f81bc306364b1467a459d52f3e4505cc948d196ed0c219c03c667cd681e057bb24bbfc0e0eebf4b83bc64a36a0e9923a60e05",
        "linux-arm64":   "07a52fb63c37ac687ad41bc949f60e16856387d5d33ecf452771b5d992fa4fe2e659f383d267de69cd9755aa5751847aab66247b5cdeeaad7a06b780ece51cb7",
        "linux-riscv64": "49ebe239f38a01b25c02e87c1308ea8298cbe8119cf9bc6c1db3ac9b4340d3b3b2612cf94fd8c2182e9c7287d52f530ab53727cd78597a2398708547bf466aba",
        "darwin-amd64":  "b8becb9d8782a968e4489a60f62bfc2a1fb5638df01488051c2255e2ebc14a9f1666097ba1ceb50f8fe8ca8efc642726bca093f81195d327dd46c1444c0f39ad",
        "darwin-arm64":  "13b6d5dc04e661bfde6b8ba469bcf5b19d9d0062fe8ed50c7aadd8a078f500d0bceee4be7c9bfa476b48c4eb84c246ba083605ed1ed24d16b98e6cd0f09140bb",
        "windows-amd64": "456f8938d7dc64fdd95ac7897af0f15249265bf2d742b6776b883c8534981f2e85e13b00f8d42fce908671e44fee08b810a8afa858f2e649e6fee9c174373591",
    },
}


def known_checksum(version: str, platform_key: str) -> "str | None":
    """Return the baked-in SHA-512 hex, or None if not in the table."""
    return CHECKSUMS.get(version, {}).get(platform_key)
