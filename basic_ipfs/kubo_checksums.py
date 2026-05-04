"""
Built-in SHA-512 checksums for Kubo binaries.

Why baked in: if dist.ipfs.tech is compromised, an attacker could swap both
the archive and its `.sha512` companion file. Verifying against a hash that
shipped inside the wheel — installed via signed PyPI metadata — closes that
gap. For unknown versions, we fall back to fetching the .sha512 alongside
the archive (with an INFO-level log noting the weaker check).

To populate a new version: ``python scripts/refresh_checksums.py <version>``
"""

# {kubo_version: {platform_key: sha512_hex}}
CHECKSUMS: dict[str, dict[str, str]] = {
    "v0.41.0": {
        "linux-amd64  ": "5c0f3dba6d29d30e3f3cfdbf7f7b05c228167d21211207b9c17a106f5c846d33895cd42a618eed989073b48af4a870df7f1f6c86a052796b02ea79767b66e4ef",
        "linux-arm64  ": "443a205d97dad590a6828e6ce994421b4fd6fa55feb9173c79b7b533b9d2c39646f0bfe2b9bcc3c6e25fe7876eae335586fddcfeefd48b2beb48c522d9713032",
        "linux-riscv64": "c850346ac0fdc18a3aa9f1b6baf70d0a45ef13f2693e65027c5a6a1346a555238e344e4ba7de0455721ca9ec49cd26b84cf9234166a9efdc2996c8323e6a1c71",
        "darwin-amd64 ": "f4c8cd6037791fcad2aa5e79f39268141df2ffe91710956499e813b77d2ad49de84e9cb52426fb8e006a52f6cf9a5ea1dc1964acf860d4c3b7c9e756c4e59f54",
        "darwin-arm64 ": "a44b7f00e21ac322dbe018bc56c7dbca6b3bde2404853041d6365439fe055bfaf97a9215c95c3b389d7e04c93233f00a65b14d5bdaa01d9854c039852831eb84",
        "windows-amd64": "c0d80cc3261c6ab4c47f477f393b1c03322c5dd89a2b598f95568eb4bbac6d85bc6ca177796da253fe75fb05188bc9f44d78b853a73fad51298d414f390c6699",
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
