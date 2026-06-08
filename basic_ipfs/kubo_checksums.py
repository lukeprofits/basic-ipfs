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
    "v0.42.0": {
        "linux-amd64  ": "054c38a0cf66f7d738e25085ad62cb3a42d03d4bac329b7dd25c1d71cf18e1ce87d55b1d1b705b04c65210dca9109973579e0eb1cd72f6341ecb3311d840d156",
        "linux-arm64  ": "5f4abb1a63e82bbdd0417517eb1c7bb5f64e95da2724f85d9762f640ddb9e6a5728bb86d60022ac367accf14248d80a0484cf7960392e15e540dfbf655974def",
        "linux-riscv64": "620db13aec006842730fc796ca7d210241300cd5c30c5b8b18252478dc187a37b8000080ffaa457350044041bf667ed05f5a76e468cf8e99a8b95bd38565ee2c",
        "darwin-amd64 ": "090105ea166d4db85ff6a5f9a2e12c6efd451bd6ba15336aa3de5534ef48fa48706cd0911a40c071175e08131432158c07cac8060721185e50ab0dd46011c7bb",
        "darwin-arm64 ": "5f863972f7edee0ac3f003d8b097366927e8d9f651fd5c74e1fda980f766dbf7af4b8a813b13400eb2bcf3a871a494a139c85f022e239b237581ad152259cd22",
        "windows-amd64": "5501a7745898e71326e1b85d8d231d79a3409147484ce2ca28da94c9272319e6c691e19a1ed74c0f0a7beb601fb203e10a6c242aaab1a5961c260b1b0d14c452",
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
