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
    "v0.43.1": {
        "linux-amd64  ": "ff53b2428794fc8cca39505d28c15b4cceaef4b90a09284f291f611fcdc8c06399690575fc89cbd4d85ef71f3652581296c6f2e710386f887c8edf36b6e89d71",
        "linux-arm64  ": "70f082584651ef78fb5b07448be53bb0adf141aadcb7eea15ffa59bd9ca78fed46781c2cf5915b3528c591052f97486067fedb0a7a1415abd5bfd44942921501",
        "linux-riscv64": "c53bea5f0f71b6e42239a239bc6d27044f4402724a0150d2875bd2d89429646301afc089678a18383c094e75fcd5e73ee7ac2936d524d5a9e7a5631438cbde26",
        "darwin-amd64 ": "efe0c1561595fbf7b5bdc3fc651863697c2bf388eed5f8c94c163f60d9575201808538abba84f652718f015ad1af6e3c01ced1321ddb2082f934ba8952e4a4ab",
        "darwin-arm64 ": "bc282d781d856736051ce6d216ba47d52bec703f1a54ab5fa20fba26a92e4af3e8fb131e220cdf01f20205f1effb1a5b7bedbdeff15e8edbbe8e5b01923a7cbb",
        "windows-amd64": "e611cecef25cddb10b7f907145383608d9b31219ad7120041aeacfe2313882da1944f2897fda29bc2d959dd357e4950089ec8f2cbd52b29f2fc472bcae4356d0",
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
