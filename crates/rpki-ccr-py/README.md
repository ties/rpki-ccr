# rpki-ccr

Python bindings for [rpki-ccr](https://github.com/ties/rpki-ccr), a parser and
encoder for RPKI Canonical Cache Representation (CCR) files
([draft-ietf-sidrops-rpki-ccr](https://datatracker.ietf.org/doc/draft-ietf-sidrops-rpki-ccr/)).

A CCR is a DER-encoded, byte-for-byte reproducible snapshot of a validated
RPKI cache: the current manifests, validated ROA payloads (VRPs), ASPA
payloads, trust anchors and BGPsec router keys. Every state aspect carries a
SHA-256 digest so that corruption is detectable without a signature.

```sh
pip install rpki-ccr
```

## Reading

```python
from rpki_ccr import Ccr

ccr = Ccr.from_file("rpki.ccr")          # plain DER or gzip (.ccr.gz)
print(ccr)                               # Ccr(produced_at=..., manifests=55587, roa_payloads=1026530, ...)

for vrp in ccr.roa_payloads:             # flattened: Vrp(asn, prefix, max_length)
    print(vrp)                           # 198.51.100.0/24-28 AS 65536

for mi in ccr.manifests:                 # ManifestInstance
    print(mi.aki.hex(), mi.manifest_number, mi.this_update, mi.locations[0].uri)
```

`Ccr.decode(data)` enforces every requirement of the specification and
raises a typed `rpki_ccr.Error` subclass on failure (`DerError`,
`HashMismatchError` with `aspect`, `declared` and `computed`,
`NotSortedError`, `DuplicateError`, `ConsistencyError`, `InvalidValueError`).
File problems raise `OSError`. Non-conforming files can be inspected with the
checks switched off:

```python
ccr = Ccr.decode(data, verify_hashes=False)
```

The five state views (`ccr.manifests`, `ccr.roa_payloads`,
`ccr.aspa_payloads`, `ccr.trust_anchors`, `ccr.router_keys`) are read-only
sequences backed by the Rust data: indexing, slicing, iteration, `in`,
`index` and `count` work without copying the whole file. Key identifiers and
digests are `bytes`, OIDs are dotted strings, AS numbers and manifest numbers
are `int`, and times are timezone-aware UTC `datetime` objects. Everything is
immutable, hashable and picklable.

## Writing

```python
from datetime import datetime, timezone
from rpki_ccr import AspaPayloadSet, Ccr, ManifestInstance, Vrp

ccr = Ccr(
    datetime(2026, 5, 15, 0, 0, 10, tzinfo=timezone.utc),
    manifests=[ManifestInstance(hash=..., size=1729, aki=..., manifest_number=257,
                                this_update=..., locations=["rsync://example.net/ca1/x.mft"])],
    roa_payloads=[Vrp(65536, "198.51.100.0/24", 28), Vrp(65536, "2001:db8::/48")],
    aspa_payloads=[AspaPayloadSet(65536, [65540, 65544])],
    trust_anchors=[bytes.fromhex("25f8ccfcefc046d8dcd00fc0e444e0aa7b790f96")],
)
der = ccr.to_der()                       # canonical: sorted, deduplicated, digests computed
```

`to_der()` validates first, so an object decoded with checks switched off is
refused unless the same checks are switched off again
(`to_der(verify_hashes=False)`). `ccr.validate()` runs the checks without
encoding. Decoded objects re-encode byte for byte.

## Comparing files

```python
diff = Ccr.from_file("old.ccr").diff(Ccr.from_file("new.ccr"))
if diff:                                     # anything changed?
    for vrp in diff.roa_payloads.added:      # RoaPayloadDiff: added, removed, unchanged
        print("+", vrp)
    for change in diff.manifests.issuers:    # by issuer: kind is "added", "removed" or "updated"
        print(change.kind, change.aki.hex(), [mi.manifest_number for mi in change.after])
    for update in diff.aspa_payloads.updated:
        print(update.customer_asn, update.providers_added, update.providers_removed)
```

The diff is a linear merge in Rust over the canonical sequences (aspects
with equal digests are skipped), so comparing two full-RPKI files costs
milliseconds. Manifests are reported both by hash (`added`/`removed`) and
grouped by issuer (`issuers`); aspects absent on one side are compared as
empty, aspects absent on both are `None`.

## Examples

`examples/ccr_diff.py OLD NEW` prints the changes between two files in the
same layout as the Rust `ccr-diff` example.

## Development

```sh
cd crates/rpki-ccr-py
uv sync                                  # builds the extension into .venv
uv run maturin develop --uv              # after Rust changes
uv run pytest
uv run python -m mypy.stubtest rpki_ccr --allowlist stubtest-allowlist.txt  # keeps rpki_ccr.pyi honest
```

Wheels are built for the stable ABI (`abi3`, Python 3.9+).
