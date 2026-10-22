# rpki-ccr

A Rust library for reading RPKI Canonical Cache Representation (CCR) files, as
specified in [draft-ietf-sidrops-rpki-ccr](https://datatracker.ietf.org/doc/draft-ietf-sidrops-rpki-ccr/).

A CCR is a DER-encoded, byte-for-byte reproducible snapshot of a validated RPKI
cache: the current manifests, validated ROA payloads (VRPs), ASPA payloads,
trust anchors and BGPsec router keys. Each state aspect carries a SHA-256
digest over its payload so that corruption is detectable without a signature.

The ASN.1 work is done with [bcder](https://crates.io/crates/bcder).

## Usage

```rust
use rpki_ccr::Ccr;

let data = std::fs::read("rpki.ccr")?;        // plain DER or gzip (.ccr.gz)
let ccr = Ccr::decode(&data)?;                // strict validation

println!("produced at {}", ccr.produced_at());
if let Some(roas) = ccr.roa_payloads() {
    for vrp in roas.vrps() {
        println!("{vrp}");                     // 198.51.100.0/24-28 AS 65536
    }
}
if let Some(manifests) = ccr.manifests() {
    for mi in manifests.instances() {
        println!("{} {} #{}", mi.aki(), mi.locations()[0].uri(), mi.manifest_number());
    }
}
```

## Validation

`Ccr::decode` enforces every requirement of the specification and fails on the
first violation:

* structure and bounds: CMS content type, absent `version`, SHA-256 without
  parameters, 15-octet `GeneralizedTime`, 20-octet key identifiers, 32-octet
  digests, `size >= 1000`, manifest numbers of at most 20 octets, valid address
  families, prefix and `maxLength` bounds, non-empty sequences where required,
  at least one state aspect;
* digests: each state aspect's hash is recomputed over its DER payload;
* ordering and uniqueness: manifest instances by hash, subordinates and trust
  anchor SKIs as unsigned 160-bit integers, ROA and router key sets by AS,
  address families and ROA addresses in RFC 9582 canonical order, ASPA
  customers and providers ascending, router keys by SKI;
* consistency: `mostRecentUpdate` equals the newest manifest `thisUpdate` (or
  the POSIX epoch), does not exceed `producedAt`, and AS 0 appears only as a
  sole provider.

Structural and bounds violations are always errors. The semantic groups can be
relaxed to inspect non-conforming files:

```rust
use rpki_ccr::{Ccr, DecodeOptions};

let ccr = Ccr::decode_with(&data, &DecodeOptions::strict().verify_hashes(false))?;
let ccr = Ccr::decode_with(&data, &DecodeOptions::lenient())?;
```

Unknown future state aspects (context tags above `[5]`) are tolerated and
exposed verbatim through `Ccr::extensions`.

## Example: `ccr-dump`

Prints a file in the textual format of the specification's Appendix B and of
`rpki-client -f`, for side-by-side comparison:

```sh
cargo run --example ccr-dump -- crates/rpki-ccr/tests/data/example.ccr
cargo run --example ccr-dump -- --lenient broken.ccr.gz
```

## Features

* `gzip` (default): inflate `application/rpki-ccr+gzip` input automatically.

## Roadmap

1. Parsing and validation (this crate).
2. DER encoding: canonical ordering, digest computation and a round-trip test
   against the specification's test vector. The encoder will also be used to
   generate a fixture whose manifest instances carry multiple
   `AccessDescription`s, which the Appendix B vector lacks.
3. Python bindings in `crates/rpki-ccr-py` (pyo3 + maturin), modelled on
   [rpki-rs-py](https://github.com/ties/rpki-rs-py).

## Development

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo test -p rpki-ccr --no-default-features
```

The minimum supported Rust version is 1.85 (edition 2024).
