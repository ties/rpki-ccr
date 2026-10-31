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
  digests, manifest numbers of at most 20 octets, valid address
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
use rpki_ccr::{Ccr, ValidationOptions};

let ccr = Ccr::decode_with(&data, &ValidationOptions::strict().verify_hashes(false))?;
let ccr = Ccr::decode_with(&data, &ValidationOptions::lenient())?;
```

Unknown future state aspects (context tags above `[5]`) are tolerated and
exposed verbatim through `Ccr::extensions`.

## Encoding

A decoded `Ccr` re-encodes byte-for-byte (`encode(decode(x)) == x` holds for
the specification's test vector and for rpki-client output). New files are
built with the canonicalising constructors, which sort, deduplicate and merge
their input and compute the state digests, and with `Ccr::builder`, which
runs the same strict validation as the decoder:

```rust
use chrono::Timelike as _;
use rpki_ccr::{Asn, Ccr, KeyIdentifier, RoaPayloadState, TrustAnchorState, Vrp};

let vrps = RoaPayloadState::from_vrps([
    Vrp::new(Asn::new(65536), "198.51.100.0/24".parse()?, 28).unwrap(),
    Vrp::new(Asn::new(65536), "2001:db8::/48".parse()?, 48).unwrap(),
]);
let tas = TrustAnchorState::new(vec![KeyIdentifier::from_hex("25f8ccfcefc046d8dcd00fc0e444e0aa7b790f96").unwrap()])?;
let produced_at = chrono::Utc::now().with_nanosecond(0).unwrap(); // whole seconds only
let ccr = Ccr::builder(produced_at).roa_payloads(vrps).trust_anchors(tas).build()?;
let der = ccr.to_der()?;           // or write_der(&mut file)?, to_der_gzip()?
```

Encoding validates first: `to_der()` recomputes the state digests from the
object's current data and runs the ordering and consistency checks, so an
object decoded with checks switched off is refused unless the same checks
are switched off with `to_der_with(&ValidationOptions::lenient())`.
`Ccr::validate` runs the checks without encoding.

Everything the specification orders is sorted by the constructors. The
`locations` of a manifest instance are the exception: the specification
defines no order for them (in practice there is exactly one), so
`ManifestInstance::new` sorts them lexicographically (access method OID,
then URI) as a safe default for
deterministic output, while decoded instances keep their encoded order.

## Comparing files

`Ccr::diff` computes the changes from one CCR to another as a linear merge
over the canonical sequences, skipping aspects whose digests are equal:

```rust
let diff = before.diff(&after);
for vrp in diff.roa_payloads().map_or(&[][..], |d| d.added()) {
    println!("+ {vrp}");
}
for change in diff.manifests().map_or(&[][..], |d| d.issuers()) {
    println!("{:?} {}: {} -> {}", change.kind(), change.aki(), change.before().len(), change.after().len());
}
```

The state types also offer plain set operations in canonical order
(`difference`, `intersection`, `union`, `symmetric_difference`), and every
diff type has `reversed()`. In Python these are the `-`, `&`, `|`, `^`
operators on the views, `new - old` on `Ccr` and unary minus on diffs.

VRPs, trust anchors and router keys are set differences (`added`, `removed`,
`unchanged`). Manifests come in two views: by hash (`added`/`removed`) and
grouped by issuer (`issuers()`, each `IssuerChange` being added, removed or
updated with the instances before and after). ASPA payloads are keyed by
customer AS with per-customer provider deltas. Aspects absent on one side
are compared as empty; aspects absent on both are `None`.

## Examples

```sh
cargo run --example ccr-dump -- crates/rpki-ccr/tests/data/example.ccr
cargo run --example ccr-diff -- old.ccr new.ccr        # add --summary for counts only
```

### `ccr-dump`

Prints a file in the textual format of the specification's Appendix B and of
`rpki-client -f`, for side-by-side comparison:

```sh
cargo run --example ccr-dump -- crates/rpki-ccr/tests/data/example.ccr
cargo run --example ccr-dump -- --lenient broken.ccr.gz
```

## Features

* `gzip` (default): inflate `application/rpki-ccr+gzip` input automatically.

## Python

`crates/rpki-ccr-py` provides the `rpki_ccr` Python package (pyo3, abi3
wheels for Python 3.9+) with the same model: `Ccr.decode` / `Ccr.from_file`,
typed exceptions, read-only sequence views for the five state aspects, value
classes for building files, and validate-before-encode `to_der()`. See
[crates/rpki-ccr-py/README.md](crates/rpki-ccr-py/README.md).

```python
from rpki_ccr import Ccr
for vrp in Ccr.from_file("rpki.ccr").roa_payloads:
    print(vrp)
```

## Roadmap

1. Parsing and validation. Done.
2. DER encoding with canonicalising constructors and a builder, round-trip
   tests against the specification's test vector and rpki-client output, and
   a generated fixture (`tests/data/multi-location.ccr`) whose manifest
   instances carry multiple `AccessDescription`s. Done.
3. Python bindings in `crates/rpki-ccr-py` (pyo3 + maturin), modelled on
   [rpki-rs-py](https://github.com/ties/rpki-rs-py). Done.

## Development

```sh
export PATH="$HOME/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin:$PATH"  # if cargo fmt/clippy are not found
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo test -p rpki-ccr --no-default-features
RPKI_CCR_ROUNDTRIP_FILE=rpki.ccr cargo test --release --test encode -- --ignored   # round-trip any file
RPKI_CCR_WRITE_FIXTURES=1 cargo test --test encode                                  # regenerate generated fixtures
```

The minimum supported Rust version is 1.85 (edition 2024).

## License

BSD 3-Clause, see [LICENSE](LICENSE).
