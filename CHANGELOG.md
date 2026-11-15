# Changelog

Versions apply to both the Rust crate and the Python package (`rpki-ccr` on
PyPI), which are released together.

## 0.2.0 (unreleased)

Follows the editor's copy of the draft
(https://github.com/job/draft-sidrops-rpki-ccr) past
draft-ietf-sidrops-rpki-ccr-11, the latest published revision.

Stricter:

- A customer AS that appears in its own ASPA provider list is rejected by
  `AspaPayloadSet::new` (Python: `AspaPayloadSet(...)` raises
  `InvalidValueError`) and fails consistency validation.
- A ROA `maxLength` equal to the prefix length fails consistency validation,
  so strict `Ccr::decode`, `Ccr::validate` and `to_der` reject it. Lenient
  decoding keeps it as encoded, so a lenient round trip stays exact.

Relaxed:

- `ManifestInstance.size` is `INTEGER (0..MAX)`. Draft -11 says
  `(1000..MAX)`; that lower bound was never enforced and has been dropped
  from the draft.

## 0.1.0 (2026-11-15)

First release, published to PyPI only.

- Decoding of plain and gzipped CCR files with strict validation, relaxable
  per rule group through `ValidationOptions`.
- DER encoding with canonicalising constructors, `Ccr::builder()` and
  validation before encoding.
- `Ccr::diff` and set operations over two CCRs, with the `ccr-diff` and
  `ccr-dump` examples.
- Python bindings (`rpki_ccr`, abi3 wheels for Python 3.9 and later) with
  type stubs.
