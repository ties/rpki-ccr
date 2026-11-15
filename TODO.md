# TODO

- Add a `rust-toolchain.toml` pinning the toolchain, if that is acceptable in
  a project that also builds through pyo3/maturin: `maturin-action` and
  `pip`/`uv` sdist builds invoke `cargo` through rustup, so a pin is honoured
  (and downloaded on first use, which slows the manylinux containers); pin a
  channel (`stable`) rather than a version unless reproducibility matters more
  than picking up compiler fixes, and keep `rust-version = "1.85"` as the MSRV
  check regardless.

- Re-check the crate against the published RFC. Three rules implemented here
  come from the draft's editor repository
  (https://github.com/job/draft-sidrops-rpki-ccr) after -11 and are not in a
  published revision yet: `size INTEGER (0..MAX)` (commits ebf45bf, e11cca3),
  no `maxLength` equal to the prefix length (92972a8) and no customer AS in
  its own `providers` (05182f0).

Completed:

- `ManifestInstance.size`: draft -11 says `INTEGER (1000..MAX)`, which turned
  out to be too high. The editor's copy now says `INTEGER (0..MAX)`, which is
  what the decoder and constructors enforce.

- Checked how the manifest hashes are determined, in the draft and in
  rpki-client's encoder (`openbsd/usr.sbin/rpki-client`): `ManifestInstance.hash`
  is SHA-256 over the raw bytes of the manifest file (`parser.c`: `EVP_Digest(der,
  len, mft->mfthash, ...)`; `size` is that file's length), so it does not cover
  `subordinates`, which rpki-client attaches afterwards from the validated CA
  certificates whose parent manifest has that hash (`ccr_insert_mft_sub`). The
  state-level `ManifestState.hash` is `ASN1_item_digest` over the DER-encoded
  `ManifestInstances`, which does include subordinates. The side-agent note is
  therefore right about subordinates; `locations` come from the EE certificate
  inside the manifest and are covered by the file hash. Open question moved to
  the diff design: whether to surface subordinate-only differences.

- RFC and draft section references next to the code that implements each
  rule (decoder checks, validation rules, canonicalising constructors).
