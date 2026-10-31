# TODO

- Add a `rust-toolchain.toml` pinning the toolchain, if that is acceptable in
  a project that also builds through pyo3/maturin: `maturin-action` and
  `pip`/`uv` sdist builds invoke `cargo` through rustup, so a pin is honoured
  (and downloaded on first use, which slows the manylinux containers); pin a
  channel (`stable`) rather than a version unless reproducibility matters more
  than picking up compiler fixes, and keep `rust-version = "1.85"` as the MSRV
  check regardless.

- Re-check the `size` constraint of `ManifestInstance` once the next draft
  revision is out. Draft -11 says `INTEGER (1000..MAX)`; the lower bound is
  not enforced because 1000 turned out to be too high and will be changed.

Completed:

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
