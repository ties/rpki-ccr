# TODO

- Add a `rust-toolchain.toml` pinning the toolchain, if that is acceptable in
  a project that also builds through pyo3/maturin: `maturin-action` and
  `pip`/`uv` sdist builds invoke `cargo` through rustup, so a pin is honoured
  (and downloaded on first use, which slows the manylinux containers); pin a
  channel (`stable`) rather than a version unless reproducibility matters more
  than picking up compiler fixes, and keep `rust-version = "1.85"` as the MSRV
  check regardless.

Completed:

- RFC and draft section references next to the code that implements each
  rule (decoder checks, validation rules, canonicalising constructors).
