# TODO

- Add references to the relevant RFC and draft sections next to the code that
  implements them: the decoder's structural checks in `crates/rpki-ccr/src/*.rs`
  (e.g. draft-ietf-sidrops-rpki-ccr section 3.4.x per state aspect, RFC 9582
  section 4.3 for `ROAIPAddressFamily` / `ROAIPAddress`, RFC 6487 section 4.8.2
  for key identifiers, RFC 5280 section 4.1.2.2 for the 20-octet manifest
  number, RFC 3779 section 2.2.3.8 for prefix bit strings, RFC 5754 section 2
  for the SHA-256 algorithm identifier), the ordering, uniqueness and
  consistency rules in `validate.rs`, and the canonicalising constructors
  (RFC 9582 section 4.3.3, draft section 3.4.3 for the AS 0 provider rule).
