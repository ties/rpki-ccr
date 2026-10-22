//! Parser for RPKI Canonical Cache Representation (CCR) files.
//!
//! A CCR file (draft-ietf-sidrops-rpki-ccr) is a DER-encoded, byte-for-byte
//! reproducible snapshot of the state of a validated RPKI cache: the current
//! manifests, validated ROA payloads (VRPs), ASPA payloads, trust anchors and
//! BGPsec router keys. Every state aspect carries a SHA-256 digest over its
//! payload so that file corruption can be detected without a signature.
//!
//! This crate decodes CCR files with [`bcder`] and, by default, enforces every
//! requirement of the specification: digest verification, canonical ordering
//! and uniqueness, and the contextual bounds of all fields. Analytics tooling
//! that must inspect non-conforming files can relax the semantic checks with
//! [`ValidationOptions`].
//!
//! ```no_run
//! use rpki_ccr::Ccr;
//!
//! let data = std::fs::read("rpki.ccr").unwrap();
//! let ccr = Ccr::decode(&data).unwrap(); // gzip input is detected automatically
//! println!("produced at {}", ccr.produced_at());
//! if let Some(roas) = ccr.roa_payloads() {
//!     for vrp in roas.vrps() {
//!         println!("{vrp}");
//!     }
//! }
//! ```
//!
//! A `Ccr` re-encodes byte-for-byte with [`Ccr::to_der`], which validates
//! the object first so that a file decoded with checks switched off cannot
//! be written back unnoticed. New files are built from the canonicalising
//! constructors of the state types and [`Ccr::builder`]:
//!
//! ```
//! use chrono::{TimeZone, Utc};
//! use rpki_ccr::{Asn, Ccr, KeyIdentifier, RoaPayloadState, TrustAnchorState, Vrp};
//!
//! let vrps = RoaPayloadState::from_vrps([
//!     Vrp::new(Asn::new(65536), "198.51.100.0/24".parse().unwrap(), 28).unwrap(),
//!     Vrp::new(Asn::new(65536), "2001:db8::/48".parse().unwrap(), 48).unwrap(),
//! ]);
//! let ski = KeyIdentifier::from_hex("25f8ccfcefc046d8dcd00fc0e444e0aa7b790f96").unwrap();
//! let tas = TrustAnchorState::new(vec![ski]).unwrap();
//! let ccr = Ccr::builder(Utc.with_ymd_and_hms(2026, 5, 15, 0, 0, 10).unwrap())
//!     .roa_payloads(vrps)
//!     .trust_anchors(tas)
//!     .build()
//!     .unwrap();
//! let der = ccr.to_der().unwrap();
//! assert_eq!(Ccr::decode(&der).unwrap(), ccr);
//! ```
//!
//! Two CCRs compare with [`Ccr::diff`], a linear merge over the canonical
//! sequences that reports added and removed VRPs, trust anchors and router
//! keys, manifests both by hash and grouped by issuer, and per-customer ASPA
//! provider changes.
//!
//! # Features
//!
//! * `gzip` (default): transparently inflate gzip-compressed CCR files
//!   (`application/rpki-ccr+gzip`).

#![warn(missing_docs)]
#![forbid(unsafe_code)]

mod access;
mod aspa;
mod ccr;
mod diff;
mod digest;
mod encode;
mod error;
mod hex;
mod key_identifier;
mod manifest;
mod manifest_number;
pub mod oid;
mod options;
mod resources;
mod roa;
mod router_key;
mod spki;
mod time;
mod trust_anchor;
mod validate;

pub use access::AccessDescription;
pub use aspa::{AspaPayloadSet, AspaPayloadState};
pub use ccr::{Ccr, CcrBuilder, HashAlgorithm};
pub use diff::{
    AspaPayloadDiff, AspaUpdate, CcrDiff, ChangeKind, IssuerChange, ManifestDiff, SetDiff,
};
pub use digest::Digest;
pub use error::{Aspect, Error};
pub use key_identifier::KeyIdentifier;
pub use manifest::{ManifestInstance, ManifestState};
pub use manifest_number::ManifestNumber;
pub use options::ValidationOptions;
pub use resources::{Afi, Asn, Prefix, RoaIpAddress, Vrp};
pub use roa::{RoaIpAddressFamily, RoaPayloadSet, RoaPayloadState};
pub use router_key::{RouterKey, RouterKeySet, RouterKeyState};
pub use spki::SubjectPublicKeyInfo;
pub use trust_anchor::TrustAnchorState;

/// Re-export of the `bcder` crate used for the ASN.1 types in the public API.
pub use bcder;
/// Re-export of the `bytes` crate used in the public API.
pub use bytes;
/// Re-export of the `chrono` crate used for timestamps in the public API.
pub use chrono;
