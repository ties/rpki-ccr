//! Error types.

use std::convert::Infallible;
use std::fmt;

use crate::Digest;

/// The state aspects of a CCR, used to attribute validation errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Aspect {
    /// `ManifestState` (`mfts`).
    Manifests,
    /// `ROAPayloadState` (`vrps`).
    RoaPayloads,
    /// `ASPAPayloadState` (`vaps`).
    AspaPayloads,
    /// `TrustAnchorState` (`tas`).
    TrustAnchors,
    /// `RouterKeyState` (`rks`).
    RouterKeys,
}

impl Aspect {
    /// The ASN.1 type name of the aspect.
    pub fn type_name(self) -> &'static str {
        match self {
            Aspect::Manifests => "ManifestState",
            Aspect::RoaPayloads => "ROAPayloadState",
            Aspect::AspaPayloads => "ASPAPayloadState",
            Aspect::TrustAnchors => "TrustAnchorState",
            Aspect::RouterKeys => "RouterKeyState",
        }
    }
}

impl fmt::Display for Aspect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.type_name())
    }
}

/// An error produced while decoding or validating a CCR.
///
/// Structural problems (malformed DER, wrong content type, out-of-range
/// values, missing mandatory elements) are reported as [`Error::Der`] with
/// the byte position of the offending element. The remaining variants are
/// semantic checks that can be disabled through [`DecodeOptions`].
///
/// [`DecodeOptions`]: crate::DecodeOptions
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The input is not a well-formed CCR.
    #[error("invalid DER: {0}")]
    Der(#[from] bcder::decode::DecodeError<Infallible>),

    /// Reading the file or inflating gzip data failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// The input is gzip-compressed but the `gzip` feature is disabled.
    #[error("input is gzip-compressed but the `gzip` feature is disabled")]
    GzipUnsupported,

    /// The digest declared for a state aspect does not match its payload.
    #[error("{aspect}: hash mismatch (declared {declared}, computed {computed})")]
    HashMismatch {
        /// The aspect whose digest failed to verify.
        aspect: Aspect,
        /// The digest stored in the file.
        declared: Digest,
        /// The digest computed over the DER-encoded payload.
        computed: Digest,
    },

    /// A sequence that must be in ascending order is not.
    #[error("{aspect}: {what} not in ascending order (element {index})")]
    NotSorted {
        /// The aspect containing the sequence.
        aspect: Aspect,
        /// What is being ordered, e.g. "manifest instances".
        what: &'static str,
        /// Index of the first element that is out of order.
        index: usize,
    },

    /// A sequence that must contain unique elements has a duplicate.
    #[error("{aspect}: duplicate {what} (element {index})")]
    Duplicate {
        /// The aspect containing the sequence.
        aspect: Aspect,
        /// What is duplicated, e.g. "subject key identifier".
        what: &'static str,
        /// Index of the repeated element.
        index: usize,
    },

    /// A relationship between fields required by the specification does not hold.
    #[error("{aspect}: {detail}")]
    Consistency {
        /// The aspect in which the inconsistency was found.
        aspect: Aspect,
        /// Human-readable description.
        detail: String,
    },

    /// A value given to a constructor or builder violates the specification.
    #[error("invalid value: {detail}")]
    InvalidValue {
        /// Human-readable description.
        detail: String,
    },
}

impl Error {
    pub(crate) fn invalid(detail: impl Into<String>) -> Self {
        Error::InvalidValue {
            detail: detail.into(),
        }
    }
}
