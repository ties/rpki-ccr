//! Decoding options.

/// Controls which semantic checks [`Ccr::decode_with`] performs.
///
/// Structural checks (DER well-formedness, mandatory fields, value bounds)
/// are always enforced. The checks below are the ones that may be relaxed to
/// inspect files produced by non-conforming or buggy relying parties.
///
/// ```
/// use rpki_ccr::DecodeOptions;
///
/// let strict = DecodeOptions::strict();
/// assert!(strict.verify_hashes && strict.check_ordering && strict.check_consistency);
///
/// let no_hashes = DecodeOptions::strict().verify_hashes(false);
/// assert!(!no_hashes.verify_hashes && no_hashes.check_ordering);
/// ```
///
/// [`Ccr::decode_with`]: crate::Ccr::decode_with
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct DecodeOptions {
    /// Verify the SHA-256 digest of every state aspect against its payload.
    pub verify_hashes: bool,
    /// Verify that every sequence is sorted as required and free of duplicates.
    pub check_ordering: bool,
    /// Verify cross-field rules: `mostRecentUpdate` versus the manifest
    /// `thisUpdate` values and `producedAt`, and the AS 0 provider rule.
    pub check_consistency: bool,
}

impl DecodeOptions {
    /// All checks enabled. This is the default.
    pub const fn strict() -> Self {
        DecodeOptions {
            verify_hashes: true,
            check_ordering: true,
            check_consistency: true,
        }
    }

    /// All semantic checks disabled; only structural validity is enforced.
    pub const fn lenient() -> Self {
        DecodeOptions {
            verify_hashes: false,
            check_ordering: false,
            check_consistency: false,
        }
    }

    /// Sets whether state aspect digests are verified.
    pub const fn verify_hashes(mut self, enabled: bool) -> Self {
        self.verify_hashes = enabled;
        self
    }

    /// Sets whether ordering and uniqueness are verified.
    pub const fn check_ordering(mut self, enabled: bool) -> Self {
        self.check_ordering = enabled;
        self
    }

    /// Sets whether cross-field consistency rules are verified.
    pub const fn check_consistency(mut self, enabled: bool) -> Self {
        self.check_consistency = enabled;
        self
    }
}

impl Default for DecodeOptions {
    fn default() -> Self {
        Self::strict()
    }
}
