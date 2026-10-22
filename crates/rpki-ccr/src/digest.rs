//! SHA-256 digests.

use std::fmt;

use bcder::OctetString;
use bcder::decode::{Constructed, DecodeError, Source};
use sha2::Digest as _;

use crate::hex;
use bcder::encode::Values;

/// A SHA-256 message digest.
///
/// Ordering is lexicographic over the octets, which is how the CCR
/// specification orders manifest instances by hash.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Digest([u8; 32]);

impl Digest {
    /// The length of the digest in octets.
    pub const LEN: usize = 32;

    /// Computes the SHA-256 digest of `data`.
    pub fn sha256(data: &[u8]) -> Self {
        Digest(sha2::Sha256::digest(data).into())
    }

    /// Returns the raw octets.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Returns the raw octets as an array.
    pub fn into_array(self) -> [u8; 32] {
        self.0
    }

    /// Parses a hex string (either case, no separators).
    pub fn from_hex(s: &str) -> Option<Self> {
        hex::decode(s).and_then(|v| Self::try_from(v.as_slice()).ok())
    }

    pub(crate) fn take_from<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        let octets = OctetString::take_from(cons)?;
        // 32 octets follow from hashAlg being SHA-256 (draft section 3.2).
        Self::try_from(octets.to_bytes().as_ref())
            .map_err(|_| cons.content_err("SHA-256 digest must be exactly 32 octets"))
    }
}

impl TryFrom<&[u8]> for Digest {
    type Error = std::array::TryFromSliceError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        <[u8; 32]>::try_from(value).map(Digest)
    }
}

impl From<[u8; 32]> for Digest {
    fn from(value: [u8; 32]) -> Self {
        Digest(value)
    }
}

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        hex::write_lower(f, &self.0)
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Digest({self})")
    }
}

impl Digest {
    /// Returns a DER encoder for the digest as an `OCTET STRING`.
    pub fn encode_ref(&self) -> impl Values + '_ {
        OctetString::encode_slice(&self.0[..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_of_empty_input() {
        assert_eq!(
            Digest::sha256(b"").to_string(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn hex_round_trip() {
        let hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(Digest::from_hex(hex).unwrap().to_string(), hex);
        assert!(Digest::from_hex("e3b0").is_none());
    }
}
