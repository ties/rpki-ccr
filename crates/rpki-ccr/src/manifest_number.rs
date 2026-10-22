//! Manifest numbers.

use std::cmp::Ordering;
use std::fmt;

use bcder::Unsigned;
use bcder::decode::{Constructed, DecodeError, Source};
use bytes::Bytes;

use crate::Error;
use crate::hex;
use std::io;

use bcder::encode::{PrimitiveContent, Values};
use bcder::{Mode, Tag};

/// A manifest number: a non-negative integer of at most 20 octets
/// (RFC 9286 section 4.2.1, RFC 5280 section 4.1.2.2).
///
/// The value is stored as its minimal big-endian magnitude, so it compares
/// numerically and can exceed the range of native integers.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ManifestNumber(Bytes);

impl ManifestNumber {
    /// The maximum number of DER content octets allowed for a manifest number.
    pub const MAX_LEN: usize = 20;

    /// Returns the minimal big-endian magnitude (at least one octet).
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the value as a `u128` if it fits.
    pub fn as_u128(&self) -> Option<u128> {
        if self.0.len() > 16 {
            return None;
        }
        Some(
            self.0
                .iter()
                .fold(0u128, |acc, &b| (acc << 8) | u128::from(b)),
        )
    }

    pub(crate) fn take_from<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        let value = Unsigned::take_from(cons)?;
        // At most 20 octets (RFC 9286 section 4.2.1 via RFC 5280 section 4.1.2.2;
        // draft section 6).
        if value.as_slice().len() > Self::MAX_LEN {
            return Err(cons.content_err("manifest number must fit in 20 octets"));
        }
        Ok(Self::from_magnitude(value.into_bytes()))
    }

    /// Creates a manifest number from big-endian magnitude octets. Leading
    /// zero octets are ignored and an empty slice is zero. The value must be
    /// representable in 20 DER content octets, i.e. below 2^159.
    pub fn try_from_be_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.is_empty() {
            return Ok(Self::from(0u64));
        }
        let number = Self::from_magnitude(Bytes::copy_from_slice(bytes));
        let octets = number.0.len() + usize::from(number.0[0] & 0x80 != 0);
        if octets > Self::MAX_LEN {
            return Err(Error::invalid(format!(
                "manifest number needs {octets} octets, the maximum is {}",
                Self::MAX_LEN
            )));
        }
        Ok(number)
    }

    /// Strips redundant leading zero octets (DER adds one when the top bit is set).
    fn from_magnitude(bytes: Bytes) -> Self {
        let skip = bytes
            .iter()
            .take_while(|&&b| b == 0)
            .count()
            .min(bytes.len().saturating_sub(1));
        ManifestNumber(bytes.slice(skip..))
    }
}

impl From<u64> for ManifestNumber {
    fn from(value: u64) -> Self {
        Self::from_magnitude(Bytes::copy_from_slice(&value.to_be_bytes()))
    }
}

impl From<u128> for ManifestNumber {
    fn from(value: u128) -> Self {
        Self::from_magnitude(Bytes::copy_from_slice(&value.to_be_bytes()))
    }
}

impl PartialOrd for ManifestNumber {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ManifestNumber {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0
            .len()
            .cmp(&other.0.len())
            .then_with(|| self.0.cmp(&other.0))
    }
}

impl fmt::Display for ManifestNumber {
    /// Upper-case hex with two digits per octet, e.g. `0101`, matching the
    /// `seqnum` notation of rpki-client.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        hex::write_upper(f, &self.0)
    }
}

impl fmt::Debug for ManifestNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ManifestNumber({self})")
    }
}

impl ManifestNumber {
    /// Returns a DER encoder for the manifest number as an `INTEGER`.
    pub fn encode_ref(&self) -> impl Values + '_ {
        ManifestNumberContent(&self.0).encode()
    }
}

/// The DER content of a manifest number: the magnitude, preceded by a zero
/// octet when its top bit is set.
struct ManifestNumberContent<'a>(&'a [u8]);

impl ManifestNumberContent<'_> {
    fn needs_sign_octet(&self) -> bool {
        self.0.first().is_some_and(|first| first & 0x80 != 0)
    }
}

impl PrimitiveContent for ManifestNumberContent<'_> {
    const TAG: Tag = Tag::INTEGER;

    fn encoded_len(&self, _: Mode) -> usize {
        self.0.len() + usize::from(self.needs_sign_octet())
    }

    fn write_encoded<W: io::Write>(&self, _: Mode, target: &mut W) -> Result<(), io::Error> {
        if self.needs_sign_octet() {
            target.write_all(&[0])?;
        }
        target.write_all(self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_leading_zeros_but_keeps_one_octet() {
        assert_eq!(ManifestNumber::from(0u64).as_bytes(), &[0]);
        assert_eq!(ManifestNumber::from(0u64).to_string(), "00");
        assert_eq!(ManifestNumber::from(0x0101u64).to_string(), "0101");
        assert_eq!(ManifestNumber::from(0x80u64).as_bytes(), &[0x80]);
    }

    #[test]
    fn as_u128() {
        assert_eq!(ManifestNumber::from(0x1321u64).as_u128(), Some(0x1321));
        assert_eq!(ManifestNumber::from(u128::MAX).as_u128(), Some(u128::MAX));
        let big = ManifestNumber(Bytes::from(vec![1u8; 17]));
        assert_eq!(big.as_u128(), None);
    }

    #[test]
    fn from_be_bytes_bounds() {
        assert_eq!(
            ManifestNumber::try_from_be_bytes(&[]).unwrap().as_bytes(),
            &[0]
        );
        assert_eq!(
            ManifestNumber::try_from_be_bytes(&[0, 0, 1, 1])
                .unwrap()
                .to_string(),
            "0101"
        );
        assert!(ManifestNumber::try_from_be_bytes(&[0x7f; 20]).is_ok());
        assert!(ManifestNumber::try_from_be_bytes(&[0x80; 20]).is_err());
        assert!(ManifestNumber::try_from_be_bytes(&[1; 21]).is_err());
        let mut padded = vec![0; 5];
        padded.extend_from_slice(&[0x7f; 20]);
        assert!(ManifestNumber::try_from_be_bytes(&padded).is_ok());
    }

    #[test]
    fn orders_numerically() {
        assert!(ManifestNumber::from(0x0101u64) < ManifestNumber::from(0x1321u64));
        assert!(ManifestNumber::from(0xffu64) < ManifestNumber::from(0x0100u64));
        assert!(ManifestNumber::from(u128::MAX) > ManifestNumber::from(u64::MAX));
    }
}
