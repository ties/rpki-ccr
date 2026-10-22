//! Subject and authority key identifiers.

use std::fmt;

use bcder::OctetString;
use bcder::decode::{Constructed, DecodeError, Source};

use crate::hex;

/// A 160-bit key identifier (RFC 6487 section 4.8.2): the SHA-1 hash of a
/// certificate's subject public key.
///
/// Ordering is the ordering of the value interpreted as an unsigned 160-bit
/// integer, as required by the CCR specification.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KeyIdentifier([u8; 20]);

impl KeyIdentifier {
    /// The length of a key identifier in octets.
    pub const LEN: usize = 20;

    /// Returns the raw octets.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Returns the raw octets as an array.
    pub fn into_array(self) -> [u8; 20] {
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
        Self::from_octets(cons, &octets)
    }

    pub(crate) fn take_opt_from<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Option<Self>, DecodeError<S::Error>> {
        match OctetString::take_opt_from(cons)? {
            Some(octets) => Self::from_octets(cons, &octets).map(Some),
            None => Ok(None),
        }
    }

    fn from_octets<S: Source>(
        cons: &Constructed<S>,
        octets: &OctetString,
    ) -> Result<Self, DecodeError<S::Error>> {
        Self::try_from(octets.to_bytes().as_ref())
            .map_err(|_| cons.content_err("key identifier must be exactly 20 octets"))
    }
}

impl TryFrom<&[u8]> for KeyIdentifier {
    type Error = std::array::TryFromSliceError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        <[u8; 20]>::try_from(value).map(KeyIdentifier)
    }
}

impl From<[u8; 20]> for KeyIdentifier {
    fn from(value: [u8; 20]) -> Self {
        KeyIdentifier(value)
    }
}

impl AsRef<[u8]> for KeyIdentifier {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for KeyIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        hex::write_upper(f, &self.0)
    }
}

impl fmt::Debug for KeyIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyIdentifier({self})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trip() {
        let ki = KeyIdentifier::from_hex("25f8ccfcefc046d8dcd00fc0e444e0aa7b790f96").unwrap();
        assert_eq!(ki.to_string(), "25F8CCFCEFC046D8DCD00FC0E444E0AA7B790F96");
        assert!(KeyIdentifier::from_hex("25f8").is_none());
        assert!(KeyIdentifier::from_hex("zz").is_none());
    }

    #[test]
    fn orders_as_unsigned_integer() {
        let lo = KeyIdentifier([0x00; 20]);
        let hi = KeyIdentifier([0xff; 20]);
        let mut mid = [0x00; 20];
        mid[0] = 0x80;
        assert!(lo < KeyIdentifier(mid) && KeyIdentifier(mid) < hi);
    }
}
