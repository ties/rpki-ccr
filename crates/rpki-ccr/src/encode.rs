//! Encoding helpers shared by the state types.

use std::io;

use bcder::encode::{PrimitiveContent, Values};
use bcder::{Mode, Tag};
use chrono::{DateTime, Utc};

use crate::Digest;

/// Emits already-encoded DER verbatim.
pub(crate) struct RawDer<'a>(pub &'a [u8]);

impl Values for RawDer<'_> {
    fn encoded_len(&self, _: Mode) -> usize {
        self.0.len()
    }

    fn write_encoded<W: io::Write>(&self, _: Mode, target: &mut W) -> Result<(), io::Error> {
        target.write_all(self.0)
    }
}

/// A `GeneralizedTime` in the 15-octet form required by RFC 5280.
pub(crate) struct GeneralizedTime(pub DateTime<Utc>);

impl PrimitiveContent for GeneralizedTime {
    const TAG: Tag = Tag::GENERALIZED_TIME;

    fn encoded_len(&self, _: Mode) -> usize {
        15
    }

    fn write_encoded<W: io::Write>(&self, _: Mode, target: &mut W) -> Result<(), io::Error> {
        write!(target, "{}", self.0.format("%Y%m%d%H%M%SZ"))
    }
}

/// The SHA-256 digest over the DER encoding of `values`.
pub(crate) fn digest_of(values: &impl Values) -> Digest {
    Digest::sha256(values.to_captured(Mode::Der).as_slice())
}

/// Sorts `items` by `key` (stable) and drops later items with an equal key.
pub(crate) fn sort_dedup_by_key<T, K: Ord>(mut items: Vec<T>, key: impl Fn(&T) -> K) -> Vec<T> {
    items.sort_by_key(|item| key(item));
    items.dedup_by_key(|item| key(item));
    items
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn generalized_time_encoding() {
        let t = Utc.with_ymd_and_hms(2026, 5, 15, 0, 0, 10).unwrap();
        let der = GeneralizedTime(t).encode().to_captured(Mode::Der);
        assert_eq!(der.as_slice(), b"\x18\x0f20260515000010Z");
        let epoch = GeneralizedTime(DateTime::UNIX_EPOCH)
            .encode()
            .to_captured(Mode::Der);
        assert_eq!(epoch.as_slice(), b"\x18\x0f19700101000000Z");
    }

    #[test]
    fn raw_der_passes_through() {
        let der = RawDer(&[0x05, 0x00]).to_captured(Mode::Der);
        assert_eq!(der.as_slice(), &[0x05, 0x00]);
    }

    #[test]
    fn sort_dedup_keeps_first() {
        let items = vec![(2, "b"), (1, "a"), (2, "c"), (1, "d")];
        assert_eq!(sort_dedup_by_key(items, |i| i.0), [(1, "a"), (2, "b")]);
    }
}
