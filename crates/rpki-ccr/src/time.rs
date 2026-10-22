//! GeneralizedTime decoding.

use bcder::Tag;
use bcder::decode::{Constructed, DecodeError, Source};
use chrono::{DateTime, NaiveDate, Utc};

/// The POSIX epoch, the value `mostRecentUpdate` must take when there are no
/// manifest instances.
pub(crate) const EPOCH: DateTime<Utc> = DateTime::UNIX_EPOCH;

/// Takes a `GeneralizedTime` value from the constructed value.
pub(crate) fn take_generalized_time<S: Source>(
    cons: &mut Constructed<S>,
) -> Result<DateTime<Utc>, DecodeError<S::Error>> {
    cons.take_primitive_if(Tag::GENERALIZED_TIME, |prim| {
        prim.with_slice_all(parse_generalized_time)
    })
}

/// Parses the DER form of GeneralizedTime restricted by RFC 5280: exactly
/// `YYYYMMDDHHMMSSZ`, no fractional seconds, no local offsets.
pub(crate) fn parse_generalized_time(s: &[u8]) -> Result<DateTime<Utc>, &'static str> {
    if s.len() != 15 {
        return Err("GeneralizedTime must be exactly 15 octets (YYYYMMDDHHMMSSZ)");
    }
    if s[14] != b'Z' {
        return Err("GeneralizedTime must be in UTC and end in 'Z'");
    }
    if !s[..14].iter().all(u8::is_ascii_digit) {
        return Err("GeneralizedTime contains non-digit characters");
    }
    let num = |range: std::ops::Range<usize>| {
        s[range]
            .iter()
            .fold(0u32, |acc, c| acc * 10 + u32::from(c - b'0'))
    };
    NaiveDate::from_ymd_opt(num(0..4) as i32, num(4..6), num(6..8))
        .and_then(|date| date.and_hms_opt(num(8..10), num(10..12), num(12..14)))
        .map(|naive| naive.and_utc())
        .ok_or("GeneralizedTime is not a valid date and time")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_times() {
        let t = parse_generalized_time(b"20260515000010Z").unwrap();
        assert_eq!(t.timestamp(), 1778803210);
        assert_eq!(parse_generalized_time(b"19700101000000Z").unwrap(), EPOCH);
        assert_eq!(
            parse_generalized_time(b"20240229235959Z")
                .unwrap()
                .timestamp(),
            1709251199
        );
    }

    #[test]
    fn rejects_invalid_times() {
        for bad in [
            &b"2026051500001Z"[..],
            b"20260515000010",
            b"20260515000010+0000",
            b"20260515000010.5Z",
            b"2026051500001xZ",
            b"20261315000010Z",
            b"20260230000010Z",
            b"20260515240010Z",
            b"20260515006010Z",
            b"20260515000060Z",
            b"",
        ] {
            assert!(parse_generalized_time(bad).is_err(), "{bad:?}");
        }
    }
}
