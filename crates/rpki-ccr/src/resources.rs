//! Resource types: AS numbers, address families, prefixes and VRPs.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use bcder::decode::{Constructed, DecodeError, Source};
use bcder::encode::{self, PrimitiveContent as _, Values};
use bcder::{BitString, OctetString};

/// An autonomous system number.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Asn(u32);

impl Asn {
    /// Creates an AS number.
    pub const fn new(number: u32) -> Self {
        Asn(number)
    }

    /// Returns the AS number as an integer.
    pub const fn into_u32(self) -> u32 {
        self.0
    }

    pub(crate) fn take_from<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.take_u32().map(Asn)
    }

    pub(crate) fn take_opt_from<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Option<Self>, DecodeError<S::Error>> {
        cons.take_opt_u32().map(|value| value.map(Asn))
    }
}

impl From<u32> for Asn {
    fn from(value: u32) -> Self {
        Asn(value)
    }
}

impl From<Asn> for u32 {
    fn from(value: Asn) -> Self {
        value.0
    }
}

impl fmt::Display for Asn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for Asn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AS{}", self.0)
    }
}

/// An IP address family as used in ROAs (RFC 9582 section 4.3.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Afi {
    /// IPv4, `addressFamily` `0001`.
    Ipv4,
    /// IPv6, `addressFamily` `0002`.
    Ipv6,
}

impl Afi {
    /// The two-octet `addressFamily` encoding.
    pub const fn octets(self) -> [u8; 2] {
        match self {
            Afi::Ipv4 => [0, 1],
            Afi::Ipv6 => [0, 2],
        }
    }

    /// The length of an address in bits.
    pub const fn max_prefix_len(self) -> u8 {
        match self {
            Afi::Ipv4 => 32,
            Afi::Ipv6 => 128,
        }
    }

    const fn max_octets(self) -> usize {
        self.max_prefix_len() as usize / 8
    }

    pub(crate) fn take_from<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        let octets = OctetString::take_from(cons)?;
        // addressFamily is exactly two octets, 0001 or 0002; a SAFI octet is not
        // allowed (RFC 9582 section 4.3.1).
        match octets.to_bytes().as_ref() {
            [0, 1] => Ok(Afi::Ipv4),
            [0, 2] => Ok(Afi::Ipv6),
            _ => Err(cons.content_err("addressFamily must be 0001 (IPv4) or 0002 (IPv6)")),
        }
    }
}

impl fmt::Display for Afi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Afi::Ipv4 => "IPv4",
            Afi::Ipv6 => "IPv6",
        })
    }
}

/// An IP prefix: an address with all host bits zero and a prefix length.
///
/// Ordering is by address family (IPv4 before IPv6), then address, then
/// prefix length, matching RFC 9582 section 4.3.3.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Prefix {
    addr: IpAddr,
    len: u8,
}

impl Prefix {
    /// Creates a prefix. Returns `None` if the length exceeds the address
    /// size or if any host bit is set.
    pub fn new(addr: IpAddr, len: u8) -> Option<Self> {
        let host_bits_clear = match addr {
            IpAddr::V4(a) => len <= 32 && (len == 32 || u32::from(a) & (u32::MAX >> len) == 0),
            IpAddr::V6(a) => len <= 128 && (len == 128 || u128::from(a) & (u128::MAX >> len) == 0),
        };
        host_bits_clear.then_some(Prefix { addr, len })
    }

    /// The network address.
    pub fn addr(&self) -> IpAddr {
        self.addr
    }

    /// The prefix length in bits.
    pub fn length(&self) -> u8 {
        self.len
    }

    /// The address family.
    pub fn afi(&self) -> Afi {
        match self.addr {
            IpAddr::V4(_) => Afi::Ipv4,
            IpAddr::V6(_) => Afi::Ipv6,
        }
    }

    /// Decodes an RFC 3779 `IPAddress` bit string in the given family
    /// (RFC 3779 section 2.2.3.8: the prefix length is the number of bits and
    /// unused bits must be zero; RFC 9582 section 4.3.2.1).
    pub(crate) fn from_bit_string(afi: Afi, bits: &BitString) -> Result<Self, &'static str> {
        let octets = bits.octet_bytes();
        let unused = bits.unused();
        if octets.len() > afi.max_octets() {
            return Err("IP address prefix is longer than an address of its family");
        }
        match octets.last() {
            None if unused != 0 => {
                return Err("unused bit count must be zero for an empty IP address prefix");
            }
            Some(last) if unused > 0 && last & ((1u8 << unused) - 1) != 0 => {
                return Err("unused bits of an IP address prefix must be zero");
            }
            _ => {}
        }
        let len = (octets.len() * 8 - usize::from(unused)) as u8;
        let addr = match afi {
            Afi::Ipv4 => {
                let mut raw = [0u8; 4];
                raw[..octets.len()].copy_from_slice(&octets);
                IpAddr::V4(Ipv4Addr::from(raw))
            }
            Afi::Ipv6 => {
                let mut raw = [0u8; 16];
                raw[..octets.len()].copy_from_slice(&octets);
                IpAddr::V6(Ipv6Addr::from(raw))
            }
        };
        Ok(Prefix { addr, len })
    }
}

impl fmt::Display for Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.len)
    }
}

impl fmt::Debug for Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Prefix({self})")
    }
}

/// Error returned when parsing a prefix from a string fails.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsePrefixError;

impl fmt::Display for ParsePrefixError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid IP prefix")
    }
}

impl std::error::Error for ParsePrefixError {}

impl FromStr for Prefix {
    type Err = ParsePrefixError;

    /// Parses `address/length`, e.g. `192.0.2.0/24` or `2001:db8::/32`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr, len) = s.split_once('/').ok_or(ParsePrefixError)?;
        let addr: IpAddr = addr.parse().map_err(|_| ParsePrefixError)?;
        let len: u8 = len.parse().map_err(|_| ParsePrefixError)?;
        Prefix::new(addr, len).ok_or(ParsePrefixError)
    }
}

/// A `ROAIPAddress`: a prefix with an optional maximum length (RFC 9582
/// section 4.3.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RoaIpAddress {
    prefix: Prefix,
    max_length: Option<u8>,
}

impl RoaIpAddress {
    /// Creates a ROA IP address. Returns `None` if `max_length` is smaller
    /// than the prefix length or larger than the address size.
    pub fn new(prefix: Prefix, max_length: Option<u8>) -> Option<Self> {
        match max_length {
            Some(m) if m < prefix.length() || m > prefix.afi().max_prefix_len() => None,
            _ => Some(RoaIpAddress { prefix, max_length }),
        }
    }

    /// The prefix.
    pub fn prefix(&self) -> Prefix {
        self.prefix
    }

    /// The `maxLength` field exactly as encoded (`None` when absent).
    pub fn max_length(&self) -> Option<u8> {
        self.max_length
    }

    /// The effective maximum length: `maxLength` when present, otherwise the
    /// prefix length.
    pub fn effective_max_length(&self) -> u8 {
        self.max_length.unwrap_or(self.prefix.length())
    }

    pub(crate) fn take_opt_from<S: Source>(
        cons: &mut Constructed<S>,
        afi: Afi,
    ) -> Result<Option<Self>, DecodeError<S::Error>> {
        cons.take_opt_sequence(|cons| {
            let bits = BitString::take_from(cons)?;
            let prefix = Prefix::from_bit_string(afi, &bits).map_err(|e| cons.content_err(e))?;
            let max_length = cons.take_opt_u8()?;
            if let Some(max) = max_length {
                // maxLength MUST be at least the prefix length and at most the address
                // length of the family (RFC 9582 section 4.3.2.2; draft section 6).
                if max < prefix.length() {
                    return Err(
                        cons.content_err("maxLength must not be smaller than the prefix length")
                    );
                }
                if max > afi.max_prefix_len() {
                    return Err(
                        cons.content_err("maxLength exceeds the address length of its family")
                    );
                }
            }
            Ok(RoaIpAddress { prefix, max_length })
        })
    }
}

impl fmt::Display for RoaIpAddress {
    /// `prefix/len` followed by `-maxLength` when the maximum length differs
    /// from the prefix length.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.prefix)?;
        if self.effective_max_length() != self.prefix.length() {
            write!(f, "-{}", self.effective_max_length())?;
        }
        Ok(())
    }
}

/// A Validated ROA Payload (RFC 6811 section 2): a flattened view of a
/// [`RoaPayloadSet`] entry.
///
/// Ordering is by AS number, then prefix, then maximum length.
///
/// [`RoaPayloadSet`]: crate::RoaPayloadSet
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Vrp {
    asn: Asn,
    prefix: Prefix,
    max_length: u8,
}

impl Vrp {
    /// Creates a VRP. Returns `None` if `max_length` is out of range.
    pub fn new(asn: Asn, prefix: Prefix, max_length: u8) -> Option<Self> {
        (prefix.length()..=prefix.afi().max_prefix_len())
            .contains(&max_length)
            .then_some(Vrp {
                asn,
                prefix,
                max_length,
            })
    }

    /// Creates the VRP for `address` originated by `asn`.
    pub fn from_address(asn: Asn, address: &RoaIpAddress) -> Self {
        Vrp {
            asn,
            prefix: address.prefix(),
            max_length: address.effective_max_length(),
        }
    }

    /// The origin AS number.
    pub fn asn(&self) -> Asn {
        self.asn
    }

    /// The prefix.
    pub fn prefix(&self) -> Prefix {
        self.prefix
    }

    /// The maximum length.
    pub fn max_length(&self) -> u8 {
        self.max_length
    }
}

impl fmt::Display for Vrp {
    /// `prefix/len[-maxLength] AS n`, e.g. `198.51.100.0/24-28 AS 65536`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.prefix)?;
        if self.max_length != self.prefix.length() {
            write!(f, "-{}", self.max_length)?;
        }
        write!(f, " AS {}", self.asn)
    }
}

impl Asn {
    /// Returns a DER encoder for the AS number as an `INTEGER`.
    pub fn encode_ref(&self) -> impl Values {
        self.0.encode()
    }
}

impl Afi {
    /// Returns a DER encoder for the two-octet `addressFamily` string.
    pub fn encode_ref(&self) -> impl Values {
        OctetString::encode_slice(self.octets())
    }
}

/// The octets of a prefix's address that carry prefix bits.
struct PrefixOctets {
    buf: [u8; 16],
    len: usize,
}

impl AsRef<[u8]> for PrefixOctets {
    fn as_ref(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

impl Prefix {
    /// Returns a DER encoder for the prefix as an RFC 3779 `IPAddress`
    /// bit string.
    pub fn encode_ref(&self) -> impl Values {
        let mut buf = [0u8; 16];
        match self.addr {
            IpAddr::V4(a) => buf[..4].copy_from_slice(&a.octets()),
            IpAddr::V6(a) => buf.copy_from_slice(&a.octets()),
        }
        let len = usize::from(self.len).div_ceil(8);
        let unused = (len * 8 - usize::from(self.len)) as u8;
        BitString::encode_slice(PrefixOctets { buf, len }, unused)
    }
}

impl RoaIpAddress {
    /// Returns the canonical form: `maxLength` omitted when it equals the
    /// prefix length (SHOULD NOT be encoded in RFC 9582 section 4.3.2.2,
    /// MUST NOT in draft section 3.4.2 after -11).
    pub fn canonical(self) -> Self {
        RoaIpAddress {
            prefix: self.prefix,
            max_length: self.max_length.filter(|&max| max != self.prefix.length()),
        }
    }

    /// Returns a DER encoder for the `ROAIPAddress` sequence.
    pub fn encode_ref(&self) -> impl Values {
        encode::sequence((
            self.prefix.encode_ref(),
            self.max_length.map(|max| max.encode()),
        ))
    }
}

impl Vrp {
    /// The VRP as a canonical `ROAIPAddress`.
    pub fn address(&self) -> RoaIpAddress {
        RoaIpAddress {
            prefix: self.prefix,
            max_length: None,
        }
        .with_max_length(self.max_length)
    }
}

impl RoaIpAddress {
    fn with_max_length(self, max_length: u8) -> Self {
        RoaIpAddress {
            prefix: self.prefix,
            max_length: Some(max_length),
        }
        .canonical()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    fn bits(unused: u8, octets: &[u8]) -> BitString {
        BitString::new(unused, Bytes::copy_from_slice(octets))
    }

    #[test]
    fn decodes_prefixes_from_bit_strings() {
        let p = Prefix::from_bit_string(Afi::Ipv4, &bits(0, &[192, 0, 2])).unwrap();
        assert_eq!(p.to_string(), "192.0.2.0/24");
        let p = Prefix::from_bit_string(Afi::Ipv4, &bits(7, &[10, 0, 0, 0x80])).unwrap();
        assert_eq!(p.to_string(), "10.0.0.128/25");
        let p = Prefix::from_bit_string(Afi::Ipv4, &bits(0, &[])).unwrap();
        assert_eq!(p.to_string(), "0.0.0.0/0");
        let p = Prefix::from_bit_string(Afi::Ipv4, &bits(0, &[192, 0, 2, 1])).unwrap();
        assert_eq!(p.to_string(), "192.0.2.1/32");
        let p =
            Prefix::from_bit_string(Afi::Ipv6, &bits(0, &[0x20, 0x01, 0x0d, 0xb8, 0, 0])).unwrap();
        assert_eq!(p.to_string(), "2001:db8::/48");
        let p = Prefix::from_bit_string(Afi::Ipv6, &bits(0, &[0xff; 16])).unwrap();
        assert_eq!(p.to_string(), "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128");
    }

    #[test]
    fn rejects_bad_bit_strings() {
        assert!(Prefix::from_bit_string(Afi::Ipv4, &bits(0, &[1, 2, 3, 4, 5])).is_err());
        assert!(Prefix::from_bit_string(Afi::Ipv6, &bits(0, &[1; 17])).is_err());
        assert!(Prefix::from_bit_string(Afi::Ipv4, &bits(7, &[10, 0, 0, 0x81])).is_err());
    }

    #[test]
    fn prefix_from_str_and_ordering() {
        let a: Prefix = "192.0.2.0/24".parse().unwrap();
        let b: Prefix = "192.0.2.0/25".parse().unwrap();
        let c: Prefix = "198.51.100.0/24".parse().unwrap();
        let d: Prefix = "2001:db8::/32".parse().unwrap();
        assert!(a < b && b < c && c < d);
        assert!("192.0.2.1/24".parse::<Prefix>().is_err());
        assert!("192.0.2.0/33".parse::<Prefix>().is_err());
        assert!("192.0.2.0".parse::<Prefix>().is_err());
        assert!("::/129".parse::<Prefix>().is_err());
        assert_eq!("0.0.0.0/0".parse::<Prefix>().unwrap().length(), 0);
        assert_eq!("::/0".parse::<Prefix>().unwrap().afi(), Afi::Ipv6);
    }

    #[test]
    fn vrp_display() {
        let p: Prefix = "198.51.100.0/24".parse().unwrap();
        assert_eq!(
            Vrp::new(Asn(65536), p, 28).unwrap().to_string(),
            "198.51.100.0/24-28 AS 65536"
        );
        assert_eq!(
            Vrp::new(Asn(0), p, 24).unwrap().to_string(),
            "198.51.100.0/24 AS 0"
        );
        assert!(Vrp::new(Asn(0), p, 23).is_none());
        assert!(Vrp::new(Asn(0), p, 33).is_none());
        assert!(RoaIpAddress::new(p, Some(20)).is_none());
        assert_eq!(
            RoaIpAddress::new(p, None).unwrap().effective_max_length(),
            24
        );
    }
}
