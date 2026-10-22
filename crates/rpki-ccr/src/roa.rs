//! `ROAPayloadState`, `ROAPayloadSet` and `ROAIPAddressFamily`.

use bcder::decode::{Constructed, DecodeError, Source};

use crate::error::Aspect;
use crate::validate::HashedPayload;
use crate::{Afi, Asn, Digest, RoaIpAddress, Vrp};
use std::collections::BTreeMap;

use bcder::encode::{self, Values};

use crate::Error;
use crate::encode::{digest_of, sort_dedup_by_key};

/// The current set of Validated ROA Payloads, grouped by origin AS.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RoaPayloadState {
    sets: Vec<RoaPayloadSet>,
    hash: Digest,
}

impl RoaPayloadState {
    /// The payload sets, in encoded order (ascending by AS number).
    pub fn sets(&self) -> &[RoaPayloadSet] {
        &self.sets
    }

    /// The digest declared over the DER-encoded `rps` sequence.
    pub fn hash(&self) -> &Digest {
        &self.hash
    }

    /// The number of payload sets.
    pub fn len(&self) -> usize {
        self.sets.len()
    }

    /// Whether there are no payload sets.
    pub fn is_empty(&self) -> bool {
        self.sets.is_empty()
    }

    /// Iterates over all VRPs in encoded order.
    pub fn vrps(&self) -> impl Iterator<Item = Vrp> + '_ {
        self.sets.iter().flat_map(RoaPayloadSet::vrps)
    }

    /// Decodes `ROAPayloadState` (draft section 3.4.2): `rps` and the digest
    /// over the DER-encoded `rps`.
    pub(crate) fn take_from<S: Source>(
        cons: &mut Constructed<S>,
        hashed: &mut Vec<HashedPayload>,
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            let mut sets = Vec::new();
            let payload = cons.capture(|cons| {
                cons.take_sequence(|cons| {
                    while let Some(set) = RoaPayloadSet::take_opt_from(cons)? {
                        sets.push(set);
                    }
                    Ok(())
                })
            })?;
            let hash = Digest::take_from(cons)?;
            hashed.push(HashedPayload {
                aspect: Aspect::RoaPayloads,
                payload,
                declared: hash,
            });
            Ok(RoaPayloadState { sets, hash })
        })
    }
}

/// The VRPs for one origin AS, modelled after `RouteOriginAttestation`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RoaPayloadSet {
    as_id: Asn,
    ip_addr_blocks: Vec<RoaIpAddressFamily>,
}

impl RoaPayloadSet {
    /// The origin AS number.
    pub fn as_id(&self) -> Asn {
        self.as_id
    }

    /// The address families (one or two, IPv4 before IPv6).
    pub fn ip_addr_blocks(&self) -> &[RoaIpAddressFamily] {
        &self.ip_addr_blocks
    }

    /// Iterates over the VRPs of this set in encoded order.
    pub fn vrps(&self) -> impl Iterator<Item = Vrp> + '_ {
        self.ip_addr_blocks.iter().flat_map(move |family| {
            family
                .addresses
                .iter()
                .map(move |address| Vrp::from_address(self.as_id, address))
        })
    }

    pub(crate) fn take_opt_from<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Option<Self>, DecodeError<S::Error>> {
        cons.take_opt_sequence(|cons| {
            let as_id = Asn::take_from(cons)?;
            let ip_addr_blocks = cons.take_sequence(|cons| {
                let mut blocks = Vec::new();
                while let Some(block) = RoaIpAddressFamily::take_opt_from(cons)? {
                    blocks.push(block);
                }
                Ok(blocks)
            })?;
            // ipAddrBlocks SEQUENCE (SIZE(1..2)) OF ROAIPAddressFamily (draft section 3,
            // RFC 9582 section 4.3.1).
            if ip_addr_blocks.is_empty() || ip_addr_blocks.len() > 2 {
                return Err(
                    cons.content_err("ipAddrBlocks must contain one or two address families")
                );
            }
            Ok(RoaPayloadSet {
                as_id,
                ip_addr_blocks,
            })
        })
    }
}

/// The ROA IP addresses of one address family.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RoaIpAddressFamily {
    afi: Afi,
    addresses: Vec<RoaIpAddress>,
}

impl RoaIpAddressFamily {
    /// The address family.
    pub fn afi(&self) -> Afi {
        self.afi
    }

    /// The addresses (at least one), in encoded order.
    pub fn addresses(&self) -> &[RoaIpAddress] {
        &self.addresses
    }

    pub(crate) fn take_opt_from<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Option<Self>, DecodeError<S::Error>> {
        cons.take_opt_sequence(|cons| {
            let afi = Afi::take_from(cons)?;
            let addresses = cons.take_sequence(|cons| {
                let mut addresses = Vec::new();
                while let Some(address) = RoaIpAddress::take_opt_from(cons, afi)? {
                    addresses.push(address);
                }
                Ok(addresses)
            })?;
            // addresses SEQUENCE (SIZE(1..MAX)) OF ROAIPAddress (RFC 9582 section 4.3.1).
            if addresses.is_empty() {
                return Err(cons.content_err("addresses must contain at least one ROAIPAddress"));
            }
            Ok(RoaIpAddressFamily { afi, addresses })
        })
    }
}

impl RoaPayloadState {
    /// Builds a canonical state from VRPs: grouped by AS number, split by
    /// address family, sorted, deduplicated, with `maxLength` omitted when
    /// it equals the prefix length (RFC 9582 sections 4.3.2.2 and 4.3.3; draft
    /// section 3.4.2).
    pub fn from_vrps(vrps: impl IntoIterator<Item = Vrp>) -> Self {
        Self::from_addresses(vrps.into_iter().map(|vrp| (vrp.asn(), vrp.address())))
    }

    /// Builds a canonical state from payload sets, merging sets with the
    /// same AS number.
    pub fn new(sets: Vec<RoaPayloadSet>) -> Self {
        Self::from_addresses(sets.into_iter().flat_map(|set| {
            let as_id = set.as_id;
            set.ip_addr_blocks.into_iter().flat_map(move |family| {
                family
                    .addresses
                    .into_iter()
                    .map(move |address| (as_id, address))
            })
        }))
    }

    fn from_addresses(items: impl IntoIterator<Item = (Asn, RoaIpAddress)>) -> Self {
        let mut by_asn: BTreeMap<Asn, Vec<RoaIpAddress>> = BTreeMap::new();
        for (as_id, address) in items {
            by_asn.entry(as_id).or_default().push(address);
        }
        let sets = by_asn
            .into_iter()
            .map(|(as_id, addresses)| RoaPayloadSet::canonical(as_id, addresses))
            .collect();
        let mut state = RoaPayloadState {
            sets,
            hash: Digest::from([0; 32]),
        };
        let hash = digest_of(&state.encode_payload());
        state.hash = hash;
        state
    }

    pub(crate) fn encode_payload(&self) -> impl Values + '_ {
        encode::sequence(encode::iter(
            self.sets.iter().map(RoaPayloadSet::encode_ref),
        ))
    }

    /// Returns a DER encoder for the `ROAPayloadState` sequence.
    pub fn encode_ref(&self) -> impl Values + '_ {
        encode::sequence((self.encode_payload(), self.hash.encode_ref()))
    }
}

impl RoaPayloadSet {
    /// Creates a canonical payload set from at least one address.
    pub fn new(as_id: Asn, addresses: Vec<RoaIpAddress>) -> Result<Self, Error> {
        // addresses SEQUENCE (SIZE(1..MAX)) OF ROAIPAddress (RFC 9582 section 4.3.1).
        if addresses.is_empty() {
            return Err(Error::invalid(format!(
                "ROA payload set for AS {as_id} needs at least one address"
            )));
        }
        Ok(Self::canonical(as_id, addresses))
    }

    /// The canonical form of RFC 9582 section 4.3.3: at most one family per AFI,
    /// IPv4 before IPv6, addresses ascending and unique (draft section 3.4.2).
    fn canonical(as_id: Asn, addresses: Vec<RoaIpAddress>) -> Self {
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for address in addresses {
            let address = address.canonical();
            match address.prefix().afi() {
                Afi::Ipv4 => v4.push(address),
                Afi::Ipv6 => v6.push(address),
            }
        }
        let ip_addr_blocks = [(Afi::Ipv4, v4), (Afi::Ipv6, v6)]
            .into_iter()
            .filter(|(_, addresses)| !addresses.is_empty())
            .map(|(afi, addresses)| RoaIpAddressFamily {
                afi,
                addresses: sort_dedup_by_key(addresses, |a| (a.prefix(), a.effective_max_length())),
            })
            .collect();
        RoaPayloadSet {
            as_id,
            ip_addr_blocks,
        }
    }

    /// Returns a DER encoder for the `ROAPayloadSet` sequence.
    pub fn encode_ref(&self) -> impl Values + '_ {
        encode::sequence((
            self.as_id.encode_ref(),
            encode::sequence(encode::iter(
                self.ip_addr_blocks
                    .iter()
                    .map(RoaIpAddressFamily::encode_ref),
            )),
        ))
    }
}

impl RoaIpAddressFamily {
    /// Returns a DER encoder for the `ROAIPAddressFamily` sequence.
    pub fn encode_ref(&self) -> impl Values + '_ {
        encode::sequence((
            self.afi.encode_ref(),
            encode::sequence(encode::iter(
                self.addresses.iter().map(RoaIpAddress::encode_ref),
            )),
        ))
    }
}
