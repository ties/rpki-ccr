//! `ROAPayloadState`, `ROAPayloadSet` and `ROAIPAddressFamily`.

use bcder::decode::{Constructed, DecodeError, Source};

use crate::error::Aspect;
use crate::validate::HashedPayload;
use crate::{Afi, Asn, Digest, RoaIpAddress, Vrp};

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
                .map(move |address| Vrp::from_parts(self.as_id, address))
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
            if addresses.is_empty() {
                return Err(cons.content_err("addresses must contain at least one ROAIPAddress"));
            }
            Ok(RoaIpAddressFamily { afi, addresses })
        })
    }
}
