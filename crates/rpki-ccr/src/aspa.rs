//! `ASPAPayloadState` and `ASPAPayloadSet`.

use bcder::decode::{Constructed, DecodeError, Source};

use crate::error::Aspect;
use crate::validate::HashedPayload;
use crate::{Asn, Digest};
use std::collections::BTreeMap;

use bcder::encode::{self, Values};

use crate::Error;
use crate::encode::{digest_of, sort_dedup_by_key};

/// The current set of deduplicated and merged ASPA payloads.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AspaPayloadState {
    sets: Vec<AspaPayloadSet>,
    hash: Digest,
}

impl AspaPayloadState {
    /// The payload sets, in encoded order (ascending by customer AS).
    pub fn sets(&self) -> &[AspaPayloadSet] {
        &self.sets
    }

    /// The digest declared over the DER-encoded `aps` sequence.
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

    /// Decodes `ASPAPayloadState` (draft section 3.4.3): `aps` and the digest
    /// over the DER-encoded `aps`.
    pub(crate) fn take_from<S: Source>(
        cons: &mut Constructed<S>,
        hashed: &mut Vec<HashedPayload>,
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            let mut sets = Vec::new();
            let payload = cons.capture(|cons| {
                cons.take_sequence(|cons| {
                    while let Some(set) = AspaPayloadSet::take_opt_from(cons)? {
                        sets.push(set);
                    }
                    Ok(())
                })
            })?;
            let hash = Digest::take_from(cons)?;
            hashed.push(HashedPayload {
                aspect: Aspect::AspaPayloads,
                payload,
                declared: hash,
            });
            Ok(AspaPayloadState { sets, hash })
        })
    }
}

/// The provider set of one customer AS.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AspaPayloadSet {
    customer_as_id: Asn,
    providers: Vec<Asn>,
}

impl AspaPayloadSet {
    /// The customer AS number.
    pub fn customer_as_id(&self) -> Asn {
        self.customer_as_id
    }

    /// The provider AS numbers (at least one), in encoded order.
    pub fn providers(&self) -> &[Asn] {
        &self.providers
    }

    pub(crate) fn take_opt_from<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Option<Self>, DecodeError<S::Error>> {
        cons.take_opt_sequence(|cons| {
            let customer_as_id = Asn::take_from(cons)?;
            let providers = cons.take_sequence(|cons| {
                let mut providers = Vec::new();
                while let Some(provider) = Asn::take_opt_from(cons)? {
                    providers.push(provider);
                }
                Ok(providers)
            })?;
            // providers SEQUENCE (SIZE(1..MAX)) OF PAS (draft section 3).
            if providers.is_empty() {
                return Err(cons.content_err("providers must contain at least one AS number"));
            }
            Ok(AspaPayloadSet {
                customer_as_id,
                providers,
            })
        })
    }
}

impl AspaPayloadState {
    /// Builds a canonical state, merging the providers of sets with the same
    /// customer AS (draft section 3.4.3: deduplicated and merged, ordered by
    /// ascending `customerASID`).
    pub fn new(sets: Vec<AspaPayloadSet>) -> Result<Self, Error> {
        let mut by_customer: BTreeMap<Asn, Vec<Asn>> = BTreeMap::new();
        for set in sets {
            by_customer
                .entry(set.customer_as_id)
                .or_default()
                .extend(set.providers);
        }
        let sets = by_customer
            .into_iter()
            .map(|(customer, providers)| AspaPayloadSet::new(customer, providers))
            .collect::<Result<Vec<_>, _>>()?;
        let mut state = AspaPayloadState {
            sets,
            hash: Digest::from([0; 32]),
        };
        let hash = digest_of(&state.encode_payload());
        state.hash = hash;
        Ok(state)
    }

    pub(crate) fn encode_payload(&self) -> impl Values + '_ {
        encode::sequence(encode::iter(
            self.sets.iter().map(AspaPayloadSet::encode_ref),
        ))
    }

    /// Returns a DER encoder for the `ASPAPayloadState` sequence.
    pub fn encode_ref(&self) -> impl Values + '_ {
        encode::sequence((self.encode_payload(), self.hash.encode_ref()))
    }
}

impl AspaPayloadSet {
    /// Creates a payload set with sorted, deduplicated providers. AS 0 is
    /// only allowed as the sole provider (draft section 3.4.3).
    pub fn new(customer_as_id: Asn, providers: Vec<Asn>) -> Result<Self, Error> {
        // providers SEQUENCE (SIZE(1..MAX)) OF PAS (draft section 3).
        if providers.is_empty() {
            return Err(Error::invalid(format!(
                "ASPA payload set for customer AS {customer_as_id} needs at least one provider"
            )));
        }
        let providers = sort_dedup_by_key(providers, |provider| *provider);
        if providers.len() > 1 && providers[0] == Asn::new(0) {
            return Err(Error::invalid(format!(
                "customer AS {customer_as_id} lists AS 0 together with other providers"
            )));
        }
        Ok(AspaPayloadSet {
            customer_as_id,
            providers,
        })
    }

    /// Returns a DER encoder for the `ASPAPayloadSet` sequence.
    pub fn encode_ref(&self) -> impl Values + '_ {
        encode::sequence((
            self.customer_as_id.encode_ref(),
            encode::sequence(encode::iter(self.providers.iter().map(Asn::encode_ref))),
        ))
    }
}
