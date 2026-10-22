//! `ASPAPayloadState` and `ASPAPayloadSet`.

use bcder::decode::{Constructed, DecodeError, Source};

use crate::error::Aspect;
use crate::validate::HashedPayload;
use crate::{Asn, Digest};

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
