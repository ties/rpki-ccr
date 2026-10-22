//! `RouterKeyState`, `RouterKeySet` and `RouterKey`.

use bcder::decode::{Constructed, DecodeError, Source};

use crate::error::Aspect;
use crate::validate::HashedPayload;
use crate::{Asn, Digest, KeyIdentifier, SubjectPublicKeyInfo};
use std::collections::BTreeMap;

use bcder::encode::{self, Values};

use crate::Error;
use crate::encode::{digest_of, sort_dedup_by_key};

/// The current set of valid BGPsec router keys, grouped by AS.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RouterKeyState {
    sets: Vec<RouterKeySet>,
    hash: Digest,
}

impl RouterKeyState {
    /// The router key sets, in encoded order (ascending by AS number).
    pub fn sets(&self) -> &[RouterKeySet] {
        &self.sets
    }

    /// The digest declared over the DER-encoded `rksets` sequence.
    pub fn hash(&self) -> &Digest {
        &self.hash
    }

    /// The number of router key sets.
    pub fn len(&self) -> usize {
        self.sets.len()
    }

    /// Whether there are no router key sets.
    pub fn is_empty(&self) -> bool {
        self.sets.is_empty()
    }

    /// Iterates over all router keys with their AS number, in encoded order.
    pub fn router_keys(&self) -> impl Iterator<Item = (Asn, &RouterKey)> + '_ {
        self.sets
            .iter()
            .flat_map(|set| set.router_keys.iter().map(move |key| (set.as_id, key)))
    }

    pub(crate) fn take_from<S: Source>(
        cons: &mut Constructed<S>,
        hashed: &mut Vec<HashedPayload>,
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            let mut sets = Vec::new();
            let payload = cons.capture(|cons| {
                cons.take_sequence(|cons| {
                    while let Some(set) = RouterKeySet::take_opt_from(cons)? {
                        sets.push(set);
                    }
                    Ok(())
                })
            })?;
            let hash = Digest::take_from(cons)?;
            hashed.push(HashedPayload {
                aspect: Aspect::RouterKeys,
                payload,
                declared: hash,
            });
            Ok(RouterKeyState { sets, hash })
        })
    }
}

/// The router keys of one AS.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RouterKeySet {
    as_id: Asn,
    router_keys: Vec<RouterKey>,
}

impl RouterKeySet {
    /// The AS number.
    pub fn as_id(&self) -> Asn {
        self.as_id
    }

    /// The router keys (at least one), in encoded order (ascending by SKI).
    pub fn router_keys(&self) -> &[RouterKey] {
        &self.router_keys
    }

    pub(crate) fn take_opt_from<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Option<Self>, DecodeError<S::Error>> {
        cons.take_opt_sequence(|cons| {
            let as_id = Asn::take_from(cons)?;
            let router_keys = cons.take_sequence(|cons| {
                let mut keys = Vec::new();
                while let Some(key) = RouterKey::take_opt_from(cons)? {
                    keys.push(key);
                }
                Ok(keys)
            })?;
            if router_keys.is_empty() {
                return Err(cons.content_err("routerKeys must contain at least one RouterKey"));
            }
            Ok(RouterKeySet { as_id, router_keys })
        })
    }
}

/// A BGPsec router key: subject key identifier and public key.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RouterKey {
    ski: KeyIdentifier,
    spki: SubjectPublicKeyInfo,
}

impl RouterKey {
    /// The subject key identifier of the router certificate.
    pub fn ski(&self) -> &KeyIdentifier {
        &self.ski
    }

    /// The subject public key info of the router certificate.
    pub fn spki(&self) -> &SubjectPublicKeyInfo {
        &self.spki
    }

    pub(crate) fn take_opt_from<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Option<Self>, DecodeError<S::Error>> {
        cons.take_opt_sequence(|cons| {
            let ski = KeyIdentifier::take_from(cons)?;
            let spki = SubjectPublicKeyInfo::take_from(cons)?;
            Ok(RouterKey { ski, spki })
        })
    }
}

impl RouterKeyState {
    /// Builds a canonical state, merging sets with the same AS number.
    pub fn new(sets: Vec<RouterKeySet>) -> Result<Self, Error> {
        let mut by_asn: BTreeMap<Asn, Vec<RouterKey>> = BTreeMap::new();
        for set in sets {
            by_asn.entry(set.as_id).or_default().extend(set.router_keys);
        }
        let sets = by_asn
            .into_iter()
            .map(|(as_id, keys)| RouterKeySet::new(as_id, keys))
            .collect::<Result<Vec<_>, _>>()?;
        let mut state = RouterKeyState {
            sets,
            hash: Digest::from([0; 32]),
        };
        let hash = digest_of(&state.encode_payload());
        state.hash = hash;
        Ok(state)
    }

    fn encode_payload(&self) -> impl Values + '_ {
        encode::sequence(encode::iter(self.sets.iter().map(RouterKeySet::encode_ref)))
    }

    /// Returns a DER encoder for the `RouterKeyState` sequence.
    pub fn encode_ref(&self) -> impl Values + '_ {
        encode::sequence((self.encode_payload(), self.hash.encode_ref()))
    }
}

impl RouterKeySet {
    /// Creates a router key set from at least one key, sorted by SKI with
    /// duplicate SKIs removed.
    pub fn new(as_id: Asn, router_keys: Vec<RouterKey>) -> Result<Self, Error> {
        if router_keys.is_empty() {
            return Err(Error::invalid(format!(
                "router key set for AS {as_id} needs at least one key"
            )));
        }
        Ok(RouterKeySet {
            as_id,
            router_keys: sort_dedup_by_key(router_keys, |key| *key.ski()),
        })
    }

    /// Returns a DER encoder for the `RouterKeySet` sequence.
    pub fn encode_ref(&self) -> impl Values + '_ {
        encode::sequence((
            self.as_id.encode_ref(),
            encode::sequence(encode::iter(
                self.router_keys.iter().map(RouterKey::encode_ref),
            )),
        ))
    }
}

impl RouterKey {
    /// Creates a router key.
    pub fn new(ski: KeyIdentifier, spki: SubjectPublicKeyInfo) -> Self {
        RouterKey { ski, spki }
    }

    /// Returns a DER encoder for the `RouterKey` sequence.
    pub fn encode_ref(&self) -> impl Values + '_ {
        encode::sequence((self.ski.encode_ref(), self.spki.encode_ref()))
    }
}
