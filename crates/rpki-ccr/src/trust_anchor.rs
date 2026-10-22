//! `TrustAnchorState`.

use bcder::decode::{Constructed, DecodeError, Source};

use crate::error::Aspect;
use crate::validate::HashedPayload;
use crate::{Digest, KeyIdentifier};
use bcder::encode::{self, Values};

use crate::Error;
use crate::encode::{digest_of, sort_dedup_by_key};

/// The set of valid trust anchor CA certificates used by the relying party.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TrustAnchorState {
    skis: Vec<KeyIdentifier>,
    hash: Digest,
}

impl TrustAnchorState {
    /// The subject key identifiers of the trust anchors (at least one), in
    /// encoded order (ascending).
    pub fn skis(&self) -> &[KeyIdentifier] {
        &self.skis
    }

    /// The digest declared over the DER-encoded `skis` sequence.
    pub fn hash(&self) -> &Digest {
        &self.hash
    }

    /// The number of trust anchors.
    pub fn len(&self) -> usize {
        self.skis.len()
    }

    /// Whether there are no trust anchors (never the case for a valid file).
    pub fn is_empty(&self) -> bool {
        self.skis.is_empty()
    }

    pub(crate) fn take_from<S: Source>(
        cons: &mut Constructed<S>,
        hashed: &mut Vec<HashedPayload>,
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            let mut skis = Vec::new();
            let payload = cons.capture(|cons| {
                cons.take_sequence(|cons| {
                    while let Some(ski) = KeyIdentifier::take_opt_from(cons)? {
                        skis.push(ski);
                    }
                    Ok(())
                })
            })?;
            if skis.is_empty() {
                return Err(cons.content_err("skis must contain at least one SubjectKeyIdentifier"));
            }
            let hash = Digest::take_from(cons)?;
            hashed.push(HashedPayload {
                aspect: Aspect::TrustAnchors,
                payload,
                declared: hash,
            });
            Ok(TrustAnchorState { skis, hash })
        })
    }
}

impl TrustAnchorState {
    /// Builds a canonical state from at least one key identifier, sorted
    /// and deduplicated.
    pub fn new(skis: Vec<KeyIdentifier>) -> Result<Self, Error> {
        if skis.is_empty() {
            return Err(Error::invalid(
                "trust anchor state needs at least one key identifier",
            ));
        }
        let mut state = TrustAnchorState {
            skis: sort_dedup_by_key(skis, |ski| *ski),
            hash: Digest::from([0; 32]),
        };
        let hash = digest_of(&state.encode_payload());
        state.hash = hash;
        Ok(state)
    }

    fn encode_payload(&self) -> impl Values + '_ {
        encode::sequence(encode::iter(
            self.skis.iter().map(KeyIdentifier::encode_ref),
        ))
    }

    /// Returns a DER encoder for the `TrustAnchorState` sequence.
    pub fn encode_ref(&self) -> impl Values + '_ {
        encode::sequence((self.encode_payload(), self.hash.encode_ref()))
    }
}
