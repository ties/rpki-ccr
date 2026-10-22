//! `ManifestState` and `ManifestInstance`.

use bcder::decode::{Constructed, DecodeError, Source};
use chrono::{DateTime, Utc};

use crate::error::Aspect;
use crate::time::take_generalized_time;
use crate::validate::HashedPayload;
use crate::{AccessDescription, Digest, KeyIdentifier, ManifestNumber};
use bcder::encode::{self, PrimitiveContent as _, Values};

use crate::Error;
use crate::encode::{GeneralizedTime, digest_of, sort_dedup, sort_dedup_by_key};
use crate::time::{EPOCH, check_encodable};

/// The set of valid, current manifests in the cache.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ManifestState {
    instances: Vec<ManifestInstance>,
    most_recent_update: DateTime<Utc>,
    hash: Digest,
}

impl ManifestState {
    /// The manifest instances, in encoded order (ascending by hash).
    pub fn instances(&self) -> &[ManifestInstance] {
        &self.instances
    }

    /// The most recent `thisUpdate` among the instances, or the POSIX epoch
    /// when there are none.
    pub fn most_recent_update(&self) -> DateTime<Utc> {
        self.most_recent_update
    }

    /// The digest declared over the DER-encoded `mis` sequence.
    pub fn hash(&self) -> &Digest {
        &self.hash
    }

    /// The number of manifest instances.
    pub fn len(&self) -> usize {
        self.instances.len()
    }

    /// Whether there are no manifest instances.
    pub fn is_empty(&self) -> bool {
        self.instances.is_empty()
    }

    /// Decodes `ManifestState` (draft section 3.4.1): `mis`, `mostRecentUpdate`
    /// and the digest over the DER-encoded `mis` (section 3.4.1.3).
    pub(crate) fn take_from<S: Source>(
        cons: &mut Constructed<S>,
        hashed: &mut Vec<HashedPayload>,
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            let mut instances = Vec::new();
            let payload = cons.capture(|cons| {
                cons.take_sequence(|cons| {
                    while let Some(instance) = ManifestInstance::take_opt_from(cons)? {
                        instances.push(instance);
                    }
                    Ok(())
                })
            })?;
            let most_recent_update = take_generalized_time(cons)?;
            let hash = Digest::take_from(cons)?;
            hashed.push(HashedPayload {
                aspect: Aspect::Manifests,
                payload,
                declared: hash,
            });
            Ok(ManifestState {
                instances,
                most_recent_update,
                hash,
            })
        })
    }
}

/// A current manifest together with the CA certificates subordinate to its
/// issuer.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ManifestInstance {
    hash: Digest,
    size: u64,
    aki: KeyIdentifier,
    manifest_number: ManifestNumber,
    this_update: DateTime<Utc>,
    locations: Vec<AccessDescription>,
    subordinates: Vec<KeyIdentifier>,
}

impl ManifestInstance {
    /// The SHA-256 digest of the DER-encoded manifest object.
    pub fn hash(&self) -> &Digest {
        &self.hash
    }

    /// The size of the DER-encoded manifest object in octets.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// The key identifier of the manifest issuer.
    pub fn aki(&self) -> &KeyIdentifier {
        &self.aki
    }

    /// The manifest number.
    pub fn manifest_number(&self) -> &ManifestNumber {
        &self.manifest_number
    }

    /// The `thisUpdate` time of the manifest.
    pub fn this_update(&self) -> DateTime<Utc> {
        self.this_update
    }

    /// The SIA access descriptions of the manifest's EE certificate
    /// (at least one).
    pub fn locations(&self) -> &[AccessDescription] {
        &self.locations
    }

    /// The key identifiers of the valid CA certificates subordinate to the
    /// manifest issuer; empty when the `subordinates` field is absent.
    pub fn subordinates(&self) -> &[KeyIdentifier] {
        &self.subordinates
    }

    /// Decodes `ManifestInstance` (draft section 3.4.1.1).
    pub(crate) fn take_opt_from<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Option<Self>, DecodeError<S::Error>> {
        cons.take_opt_sequence(|cons| {
            let hash = Digest::take_from(cons)?;
            let size = cons.take_u64()?;
            // size INTEGER (1000..MAX) (draft section 3, ASN.1 module).
            if size < 1000 {
                return Err(cons.content_err("manifest size must be at least 1000 octets"));
            }
            let aki = KeyIdentifier::take_from(cons)?;
            // manifestNumber INTEGER (0..MAX) of at most 20 octets (draft sections 3 and 6).
            let manifest_number = ManifestNumber::take_from(cons)?;
            let this_update = take_generalized_time(cons)?;
            let locations = cons.take_sequence(|cons| {
                let mut locations = Vec::new();
                while let Some(location) = AccessDescription::take_opt_from(cons)? {
                    locations.push(location);
                }
                Ok(locations)
            })?;
            // locations SEQUENCE (SIZE(1..MAX)) OF AccessDescription (draft section 3):
            // the SIA of the manifest's EE certificate (section 3.4.1.1).
            if locations.is_empty() {
                return Err(
                    cons.content_err("locations must contain at least one AccessDescription")
                );
            }
            let subordinates = cons.take_opt_sequence(|cons| {
                let mut subordinates = Vec::new();
                while let Some(ski) = KeyIdentifier::take_opt_from(cons)? {
                    subordinates.push(ski);
                }
                Ok(subordinates)
            })?;
            let subordinates = match subordinates {
                // subordinates is OPTIONAL but SIZE(1..MAX) when present (draft section 3).
                Some(list) if list.is_empty() => {
                    return Err(cons.content_err("subordinates must not be empty when present"));
                }
                Some(list) => list,
                None => Vec::new(),
            };
            Ok(ManifestInstance {
                hash,
                size,
                aki,
                manifest_number,
                this_update,
                locations,
                subordinates,
            })
        })
    }
}

impl ManifestState {
    /// Builds a canonical manifest state: instances sorted by hash with
    /// duplicates removed, `mostRecentUpdate` derived from the instances and
    /// the digest computed over the DER-encoded `mis` sequence.
    ///
    /// Draft sections 3.4.1.1 (ascending by hash, unique), 3.4.1.2
    /// (`mostRecentUpdate`, the POSIX epoch when `mis` is empty) and 3.4.1.3
    /// (the digest).
    pub fn new(instances: Vec<ManifestInstance>) -> Self {
        let instances = sort_dedup_by_key(instances, |instance| *instance.hash());
        let most_recent_update = instances
            .iter()
            .map(ManifestInstance::this_update)
            .max()
            .unwrap_or(EPOCH);
        let mut state = ManifestState {
            instances,
            most_recent_update,
            hash: Digest::from([0; 32]),
        };
        let hash = digest_of(&state.encode_payload());
        state.hash = hash;
        state
    }

    pub(crate) fn encode_payload(&self) -> impl Values + '_ {
        encode::sequence(encode::iter(
            self.instances.iter().map(ManifestInstance::encode_ref),
        ))
    }

    /// Returns a DER encoder for the `ManifestState` sequence.
    pub fn encode_ref(&self) -> impl Values + '_ {
        encode::sequence((
            self.encode_payload(),
            GeneralizedTime(self.most_recent_update).encode(),
            self.hash.encode_ref(),
        ))
    }
}

impl ManifestInstance {
    /// Creates a manifest instance. Subordinates are sorted and deduplicated
    /// as the specification requires. Locations are sorted lexicographically
    /// (by access method, then URI) and deduplicated.
    ///
    /// Multiple `locations` per manifest instance are currently not defined:
    /// the specification orders every other sequence but says nothing about
    /// this one, and in practice an RPKI manifest's EE certificate carries
    /// exactly one SIA access location. A later profile could define a
    /// semantic order (for example the order of the SIA extension in the
    /// certificate), so the sort is not a canonical form, just a safe
    /// default that keeps the encoder output deterministic. Decoded
    /// instances keep their encoded order so that re-encoding is exact.
    ///
    /// Subordinates are ordered as unsigned 160-bit integers and unique
    /// (draft section 3.4.1.1); `size` must be at least 1000 (section 3).
    pub fn new(
        hash: Digest,
        size: u64,
        aki: KeyIdentifier,
        manifest_number: ManifestNumber,
        this_update: DateTime<Utc>,
        locations: Vec<AccessDescription>,
        subordinates: Vec<KeyIdentifier>,
    ) -> Result<Self, Error> {
        // size INTEGER (1000..MAX) (draft section 3, ASN.1 module).
        if size < 1000 {
            return Err(Error::invalid(format!(
                "manifest size {size} is below the minimum of 1000 octets"
            )));
        }
        // locations SEQUENCE (SIZE(1..MAX)) OF AccessDescription (draft section 3):
        // the SIA of the manifest's EE certificate (section 3.4.1.1).
        if locations.is_empty() {
            return Err(Error::invalid(
                "a manifest instance needs at least one location",
            ));
        }
        check_encodable(this_update)?;
        Ok(ManifestInstance {
            hash,
            size,
            aki,
            manifest_number,
            this_update,
            // Not specified by the draft; lexicographic is only a safe default.
            locations: sort_dedup(locations),
            subordinates: sort_dedup_by_key(subordinates, |ski| *ski),
        })
    }

    /// Returns a DER encoder for the `ManifestInstance` sequence.
    pub fn encode_ref(&self) -> impl Values + '_ {
        encode::sequence((
            self.hash.encode_ref(),
            self.size.encode(),
            self.aki.encode_ref(),
            self.manifest_number.encode_ref(),
            GeneralizedTime(self.this_update).encode(),
            encode::sequence(encode::iter(
                self.locations.iter().map(AccessDescription::encode_ref),
            )),
            (!self.subordinates.is_empty()).then(|| {
                encode::sequence(encode::iter(
                    self.subordinates.iter().map(KeyIdentifier::encode_ref),
                ))
            }),
        ))
    }
}
