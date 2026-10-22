//! `ManifestState` and `ManifestInstance`.

use bcder::decode::{Constructed, DecodeError, Source};
use chrono::{DateTime, Utc};

use crate::error::Aspect;
use crate::time::take_generalized_time;
use crate::validate::HashedPayload;
use crate::{AccessDescription, Digest, KeyIdentifier, ManifestNumber};

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

    pub(crate) fn take_opt_from<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Option<Self>, DecodeError<S::Error>> {
        cons.take_opt_sequence(|cons| {
            let hash = Digest::take_from(cons)?;
            let size = cons.take_u64()?;
            if size < 1000 {
                return Err(cons.content_err("manifest size must be at least 1000 octets"));
            }
            let aki = KeyIdentifier::take_from(cons)?;
            let manifest_number = ManifestNumber::take_from(cons)?;
            let this_update = take_generalized_time(cons)?;
            let locations = cons.take_sequence(|cons| {
                let mut locations = Vec::new();
                while let Some(location) = AccessDescription::take_opt_from(cons)? {
                    locations.push(location);
                }
                Ok(locations)
            })?;
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
