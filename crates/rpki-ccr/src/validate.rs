//! Semantic validation of a decoded CCR.

use std::cmp::Ordering;

use bcder::Captured;

use crate::error::Aspect;
use crate::time::EPOCH;
use crate::{Asn, Ccr, DecodeOptions, Digest, Error};

/// The captured DER encoding of a hashed state payload together with the
/// digest declared for it.
pub(crate) struct HashedPayload {
    pub aspect: Aspect,
    pub payload: Captured,
    pub declared: Digest,
}

pub(crate) fn validate(
    ccr: &Ccr,
    hashed: &[HashedPayload],
    options: &DecodeOptions,
) -> Result<(), Error> {
    if options.verify_hashes {
        for item in hashed {
            let computed = Digest::sha256(item.payload.as_slice());
            if computed != item.declared {
                return Err(Error::HashMismatch {
                    aspect: item.aspect,
                    declared: item.declared,
                    computed,
                });
            }
        }
    }
    if options.check_ordering {
        check_ordering(ccr)?;
    }
    if options.check_consistency {
        check_consistency(ccr)?;
    }
    Ok(())
}

/// Checks that `items` are strictly ascending by `key`.
fn check_sorted<T, K: Ord>(
    items: &[T],
    key: impl Fn(&T) -> K,
    aspect: Aspect,
    what: &'static str,
) -> Result<(), Error> {
    for (index, pair) in items.windows(2).enumerate() {
        match key(&pair[0]).cmp(&key(&pair[1])) {
            Ordering::Less => {}
            Ordering::Equal => {
                return Err(Error::Duplicate {
                    aspect,
                    what,
                    index: index + 1,
                });
            }
            Ordering::Greater => {
                return Err(Error::NotSorted {
                    aspect,
                    what,
                    index: index + 1,
                });
            }
        }
    }
    Ok(())
}

fn check_ordering(ccr: &Ccr) -> Result<(), Error> {
    if let Some(state) = ccr.manifests() {
        check_sorted(
            state.instances(),
            |i| *i.hash(),
            Aspect::Manifests,
            "manifest instance hash",
        )?;
        for instance in state.instances() {
            check_sorted(
                instance.subordinates(),
                |ski| *ski,
                Aspect::Manifests,
                "subordinate key identifier",
            )?;
        }
    }
    if let Some(state) = ccr.roa_payloads() {
        check_sorted(
            state.sets(),
            |set| set.as_id(),
            Aspect::RoaPayloads,
            "ROA payload set AS number",
        )?;
        for set in state.sets() {
            check_sorted(
                set.ip_addr_blocks(),
                |b| b.afi(),
                Aspect::RoaPayloads,
                "address family",
            )?;
            for family in set.ip_addr_blocks() {
                check_sorted(
                    family.addresses(),
                    |a| (a.prefix(), a.effective_max_length()),
                    Aspect::RoaPayloads,
                    "ROA IP address",
                )?;
            }
        }
    }
    if let Some(state) = ccr.aspa_payloads() {
        check_sorted(
            state.sets(),
            |set| set.customer_as_id(),
            Aspect::AspaPayloads,
            "customer AS number",
        )?;
        for set in state.sets() {
            check_sorted(
                set.providers(),
                |p| *p,
                Aspect::AspaPayloads,
                "provider AS number",
            )?;
        }
    }
    if let Some(state) = ccr.trust_anchors() {
        check_sorted(
            state.skis(),
            |ski| *ski,
            Aspect::TrustAnchors,
            "trust anchor key identifier",
        )?;
    }
    if let Some(state) = ccr.router_keys() {
        check_sorted(
            state.sets(),
            |set| set.as_id(),
            Aspect::RouterKeys,
            "router key set AS number",
        )?;
        for set in state.sets() {
            check_sorted(
                set.router_keys(),
                |key| *key.ski(),
                Aspect::RouterKeys,
                "router key identifier",
            )?;
        }
    }
    Ok(())
}

fn check_consistency(ccr: &Ccr) -> Result<(), Error> {
    if let Some(state) = ccr.manifests() {
        let newest = state.instances().iter().map(|i| i.this_update()).max();
        let expected = newest.unwrap_or(EPOCH);
        if state.most_recent_update() != expected {
            let detail = match newest {
                Some(newest) => format!(
                    "mostRecentUpdate {} does not match the most recent manifest thisUpdate {}",
                    state.most_recent_update(),
                    newest
                ),
                None => format!(
                    "mostRecentUpdate {} must be the POSIX epoch when there are no manifest instances",
                    state.most_recent_update()
                ),
            };
            return Err(Error::Consistency {
                aspect: Aspect::Manifests,
                detail,
            });
        }
        if state.most_recent_update() > ccr.produced_at() {
            return Err(Error::Consistency {
                aspect: Aspect::Manifests,
                detail: format!(
                    "mostRecentUpdate {} is later than producedAt {}",
                    state.most_recent_update(),
                    ccr.produced_at()
                ),
            });
        }
    }
    if let Some(state) = ccr.aspa_payloads() {
        for set in state.sets() {
            if set.providers().len() > 1 && set.providers().contains(&Asn::new(0)) {
                return Err(Error::Consistency {
                    aspect: Aspect::AspaPayloads,
                    detail: format!(
                        "customer AS {} lists AS 0 together with other providers",
                        set.customer_as_id()
                    ),
                });
            }
        }
    }
    Ok(())
}
