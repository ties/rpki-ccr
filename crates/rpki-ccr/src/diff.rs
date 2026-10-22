//! Differences between two CCRs.
//!
//! Every sequence in a valid CCR is canonically ordered, so the difference
//! between two files is a linear merge with no hashing. Aspects whose
//! declared digests are equal are skipped outright. An aspect that is absent
//! on one side is compared as if it were empty; an aspect absent on both
//! sides yields `None`.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use chrono::{DateTime, Utc};

use crate::{Asn, AspaPayloadSet, Ccr, KeyIdentifier, ManifestInstance, RouterKey, Vrp};

/// The difference between two sets, as computed by [`Ccr::diff`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SetDiff<T> {
    added: Vec<T>,
    removed: Vec<T>,
    unchanged: usize,
}

impl<T> SetDiff<T> {
    fn unchanged_only(unchanged: usize) -> Self {
        SetDiff {
            added: Vec::new(),
            removed: Vec::new(),
            unchanged,
        }
    }

    /// Elements present in the newer CCR only, in canonical order.
    pub fn added(&self) -> &[T] {
        &self.added
    }

    /// Elements present in the older CCR only, in canonical order.
    pub fn removed(&self) -> &[T] {
        &self.removed
    }

    /// The number of elements present in both.
    pub fn unchanged(&self) -> usize {
        self.unchanged
    }

    /// Whether nothing was added or removed.
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty()
    }
}

/// Merges two sequences sorted ascending by `key` into a [`SetDiff`].
fn merge_by_key<T: Clone, K: Ord>(before: &[T], after: &[T], key: impl Fn(&T) -> K) -> SetDiff<T> {
    let mut diff = SetDiff::unchanged_only(0);
    let (mut i, mut j) = (0, 0);
    while i < before.len() && j < after.len() {
        match key(&before[i]).cmp(&key(&after[j])) {
            Ordering::Less => {
                diff.removed.push(before[i].clone());
                i += 1;
            }
            Ordering::Greater => {
                diff.added.push(after[j].clone());
                j += 1;
            }
            Ordering::Equal => {
                diff.unchanged += 1;
                i += 1;
                j += 1;
            }
        }
    }
    diff.removed.extend(before[i..].iter().cloned());
    diff.added.extend(after[j..].iter().cloned());
    diff
}

/// Collects `items` and sorts them by `key` unless they already are, which
/// is always the case for a valid CCR.
fn sorted_by_key<T, K: Ord>(items: impl Iterator<Item = T>, key: impl Fn(&T) -> K) -> Vec<T> {
    let mut items: Vec<T> = items.collect();
    if !items.is_sorted_by_key(&key) {
        items.sort_by_key(&key);
    }
    items
}

/// How the manifests of one issuer changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ChangeKind {
    /// The issuer has manifests in the newer CCR only.
    Added,
    /// The issuer has manifests in the older CCR only.
    Removed,
    /// The issuer has manifests in both, but not the same ones.
    Updated,
}

/// The manifests of one issuer (AKI) before and after.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct IssuerChange {
    aki: KeyIdentifier,
    before: Vec<ManifestInstance>,
    after: Vec<ManifestInstance>,
}

impl IssuerChange {
    /// The issuer's key identifier.
    pub fn aki(&self) -> &KeyIdentifier {
        &self.aki
    }

    /// The issuer's manifest instances in the older CCR (usually one).
    pub fn before(&self) -> &[ManifestInstance] {
        &self.before
    }

    /// The issuer's manifest instances in the newer CCR (usually one).
    pub fn after(&self) -> &[ManifestInstance] {
        &self.after
    }

    /// Whether the issuer appeared, disappeared or published new manifests.
    pub fn kind(&self) -> ChangeKind {
        if self.before.is_empty() {
            ChangeKind::Added
        } else if self.after.is_empty() {
            ChangeKind::Removed
        } else {
            ChangeKind::Updated
        }
    }
}

/// The difference between two manifest states, in two views: by manifest
/// hash (plain set membership) and by issuer (grouped by AKI).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ManifestDiff {
    by_hash: SetDiff<ManifestInstance>,
    issuers: Vec<IssuerChange>,
    unchanged_issuers: usize,
}

impl ManifestDiff {
    fn compute(before: &[ManifestInstance], after: &[ManifestInstance]) -> Self {
        let by_hash = merge_by_key(before, after, |mi| *mi.hash());
        let group = |instances: &[ManifestInstance]| {
            let mut groups: BTreeMap<KeyIdentifier, Vec<ManifestInstance>> = BTreeMap::new();
            for mi in instances {
                groups.entry(*mi.aki()).or_default().push(mi.clone());
            }
            for group in groups.values_mut() {
                group.sort_by_key(|mi| *mi.hash());
            }
            groups
        };
        let mut before_groups = group(before);
        let mut after_groups = group(after);
        let mut issuers = Vec::new();
        let mut unchanged_issuers = 0;
        let akis: Vec<KeyIdentifier> = before_groups
            .keys()
            .chain(after_groups.keys())
            .copied()
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        for aki in akis {
            let before = before_groups.remove(&aki).unwrap_or_default();
            let after = after_groups.remove(&aki).unwrap_or_default();
            let same = before.len() == after.len()
                && before.iter().zip(&after).all(|(a, b)| a.hash() == b.hash());
            if same {
                unchanged_issuers += 1;
            } else {
                issuers.push(IssuerChange { aki, before, after });
            }
        }
        ManifestDiff {
            by_hash,
            issuers,
            unchanged_issuers,
        }
    }

    /// Manifest instances present in the newer CCR only (by hash).
    pub fn added(&self) -> &[ManifestInstance] {
        self.by_hash.added()
    }

    /// Manifest instances present in the older CCR only (by hash).
    pub fn removed(&self) -> &[ManifestInstance] {
        self.by_hash.removed()
    }

    /// The number of manifest instances present in both (by hash).
    pub fn unchanged(&self) -> usize {
        self.by_hash.unchanged()
    }

    /// The set view by hash.
    pub fn by_hash(&self) -> &SetDiff<ManifestInstance> {
        &self.by_hash
    }

    /// Issuers whose manifests changed, appeared or disappeared, ascending by AKI.
    pub fn issuers(&self) -> &[IssuerChange] {
        &self.issuers
    }

    /// The number of issuers with exactly the same manifests in both.
    pub fn unchanged_issuers(&self) -> usize {
        self.unchanged_issuers
    }

    /// Whether nothing changed.
    pub fn is_empty(&self) -> bool {
        self.by_hash.is_empty()
    }
}

/// A customer AS whose provider set changed.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AspaUpdate {
    before: AspaPayloadSet,
    after: AspaPayloadSet,
}

impl AspaUpdate {
    /// The customer AS number.
    pub fn customer_as_id(&self) -> Asn {
        self.after.customer_as_id()
    }

    /// The payload set in the older CCR.
    pub fn before(&self) -> &AspaPayloadSet {
        &self.before
    }

    /// The payload set in the newer CCR.
    pub fn after(&self) -> &AspaPayloadSet {
        &self.after
    }

    /// Providers present in the newer set only.
    pub fn providers_added(&self) -> Vec<Asn> {
        merge_by_key(self.before.providers(), self.after.providers(), |p| *p).added
    }

    /// Providers present in the older set only.
    pub fn providers_removed(&self) -> Vec<Asn> {
        merge_by_key(self.before.providers(), self.after.providers(), |p| *p).removed
    }
}

/// The difference between two ASPA payload states, keyed by customer AS.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AspaPayloadDiff {
    added: Vec<AspaPayloadSet>,
    removed: Vec<AspaPayloadSet>,
    updated: Vec<AspaUpdate>,
    unchanged: usize,
}

impl AspaPayloadDiff {
    fn compute(before: &[AspaPayloadSet], after: &[AspaPayloadSet]) -> Self {
        let mut diff = AspaPayloadDiff {
            added: Vec::new(),
            removed: Vec::new(),
            updated: Vec::new(),
            unchanged: 0,
        };
        let (mut i, mut j) = (0, 0);
        while i < before.len() && j < after.len() {
            match before[i].customer_as_id().cmp(&after[j].customer_as_id()) {
                Ordering::Less => {
                    diff.removed.push(before[i].clone());
                    i += 1;
                }
                Ordering::Greater => {
                    diff.added.push(after[j].clone());
                    j += 1;
                }
                Ordering::Equal => {
                    if before[i].providers() == after[j].providers() {
                        diff.unchanged += 1;
                    } else {
                        diff.updated.push(AspaUpdate {
                            before: before[i].clone(),
                            after: after[j].clone(),
                        });
                    }
                    i += 1;
                    j += 1;
                }
            }
        }
        diff.removed.extend(before[i..].iter().cloned());
        diff.added.extend(after[j..].iter().cloned());
        diff
    }

    /// Customers present in the newer CCR only.
    pub fn added(&self) -> &[AspaPayloadSet] {
        &self.added
    }

    /// Customers present in the older CCR only.
    pub fn removed(&self) -> &[AspaPayloadSet] {
        &self.removed
    }

    /// Customers present in both with different providers.
    pub fn updated(&self) -> &[AspaUpdate] {
        &self.updated
    }

    /// The number of customers with identical providers in both.
    pub fn unchanged(&self) -> usize {
        self.unchanged
    }

    /// Whether nothing changed.
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.updated.is_empty()
    }
}

/// The difference between two CCRs, from an older one to a newer one.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CcrDiff {
    before_produced_at: DateTime<Utc>,
    after_produced_at: DateTime<Utc>,
    manifests: Option<ManifestDiff>,
    roa_payloads: Option<SetDiff<Vrp>>,
    aspa_payloads: Option<AspaPayloadDiff>,
    trust_anchors: Option<SetDiff<KeyIdentifier>>,
    router_keys: Option<SetDiff<(Asn, RouterKey)>>,
}

impl CcrDiff {
    pub(crate) fn compute(before: &Ccr, after: &Ccr) -> Self {
        let manifests = match (before.manifests(), after.manifests()) {
            (None, None) => None,
            (Some(a), Some(b)) if a.hash() == b.hash() => Some(ManifestDiff {
                by_hash: SetDiff::unchanged_only(a.len()),
                issuers: Vec::new(),
                unchanged_issuers: a
                    .instances()
                    .iter()
                    .map(ManifestInstance::aki)
                    .collect::<std::collections::BTreeSet<_>>()
                    .len(),
            }),
            (a, b) => {
                let before =
                    sorted_by_key(a.map_or(&[][..], |s| s.instances()).iter().cloned(), |mi| {
                        *mi.hash()
                    });
                let after =
                    sorted_by_key(b.map_or(&[][..], |s| s.instances()).iter().cloned(), |mi| {
                        *mi.hash()
                    });
                Some(ManifestDiff::compute(&before, &after))
            }
        };
        let roa_payloads = match (before.roa_payloads(), after.roa_payloads()) {
            (None, None) => None,
            (Some(a), Some(b)) if a.hash() == b.hash() => {
                Some(SetDiff::unchanged_only(a.vrps().count()))
            }
            (a, b) => {
                let before = sorted_by_key(a.into_iter().flat_map(|s| s.vrps()), |v| *v);
                let after = sorted_by_key(b.into_iter().flat_map(|s| s.vrps()), |v| *v);
                Some(merge_by_key(&before, &after, |v| *v))
            }
        };
        let aspa_payloads = match (before.aspa_payloads(), after.aspa_payloads()) {
            (None, None) => None,
            (Some(a), Some(b)) if a.hash() == b.hash() => Some(AspaPayloadDiff {
                added: Vec::new(),
                removed: Vec::new(),
                updated: Vec::new(),
                unchanged: a.len(),
            }),
            (a, b) => {
                let key = |set: &AspaPayloadSet| set.customer_as_id();
                let before = sorted_by_key(a.map_or(&[][..], |s| s.sets()).iter().cloned(), key);
                let after = sorted_by_key(b.map_or(&[][..], |s| s.sets()).iter().cloned(), key);
                Some(AspaPayloadDiff::compute(&before, &after))
            }
        };
        let trust_anchors = match (before.trust_anchors(), after.trust_anchors()) {
            (None, None) => None,
            (Some(a), Some(b)) if a.hash() == b.hash() => Some(SetDiff::unchanged_only(a.len())),
            (a, b) => {
                let before = sorted_by_key(a.map_or(&[][..], |s| s.skis()).iter().copied(), |k| *k);
                let after = sorted_by_key(b.map_or(&[][..], |s| s.skis()).iter().copied(), |k| *k);
                Some(merge_by_key(&before, &after, |k| *k))
            }
        };
        let router_keys = match (before.router_keys(), after.router_keys()) {
            (None, None) => None,
            (Some(a), Some(b)) if a.hash() == b.hash() => {
                Some(SetDiff::unchanged_only(a.router_keys().count()))
            }
            (a, b) => {
                let key = |(asn, key): &(Asn, RouterKey)| (*asn, *key.ski());
                let entries = |state: Option<&crate::RouterKeyState>| {
                    sorted_by_key(
                        state
                            .into_iter()
                            .flat_map(|s| s.router_keys().map(|(asn, key)| (asn, key.clone()))),
                        key,
                    )
                };
                Some(merge_by_key(&entries(a), &entries(b), key))
            }
        };
        CcrDiff {
            before_produced_at: before.produced_at(),
            after_produced_at: after.produced_at(),
            manifests,
            roa_payloads,
            aspa_payloads,
            trust_anchors,
            router_keys,
        }
    }

    /// `producedAt` of the older CCR.
    pub fn before_produced_at(&self) -> DateTime<Utc> {
        self.before_produced_at
    }

    /// `producedAt` of the newer CCR.
    pub fn after_produced_at(&self) -> DateTime<Utc> {
        self.after_produced_at
    }

    /// The manifest difference, unless both CCRs lack the aspect.
    pub fn manifests(&self) -> Option<&ManifestDiff> {
        self.manifests.as_ref()
    }

    /// The VRP difference, unless both CCRs lack the aspect.
    pub fn roa_payloads(&self) -> Option<&SetDiff<Vrp>> {
        self.roa_payloads.as_ref()
    }

    /// The ASPA difference, unless both CCRs lack the aspect.
    pub fn aspa_payloads(&self) -> Option<&AspaPayloadDiff> {
        self.aspa_payloads.as_ref()
    }

    /// The trust anchor difference, unless both CCRs lack the aspect.
    pub fn trust_anchors(&self) -> Option<&SetDiff<KeyIdentifier>> {
        self.trust_anchors.as_ref()
    }

    /// The router key difference as `(AS, key)` entries, unless both CCRs
    /// lack the aspect.
    pub fn router_keys(&self) -> Option<&SetDiff<(Asn, RouterKey)>> {
        self.router_keys.as_ref()
    }

    /// Whether no aspect changed (`producedAt` is not considered).
    pub fn is_empty(&self) -> bool {
        self.manifests.as_ref().is_none_or(ManifestDiff::is_empty)
            && self.roa_payloads.as_ref().is_none_or(SetDiff::is_empty)
            && self
                .aspa_payloads
                .as_ref()
                .is_none_or(AspaPayloadDiff::is_empty)
            && self.trust_anchors.as_ref().is_none_or(SetDiff::is_empty)
            && self.router_keys.as_ref().is_none_or(SetDiff::is_empty)
    }
}

impl Ccr {
    /// Computes the changes from `self` (the older CCR) to `after`.
    ///
    /// Each aspect is a linear merge over the canonical order; aspects with
    /// equal digests are skipped. Objects decoded with ordering checks
    /// switched off are sorted first.
    pub fn diff(&self, after: &Ccr) -> CcrDiff {
        CcrDiff::compute(self, after)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_handles_disjoint_and_overlapping_input() {
        let diff = merge_by_key(&[1, 3, 5, 7], &[3, 4, 7, 9], |x| *x);
        assert_eq!(diff.added(), &[4, 9]);
        assert_eq!(diff.removed(), &[1, 5]);
        assert_eq!(diff.unchanged(), 2);
        let diff = merge_by_key(&[], &[1], |x| *x);
        assert_eq!(
            (diff.added(), diff.removed(), diff.unchanged()),
            (&[1][..], &[][..], 0)
        );
        assert!(merge_by_key::<u8, u8>(&[], &[], |x| *x).is_empty());
    }

    #[test]
    fn sorts_unsorted_input() {
        assert_eq!(sorted_by_key([3, 1, 2].into_iter(), |x| *x), [1, 2, 3]);
    }
}
