//! Differences between two CCRs.
//!
//! Every sequence in a valid CCR is canonically ordered, so the difference
//! between two files is a linear merge with no hashing. Aspects whose
//! declared digests are equal are skipped outright. An aspect that is absent
//! on one side is compared as if it were empty; an aspect absent on both
//! sides yields `None`.
//!
//! The state types also offer plain set operations (`difference`,
//! `intersection`, `union`, `symmetric_difference`) over the same element
//! identities, returning the elements in canonical order.

use std::borrow::Cow;
use std::cmp::Ordering;
use std::collections::BTreeMap;

use chrono::{DateTime, Utc};

use crate::{
    Asn, AspaPayloadSet, AspaPayloadState, Ccr, KeyIdentifier, ManifestInstance, ManifestState,
    RoaPayloadState, RouterKey, RouterKeyState, TrustAnchorState, Vrp,
};

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

    /// The same difference seen from the other direction: added and removed
    /// swap places.
    pub fn reversed(&self) -> Self
    where
        T: Clone,
    {
        SetDiff {
            added: self.removed.clone(),
            removed: self.added.clone(),
            unchanged: self.unchanged,
        }
    }
}

/// Merges two sequences sorted ascending by `key` into a [`SetDiff`].
fn merge_by_key<T: Clone, K: Ord>(before: &[T], after: &[T], key: impl Fn(&T) -> K) -> SetDiff<T> {
    merge_by(before, after, |a, b| key(a).cmp(&key(b)))
}

/// Merges two sequences sorted ascending by `cmp` into a [`SetDiff`].
fn merge_by<T: Clone>(before: &[T], after: &[T], cmp: impl Fn(&T, &T) -> Ordering) -> SetDiff<T> {
    let mut diff = SetDiff::unchanged_only(0);
    let (mut i, mut j) = (0, 0);
    while i < before.len() && j < after.len() {
        match cmp(&before[i], &after[j]) {
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

/// Collects `items` and sorts them by `cmp` unless they already are, which
/// is always the case for a valid CCR.
fn sorted_by<T>(items: impl Iterator<Item = T>, cmp: impl Fn(&T, &T) -> Ordering) -> Vec<T> {
    let mut items: Vec<T> = items.collect();
    if !items.is_sorted_by(|a, b| cmp(a, b) != Ordering::Greater) {
        items.sort_by(&cmp);
    }
    items
}

/// Borrows `items` when they are sorted by `cmp`, otherwise a sorted copy.
fn canonical<'a, T: Clone>(items: &'a [T], cmp: impl Fn(&T, &T) -> Ordering) -> Cow<'a, [T]> {
    if items.is_sorted_by(|a, b| cmp(a, b) != Ordering::Greater) {
        Cow::Borrowed(items)
    } else {
        let mut copy = items.to_vec();
        copy.sort_by(&cmp);
        Cow::Owned(copy)
    }
}

/// A set operation over two sequences sorted by the same comparator.
#[derive(Clone, Copy)]
enum SetOp {
    Difference,
    Intersection,
    Union,
    SymmetricDifference,
}

/// Applies `op` to two sequences sorted ascending by `cmp`. On equal
/// elements the left one is kept.
fn set_op_by<T: Clone>(
    left: &[T],
    right: &[T],
    cmp: impl Fn(&T, &T) -> Ordering,
    op: SetOp,
) -> Vec<T> {
    use SetOp::*;
    let keep_left_only = matches!(op, Difference | Union | SymmetricDifference);
    let keep_right_only = matches!(op, Union | SymmetricDifference);
    let keep_common = matches!(op, Intersection | Union);
    let mut out = Vec::new();
    let (mut i, mut j) = (0, 0);
    while i < left.len() && j < right.len() {
        match cmp(&left[i], &right[j]) {
            Ordering::Less => {
                if keep_left_only {
                    out.push(left[i].clone());
                }
                i += 1;
            }
            Ordering::Greater => {
                if keep_right_only {
                    out.push(right[j].clone());
                }
                j += 1;
            }
            Ordering::Equal => {
                if keep_common {
                    out.push(left[i].clone());
                }
                i += 1;
                j += 1;
            }
        }
    }
    if keep_left_only {
        out.extend(left[i..].iter().cloned());
    }
    if keep_right_only {
        out.extend(right[j..].iter().cloned());
    }
    out
}

// ---- Comparators defining element identity ----------------------------------

fn cmp_manifest(a: &ManifestInstance, b: &ManifestInstance) -> Ordering {
    a.hash().cmp(b.hash())
}

fn cmp_vrp(a: &Vrp, b: &Vrp) -> Ordering {
    a.cmp(b)
}

fn cmp_aspa(a: &AspaPayloadSet, b: &AspaPayloadSet) -> Ordering {
    a.customer_as_id()
        .cmp(&b.customer_as_id())
        .then_with(|| a.providers().cmp(b.providers()))
}

fn cmp_ski(a: &KeyIdentifier, b: &KeyIdentifier) -> Ordering {
    a.cmp(b)
}

fn cmp_router_key(a: &(Asn, RouterKey), b: &(Asn, RouterKey)) -> Ordering {
    a.0.cmp(&b.0).then_with(|| a.1.ski().cmp(b.1.ski()))
}

/// Defines the four set operations on a state type in terms of a sorted
/// element vector and a comparator.
macro_rules! set_operations {
    ($state:ty, $elem:ty, $cmp:ident, |$this:ident| $elements:expr, $doc:literal) => {
        impl $state {
            fn canonical_elements(&self) -> Cow<'_, [$elem]> {
                let $this = self;
                $elements
            }

            fn set_op(&self, other: &Self, op: SetOp) -> Vec<$elem> {
                set_op_by(&self.canonical_elements(), &other.canonical_elements(), $cmp, op)
            }

            #[doc = concat!("Elements of `self` that `other` lacks, in canonical order. ", $doc)]
            pub fn difference(&self, other: &Self) -> Vec<$elem> {
                self.set_op(other, SetOp::Difference)
            }

            #[doc = concat!("Elements present in both, in canonical order (taken from `self`). ", $doc)]
            pub fn intersection(&self, other: &Self) -> Vec<$elem> {
                self.set_op(other, SetOp::Intersection)
            }

            #[doc = concat!("Elements present in either, in canonical order (`self`'s on ties). ", $doc)]
            pub fn union(&self, other: &Self) -> Vec<$elem> {
                self.set_op(other, SetOp::Union)
            }

            #[doc = concat!("Elements present in exactly one of the two, in canonical order. ", $doc)]
            pub fn symmetric_difference(&self, other: &Self) -> Vec<$elem> {
                self.set_op(other, SetOp::SymmetricDifference)
            }
        }
    };
}

set_operations!(
    ManifestState,
    ManifestInstance,
    cmp_manifest,
    |this| canonical(this.instances(), cmp_manifest),
    "Instances are identified by their hash."
);
set_operations!(
    RoaPayloadState,
    Vrp,
    cmp_vrp,
    |this| Cow::Owned(sorted_by(this.vrps(), cmp_vrp)),
    "VRPs are identified by AS number, prefix and maximum length."
);
set_operations!(
    AspaPayloadState,
    AspaPayloadSet,
    cmp_aspa,
    |this| canonical(this.sets(), cmp_aspa),
    "Sets are identified by customer AS and provider list."
);
set_operations!(
    TrustAnchorState,
    KeyIdentifier,
    cmp_ski,
    |this| canonical(this.skis(), cmp_ski),
    "Trust anchors are identified by key identifier."
);
set_operations!(
    RouterKeyState,
    (Asn, RouterKey),
    cmp_router_key,
    |this| Cow::Owned(sorted_by(
        this.router_keys().map(|(asn, key)| (asn, key.clone())),
        cmp_router_key
    )),
    "Router keys are identified by AS number and key identifier."
);

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

    /// The same change seen from the other direction.
    pub fn reversed(&self) -> Self {
        IssuerChange {
            aki: self.aki,
            before: self.after.clone(),
            after: self.before.clone(),
        }
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

    /// The same difference seen from the other direction.
    pub fn reversed(&self) -> Self {
        ManifestDiff {
            by_hash: self.by_hash.reversed(),
            issuers: self.issuers.iter().map(IssuerChange::reversed).collect(),
            unchanged_issuers: self.unchanged_issuers,
        }
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

    /// The same update seen from the other direction.
    pub fn reversed(&self) -> Self {
        AspaUpdate {
            before: self.after.clone(),
            after: self.before.clone(),
        }
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

    /// The same difference seen from the other direction.
    pub fn reversed(&self) -> Self {
        AspaPayloadDiff {
            added: self.removed.clone(),
            removed: self.added.clone(),
            updated: self.updated.iter().map(AspaUpdate::reversed).collect(),
            unchanged: self.unchanged,
        }
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
                let before = a.map_or(Cow::Borrowed(&[][..]), ManifestState::canonical_elements);
                let after = b.map_or(Cow::Borrowed(&[][..]), ManifestState::canonical_elements);
                Some(ManifestDiff::compute(&before, &after))
            }
        };
        let roa_payloads = match (before.roa_payloads(), after.roa_payloads()) {
            (None, None) => None,
            (Some(a), Some(b)) if a.hash() == b.hash() => {
                Some(SetDiff::unchanged_only(a.vrps().count()))
            }
            (a, b) => {
                let before = a.map_or(Cow::Borrowed(&[][..]), RoaPayloadState::canonical_elements);
                let after = b.map_or(Cow::Borrowed(&[][..]), RoaPayloadState::canonical_elements);
                Some(merge_by(&before, &after, cmp_vrp))
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
                let by_customer = |x: &AspaPayloadSet, y: &AspaPayloadSet| {
                    x.customer_as_id().cmp(&y.customer_as_id())
                };
                let before = a.map_or(Cow::Borrowed(&[][..]), |s| canonical(s.sets(), by_customer));
                let after = b.map_or(Cow::Borrowed(&[][..]), |s| canonical(s.sets(), by_customer));
                Some(AspaPayloadDiff::compute(&before, &after))
            }
        };
        let trust_anchors = match (before.trust_anchors(), after.trust_anchors()) {
            (None, None) => None,
            (Some(a), Some(b)) if a.hash() == b.hash() => Some(SetDiff::unchanged_only(a.len())),
            (a, b) => {
                let before = a.map_or(Cow::Borrowed(&[][..]), TrustAnchorState::canonical_elements);
                let after = b.map_or(Cow::Borrowed(&[][..]), TrustAnchorState::canonical_elements);
                Some(merge_by(&before, &after, cmp_ski))
            }
        };
        let router_keys = match (before.router_keys(), after.router_keys()) {
            (None, None) => None,
            (Some(a), Some(b)) if a.hash() == b.hash() => {
                Some(SetDiff::unchanged_only(a.router_keys().count()))
            }
            (a, b) => {
                let before = a.map_or(Cow::Borrowed(&[][..]), RouterKeyState::canonical_elements);
                let after = b.map_or(Cow::Borrowed(&[][..]), RouterKeyState::canonical_elements);
                Some(merge_by(&before, &after, cmp_router_key))
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

    /// The same difference seen from the other direction: `producedAt`s
    /// swap, added and removed swap, issuer and provider changes reverse.
    pub fn reversed(&self) -> Self {
        CcrDiff {
            before_produced_at: self.after_produced_at,
            after_produced_at: self.before_produced_at,
            manifests: self.manifests.as_ref().map(ManifestDiff::reversed),
            roa_payloads: self.roa_payloads.as_ref().map(SetDiff::reversed),
            aspa_payloads: self.aspa_payloads.as_ref().map(AspaPayloadDiff::reversed),
            trust_anchors: self.trust_anchors.as_ref().map(SetDiff::reversed),
            router_keys: self.router_keys.as_ref().map(SetDiff::reversed),
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
        assert_eq!(sorted_by([3, 1, 2].into_iter(), |a, b| a.cmp(b)), [1, 2, 3]);
        assert!(matches!(
            canonical(&[1, 2, 3], |a, b| a.cmp(b)),
            Cow::Borrowed(_)
        ));
        assert!(matches!(canonical(&[2, 1], |a, b| a.cmp(b)), Cow::Owned(_)));
    }

    #[test]
    fn set_operations_over_sorted_input() {
        let cmp = |a: &u8, b: &u8| a.cmp(b);
        let (l, r) = ([1u8, 3, 5, 7], [3u8, 4, 7, 9]);
        assert_eq!(set_op_by(&l, &r, cmp, SetOp::Difference), [1, 5]);
        assert_eq!(set_op_by(&l, &r, cmp, SetOp::Intersection), [3, 7]);
        assert_eq!(set_op_by(&l, &r, cmp, SetOp::Union), [1, 3, 4, 5, 7, 9]);
        assert_eq!(
            set_op_by(&l, &r, cmp, SetOp::SymmetricDifference),
            [1, 4, 5, 9]
        );
        assert_eq!(set_op_by(&l, &[], cmp, SetOp::Intersection), []);
        assert_eq!(set_op_by(&[], &r, cmp, SetOp::Union), r);
    }
}
