//! `Ccr::diff`: set and issuer views.

mod common;

use chrono::{TimeZone, Utc};
use common::*;
use rpki_ccr::{
    Asn, AspaPayloadSet, AspaPayloadState, Ccr, ChangeKind, Digest, KeyIdentifier,
    ManifestInstance, ManifestNumber, ManifestState, RoaPayloadState, RouterKeyState,
    TrustAnchorState, ValidationOptions,
};

const DATA: &[u8] = include_bytes!("data/example.ccr");
const MULTI: &[u8] = include_bytes!("data/multi-location.ccr");

fn ki(hex: &str) -> KeyIdentifier {
    KeyIdentifier::from_hex(hex).unwrap()
}

#[test]
fn identical_ccrs_have_an_empty_diff() {
    let a = Ccr::decode(DATA).unwrap();
    let diff = a.diff(&a);
    assert!(diff.is_empty());
    assert_eq!(diff.before_produced_at(), diff.after_produced_at());
    let manifests = diff.manifests().unwrap();
    assert!(manifests.is_empty());
    assert_eq!(
        (manifests.unchanged(), manifests.unchanged_issuers()),
        (4, 4)
    );
    assert!(manifests.issuers().is_empty());
    assert_eq!(diff.roa_payloads().unwrap().unchanged(), 5);
    assert_eq!(diff.aspa_payloads().unwrap().unchanged(), 3);
    assert_eq!(diff.trust_anchors().unwrap().unchanged(), 2);
    assert_eq!(diff.router_keys().unwrap().unchanged(), 3);
}

#[test]
fn example_to_multi_location_fixture() {
    let before = Ccr::decode(DATA).unwrap();
    let after = Ccr::decode(MULTI).unwrap();
    let diff = before.diff(&after);
    assert!(!diff.is_empty());

    let manifests = diff.manifests().unwrap();
    assert_eq!(
        (
            manifests.added().len(),
            manifests.removed().len(),
            manifests.unchanged()
        ),
        (2, 4, 0)
    );
    assert_eq!(manifests.by_hash().added(), manifests.added());
    // Issuers ascending by AKI: 25F8 (updated), A2DF (removed), E731 (removed), FACB (updated).
    let kinds: Vec<(String, ChangeKind, usize, usize)> = manifests
        .issuers()
        .iter()
        .map(|c| {
            (
                c.aki().to_string()[..4].to_string(),
                c.kind(),
                c.before().len(),
                c.after().len(),
            )
        })
        .collect();
    assert_eq!(
        kinds,
        [
            ("25F8".to_string(), ChangeKind::Updated, 1, 1),
            ("A2DF".to_string(), ChangeKind::Removed, 1, 0),
            ("E731".to_string(), ChangeKind::Removed, 1, 0),
            ("FACB".to_string(), ChangeKind::Updated, 1, 1),
        ]
    );
    assert_eq!(manifests.unchanged_issuers(), 0);
    let updated = &manifests.issuers()[0];
    assert_eq!(updated.before()[0].manifest_number().to_string(), "0101");
    assert_eq!(updated.after()[0].manifest_number().to_string(), "2A");

    let vrps = diff.roa_payloads().unwrap();
    assert_eq!(
        (vrps.added().len(), vrps.removed().len(), vrps.unchanged()),
        (2, 5, 0)
    );
    assert_eq!(vrps.added()[0].to_string(), "192.0.2.0/24-25 AS 64496");

    // The fixture has no ASPA or router key state: compared as empty.
    let aspas = diff.aspa_payloads().unwrap();
    assert_eq!(
        (
            aspas.added().len(),
            aspas.removed().len(),
            aspas.updated().len()
        ),
        (0, 3, 0)
    );
    assert_eq!(diff.router_keys().unwrap().removed().len(), 3);
    // Identical trust anchors are skipped by digest.
    let tas = diff.trust_anchors().unwrap();
    assert!(tas.is_empty());
    assert_eq!(tas.unchanged(), 2);

    let reverse = after.diff(&before);
    assert_eq!(reverse.roa_payloads().unwrap().added(), vrps.removed());
    assert_eq!(reverse.roa_payloads().unwrap().removed(), vrps.added());
    assert_eq!(
        reverse.manifests().unwrap().issuers()[1].kind(),
        ChangeKind::Added
    );
}

#[test]
fn issuer_update_and_provider_changes() {
    let before = Ccr::decode(DATA).unwrap();
    let state = before.manifests().unwrap();
    let mut instances = state.instances().to_vec();
    let ca4 = ki("A2DF042FE8B0006311E894851AC11411307B6043");
    let old = instances.iter().position(|mi| *mi.aki() == ca4).unwrap();
    let replacement = ManifestInstance::new(
        Digest::sha256(b"the next manifest of ca4"),
        1001,
        ca4,
        ManifestNumber::from(0x1322u64),
        Utc.with_ymd_and_hms(2026, 5, 15, 0, 0, 10).unwrap(),
        instances[old].locations().to_vec(),
        vec![],
    )
    .unwrap();
    instances[old] = replacement.clone();

    let aspas = AspaPayloadState::new(vec![
        AspaPayloadSet::new(Asn::new(64512), vec![Asn::new(64496)]).unwrap(),
        AspaPayloadSet::new(
            Asn::new(65536),
            vec![Asn::new(65540), Asn::new(65545), Asn::new(65546)],
        )
        .unwrap(),
        AspaPayloadSet::new(Asn::new(65550), vec![Asn::new(0)]).unwrap(),
    ])
    .unwrap();
    let after = Ccr::builder(before.produced_at())
        .manifests(ManifestState::new(instances))
        .roa_payloads(RoaPayloadState::from_vrps(
            before.roa_payloads().unwrap().vrps(),
        ))
        .aspa_payloads(aspas)
        .trust_anchors(
            TrustAnchorState::new(before.trust_anchors().unwrap().skis().to_vec()).unwrap(),
        )
        .router_keys(RouterKeyState::new(before.router_keys().unwrap().sets().to_vec()).unwrap())
        .build()
        .unwrap();

    let diff = before.diff(&after);
    let manifests = diff.manifests().unwrap();
    assert_eq!(
        (
            manifests.added().len(),
            manifests.removed().len(),
            manifests.unchanged()
        ),
        (1, 1, 3)
    );
    assert_eq!(manifests.added(), std::slice::from_ref(&replacement));
    assert_eq!(manifests.issuers().len(), 1);
    assert_eq!(manifests.unchanged_issuers(), 3);
    let change = &manifests.issuers()[0];
    assert_eq!((change.aki(), change.kind()), (&ca4, ChangeKind::Updated));
    assert_eq!(change.before()[0].manifest_number().to_string(), "1321");
    assert_eq!(change.after(), [replacement]);

    let aspas = diff.aspa_payloads().unwrap();
    assert_eq!(aspas.added()[0].customer_as_id(), Asn::new(64512));
    assert_eq!(aspas.removed()[0].customer_as_id(), Asn::new(64511));
    assert_eq!(aspas.unchanged(), 1);
    let update = &aspas.updated()[0];
    assert_eq!(update.customer_as_id(), Asn::new(65536));
    assert_eq!(update.providers_added(), [Asn::new(65545), Asn::new(65546)]);
    assert_eq!(update.providers_removed(), [Asn::new(65544)]);
    assert!(!aspas.is_empty());

    assert!(diff.roa_payloads().unwrap().is_empty());
    assert!(diff.trust_anchors().unwrap().is_empty());
    assert!(diff.router_keys().unwrap().is_empty());
    assert!(!diff.is_empty());
}

#[test]
fn leniently_decoded_unsorted_input_is_sorted_first() {
    let unsorted = ccr(T0, &[ta_state(&[ski(2), ski(1)], None)]);
    let lenient = Ccr::decode_with(&unsorted, &ValidationOptions::lenient()).unwrap();
    let sorted = Ccr::builder(lenient.produced_at())
        .trust_anchors(TrustAnchorState::new(vec![ski(1).into(), ski(2).into()]).unwrap())
        .build()
        .unwrap();
    let diff = lenient.diff(&sorted);
    assert!(diff.is_empty());
    assert_eq!(diff.trust_anchors().unwrap().unchanged(), 2);
}

#[test]
fn absent_aspects() {
    let produced_at = Utc.with_ymd_and_hms(2026, 5, 15, 0, 0, 10).unwrap();
    let tas = TrustAnchorState::new(vec![ski(1).into()]).unwrap();
    let only_tas = Ccr::builder(produced_at)
        .trust_anchors(tas.clone())
        .build()
        .unwrap();
    let with_vrps = Ccr::builder(produced_at)
        .trust_anchors(tas)
        .roa_payloads(RoaPayloadState::from_vrps([rpki_ccr::Vrp::new(
            Asn::new(1),
            "10.0.0.0/8".parse().unwrap(),
            8,
        )
        .unwrap()]))
        .build()
        .unwrap();
    let diff = only_tas.diff(&with_vrps);
    assert!(diff.manifests().is_none());
    assert!(diff.aspa_payloads().is_none());
    assert!(diff.router_keys().is_none());
    assert_eq!(diff.roa_payloads().unwrap().added().len(), 1);
    assert!(diff.trust_anchors().unwrap().is_empty());
    assert!(!diff.is_empty());
    assert!(only_tas.diff(&only_tas).is_empty());
}
