//! Encoding: byte-for-byte round trips, building a CCR from scratch, and
//! the multi-location fixture.

use std::collections::BTreeMap;
use std::path::Path;

use base64::prelude::*;
use bytes::Bytes;
use chrono::{DateTime, Duration, TimeZone, Utc};
use rpki_ccr::bcder::Oid;
use rpki_ccr::{
    AccessDescription, Asn, AspaPayloadSet, AspaPayloadState, Ccr, Digest, Error, KeyIdentifier,
    ManifestInstance, ManifestNumber, ManifestState, Prefix, RoaIpAddress, RoaPayloadSet,
    RoaPayloadState, RouterKey, RouterKeySet, RouterKeyState, SubjectPublicKeyInfo,
    TrustAnchorState, Vrp,
};

const DATA: &[u8] = include_bytes!("data/example.ccr");

const TA1: &str = "25F8CCFCEFC046D8DCD00FC0E444E0AA7B790F96";
const TA2: &str = "FACBD02CA47E3BD9666FCBD823B37DEDD0BCEE00";
const CA3: &str = "E7315EA515D7C20538681249D3E30D6777162585";
const CA4: &str = "A2DF042FE8B0006311E894851AC11411307B6043";

const SPKI1: &str = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE64mxtNmdKd1bxIjgWrGJutr11LDeA56L8cc1NLL/WW9RZ+rbi+G4rFSvfrEjxzRPt6tcNWpgEINq7tOR7J5dAg==";
const SPKI2: &str = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKjqTNoxSLK3UnLMNj2AdN/5sk5SITnYWK5e/JebKlJPFFxmBrOXWQyijRQBFFus7GtLLIZBYgp4K/u8o2/D4ig==";
const SPKI3: &str = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4Xt6+dRDhjmH0QVmXlUPndJeXyzlMcsco6WkrjBf6NoX6gYahESgCm67xkBK4ZxhvCZRFWLxqH8cgT/Pgvl94w==";

fn t(h: u32, m: u32, s: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 5, 15, h, m, s).unwrap()
}

fn ki(hex: &str) -> KeyIdentifier {
    KeyIdentifier::from_hex(hex).unwrap()
}

fn digest(b64: &str) -> Digest {
    Digest::try_from(BASE64_STANDARD.decode(b64).unwrap().as_slice()).unwrap()
}

fn prefix(s: &str) -> Prefix {
    s.parse().unwrap()
}

fn vrp(asn: u32, p: &str, max: u8) -> Vrp {
    Vrp::new(Asn::new(asn), prefix(p), max).unwrap()
}

fn sia(uri: &str) -> AccessDescription {
    AccessDescription::signed_object(uri).unwrap()
}

fn spki(b64: &str) -> SubjectPublicKeyInfo {
    SubjectPublicKeyInfo::from_der(&BASE64_STANDARD.decode(b64).unwrap()).unwrap()
}

#[test]
fn round_trip_example_vector() {
    let ccr = Ccr::decode(DATA).unwrap();
    assert_eq!(ccr.to_der().as_ref(), DATA);
    let mut out = Vec::new();
    ccr.write_der(&mut out).unwrap();
    assert_eq!(out, DATA);
    #[cfg(feature = "gzip")]
    {
        let gz = ccr.to_der_gzip().unwrap();
        assert!(Ccr::is_gzip(&gz));
        assert_eq!(Ccr::decode(&gz).unwrap(), ccr);
    }
}

#[test]
fn builds_example_vector_from_scratch() {
    // Inputs are deliberately unsorted and contain duplicates and mergeable
    // sets; the constructors must produce the canonical form.
    let manifests = ManifestState::new(vec![
        ManifestInstance::new(
            digest("48JkKNPGfzSWjkALB4rFbaktXGSFaAV5qj0gj7zCCFY="),
            1729,
            ki(TA1),
            ManifestNumber::from(0x0101u64),
            t(0, 0, 6),
            vec![sia(
                "rsync://example.net/ca1/OaVUOIDSaLzUbeiz6VPogXxsK5o.mft",
            )],
            vec![ki(CA3), ki(CA4), ki(CA3)],
        )
        .unwrap(),
        ManifestInstance::new(
            digest("vee5m+i2FKhzHwldksC2IX0WlVcHHVu3B8qAMnk+/Xo="),
            3995,
            ki(CA3),
            ManifestNumber::from(0x0508u64),
            t(0, 0, 8),
            vec![sia(
                "rsync://example.net/ca3/sbhFzz4wTqsFo2NVRM8mWfsPBKQ.mft",
            )],
            vec![],
        )
        .unwrap(),
        ManifestInstance::new(
            digest("KF60zgHHRNmQSUXcsAcAPB2cB7kvToWUF60GADJuG5E="),
            1001,
            ki(CA4),
            ManifestNumber::from(0x1321u64),
            t(0, 0, 9),
            vec![sia(
                "rsync://example.net/ca4/QksbQZMC7YWsNrREt4l4dWAQ1sE.mft",
            )],
            vec![],
        )
        .unwrap(),
        ManifestInstance::new(
            digest("PH84tOOYN8EterYimODMa4sDj9HkMeyTNyCsy/9Q/48="),
            2040,
            ki(TA2),
            ManifestNumber::from(0x0203u64),
            t(0, 0, 7),
            vec![sia(
                "rsync://example.net/ca2/z0nzVS7SOB_9y6tapHk7-YuKkm8.mft",
            )],
            vec![],
        )
        .unwrap(),
    ]);
    assert_eq!(manifests.most_recent_update(), t(0, 0, 9));

    let roas = RoaPayloadState::from_vrps([
        vrp(65551, "3fff::/32", 32),
        vrp(65536, "2001:db8::/48", 48),
        vrp(65536, "198.51.100.0/24", 28),
        vrp(0, "192.0.2.0/24", 24),
        vrp(65550, "3fff::/32", 32),
        vrp(0, "192.0.2.0/24", 24),
    ]);
    let aspas = AspaPayloadState::new(vec![
        AspaPayloadSet::new(Asn::new(65550), vec![Asn::new(0)]).unwrap(),
        AspaPayloadSet::new(Asn::new(65536), vec![Asn::new(65544)]).unwrap(),
        AspaPayloadSet::new(Asn::new(64511), vec![Asn::new(64496)]).unwrap(),
        AspaPayloadSet::new(Asn::new(65536), vec![Asn::new(65544), Asn::new(65540)]).unwrap(),
    ])
    .unwrap();
    let tas = TrustAnchorState::new(vec![ki(TA2), ki(TA1), ki(TA2)]).unwrap();
    let rks = RouterKeyState::new(vec![
        RouterKeySet::new(
            Asn::new(65551),
            vec![RouterKey::new(
                ki("4602B621B017681E61EE1F4A5EFC1D02C3B46F2C"),
                spki(SPKI3),
            )],
        )
        .unwrap(),
        RouterKeySet::new(
            Asn::new(65542),
            vec![RouterKey::new(
                ki("BE16E74E10F4BDF3F8C2618B024A9457DFBF89FA"),
                spki(SPKI2),
            )],
        )
        .unwrap(),
        RouterKeySet::new(
            Asn::new(65542),
            vec![RouterKey::new(
                ki("88C5DE295A3276D69E9BB7469BD46EF972DE32AC"),
                spki(SPKI1),
            )],
        )
        .unwrap(),
    ])
    .unwrap();

    let ccr = Ccr::builder(t(0, 0, 10))
        .manifests(manifests)
        .roa_payloads(roas)
        .aspa_payloads(aspas)
        .trust_anchors(tas)
        .router_keys(rks)
        .build()
        .unwrap();
    assert_eq!(ccr.to_der().as_ref(), DATA);
    assert_eq!(ccr, Ccr::decode(DATA).unwrap());
}

/// A fixture whose manifest instances carry several `AccessDescription`s,
/// which the specification's own test vector lacks. Regenerate with
/// `RPKI_CCR_WRITE_FIXTURES=1 cargo test --test encode`.
#[test]
fn multi_location_fixture() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/multi-location.ccr");
    let rpki_notify = Oid(Bytes::from_static(&[43, 6, 1, 5, 5, 7, 48, 13]));

    let a = ManifestInstance::new(
        Digest::sha256(b"manifest a"),
        1500,
        ki(TA1),
        ManifestNumber::from(42u64),
        t(0, 0, 5),
        vec![
            sia("rsync://example.net/ca1/a.mft"),
            sia("https://example.net/ca1/a.mft"),
        ],
        vec![ki(CA4)],
    )
    .unwrap();
    let b = ManifestInstance::new(
        Digest::sha256(b"manifest b"),
        2000,
        ki(TA2),
        ManifestNumber::from(0x01ffu64),
        t(0, 0, 9),
        vec![
            sia("rsync://example.net/ca2/b.mft"),
            AccessDescription::new(rpki_notify, "https://example.net/notification.xml").unwrap(),
            sia("https://example.net/ca2/b.mft"),
        ],
        vec![],
    )
    .unwrap();
    let ccr = Ccr::builder(t(0, 0, 10))
        .manifests(ManifestState::new(vec![a, b]))
        .roa_payloads(RoaPayloadState::from_vrps([
            vrp(64496, "192.0.2.0/24", 25),
            vrp(64496, "2001:db8::/32", 32),
        ]))
        .trust_anchors(TrustAnchorState::new(vec![ki(TA1), ki(TA2)]).unwrap())
        .build()
        .unwrap();
    let der = ccr.to_der();

    if std::env::var_os("RPKI_CCR_WRITE_FIXTURES").is_some() {
        std::fs::write(&path, &der).unwrap();
    }
    let fixture = std::fs::read(&path).unwrap();
    assert_eq!(
        der.as_ref(),
        fixture.as_slice(),
        "fixture is stale; regenerate with RPKI_CCR_WRITE_FIXTURES=1"
    );

    let decoded = Ccr::decode(&fixture).unwrap();
    assert_eq!(decoded, ccr);
    let by_aki: BTreeMap<String, &ManifestInstance> = decoded
        .manifests()
        .unwrap()
        .instances()
        .iter()
        .map(|mi| (mi.aki().to_string(), mi))
        .collect();
    let a = by_aki[TA1];
    let uris: Vec<&str> = a.locations().iter().map(AccessDescription::uri).collect();
    assert_eq!(
        uris,
        [
            "rsync://example.net/ca1/a.mft",
            "https://example.net/ca1/a.mft"
        ]
    );
    assert!(
        a.locations()
            .iter()
            .all(AccessDescription::is_signed_object)
    );
    assert_eq!(a.manifest_number().to_string(), "2A");
    let b = by_aki[TA2];
    assert_eq!(b.locations().len(), 3);
    assert!(!b.locations()[1].is_signed_object());
    assert_eq!(
        b.locations()[1].access_method().to_string(),
        "1.3.6.1.5.5.7.48.13"
    );
    assert_eq!(
        b.locations()[1].uri(),
        "https://example.net/notification.xml"
    );
    assert_eq!(b.manifest_number().to_string(), "01FF");
    assert_eq!(
        decoded.manifests().unwrap().most_recent_update(),
        t(0, 0, 9)
    );
}

#[test]
fn canonical_roa_payloads() {
    let state = RoaPayloadState::from_vrps([
        vrp(65536, "2001:db8::/32", 48),
        vrp(65536, "192.0.2.0/24", 24),
        vrp(65536, "192.0.2.0/24", 24),
        vrp(65536, "192.0.2.0/25", 25),
        vrp(65536, "192.0.2.0/24", 28),
        vrp(64496, "198.51.100.0/24", 24),
    ]);
    let vrps: Vec<String> = state.vrps().map(|v| v.to_string()).collect();
    assert_eq!(
        vrps,
        [
            "198.51.100.0/24 AS 64496",
            "192.0.2.0/24 AS 65536",
            "192.0.2.0/24-28 AS 65536",
            "192.0.2.0/25 AS 65536",
            "2001:db8::/32-48 AS 65536",
        ]
    );
    // maxLength equal to the prefix length is omitted from the encoding.
    let first = &state.sets()[0].ip_addr_blocks()[0].addresses()[0];
    assert_eq!(first.max_length(), None);
    let explicit = RoaIpAddress::new(prefix("192.0.2.0/24"), Some(24)).unwrap();
    assert_eq!(explicit.canonical().max_length(), None);

    // Sets with the same AS are merged.
    let merged = RoaPayloadState::new(vec![
        RoaPayloadSet::new(Asn::new(1), vec![vrp(1, "10.0.0.0/8", 8).address()]).unwrap(),
        RoaPayloadSet::new(Asn::new(1), vec![vrp(1, "::/0", 0).address()]).unwrap(),
    ]);
    assert_eq!(merged.len(), 1);
    assert_eq!(merged.sets()[0].ip_addr_blocks().len(), 2);

    let ccr = Ccr::builder(t(0, 0, 10))
        .roa_payloads(state)
        .build()
        .unwrap();
    assert_eq!(Ccr::decode(&ccr.to_der()).unwrap(), ccr);
}

#[test]
fn constructors_reject_invalid_input() {
    let invalid =
        |r: Result<(), Error>| assert!(matches!(r, Err(Error::InvalidValue { .. })), "{r:?}");

    invalid(Ccr::builder(t(0, 0, 10)).build().map(drop));
    invalid(
        ManifestInstance::new(
            Digest::sha256(b""),
            999,
            ki(TA1),
            1u64.into(),
            t(0, 0, 0),
            vec![sia("rsync://a")],
            vec![],
        )
        .map(drop),
    );
    invalid(
        ManifestInstance::new(
            Digest::sha256(b""),
            1000,
            ki(TA1),
            1u64.into(),
            t(0, 0, 0),
            vec![],
            vec![],
        )
        .map(drop),
    );
    let far_future = Utc.with_ymd_and_hms(10000, 1, 1, 0, 0, 0).unwrap();
    invalid(
        ManifestInstance::new(
            Digest::sha256(b""),
            1000,
            ki(TA1),
            1u64.into(),
            far_future,
            vec![sia("rsync://a")],
            vec![],
        )
        .map(drop),
    );
    let fractional = t(0, 0, 0) + Duration::milliseconds(500);
    invalid(
        ManifestInstance::new(
            Digest::sha256(b""),
            1000,
            ki(TA1),
            1u64.into(),
            fractional,
            vec![sia("rsync://a")],
            vec![],
        )
        .map(drop),
    );
    invalid(
        Ccr::builder(fractional)
            .trust_anchors(TrustAnchorState::new(vec![ki(TA1)]).unwrap())
            .build()
            .map(drop),
    );
    invalid(AccessDescription::signed_object("").map(drop));
    invalid(AccessDescription::signed_object("rsync://exämple.net/a.mft").map(drop));
    invalid(AspaPayloadSet::new(Asn::new(1), vec![]).map(drop));
    invalid(AspaPayloadSet::new(Asn::new(1), vec![Asn::new(0), Asn::new(2)]).map(drop));
    invalid(
        AspaPayloadState::new(vec![
            AspaPayloadSet::new(Asn::new(1), vec![Asn::new(0)]).unwrap(),
            AspaPayloadSet::new(Asn::new(1), vec![Asn::new(2)]).unwrap(),
        ])
        .map(drop),
    );
    invalid(TrustAnchorState::new(vec![]).map(drop));
    invalid(RouterKeySet::new(Asn::new(1), vec![]).map(drop));
    invalid(RoaPayloadSet::new(Asn::new(1), vec![]).map(drop));

    let mut trailing = BASE64_STANDARD.decode(SPKI1).unwrap();
    trailing.push(0);
    invalid(SubjectPublicKeyInfo::from_der(&trailing).map(drop));
    assert!(matches!(
        SubjectPublicKeyInfo::from_der(&[0x30, 0x00]),
        Err(Error::Der(_))
    ));

    // mostRecentUpdate later than producedAt is caught by the builder.
    let late = ManifestInstance::new(
        Digest::sha256(b""),
        1000,
        ki(TA1),
        1u64.into(),
        t(0, 0, 11),
        vec![sia("rsync://a")],
        vec![],
    )
    .unwrap();
    assert!(matches!(
        Ccr::builder(t(0, 0, 10))
            .manifests(ManifestState::new(vec![late]))
            .build(),
        Err(Error::Consistency { .. })
    ));
}

#[test]
fn merging_and_deduplication() {
    let aspas = AspaPayloadState::new(vec![
        AspaPayloadSet::new(Asn::new(2), vec![Asn::new(20), Asn::new(10)]).unwrap(),
        AspaPayloadSet::new(Asn::new(1), vec![Asn::new(5)]).unwrap(),
        AspaPayloadSet::new(Asn::new(2), vec![Asn::new(10), Asn::new(30)]).unwrap(),
    ])
    .unwrap();
    let sets: Vec<(u32, Vec<u32>)> = aspas
        .sets()
        .iter()
        .map(|s| {
            (
                s.customer_as_id().into_u32(),
                s.providers().iter().map(|p| p.into_u32()).collect(),
            )
        })
        .collect();
    assert_eq!(sets, [(1, vec![5]), (2, vec![10, 20, 30])]);

    let empty = ManifestState::new(vec![]);
    assert!(empty.is_empty());
    assert_eq!(empty.most_recent_update(), DateTime::UNIX_EPOCH);
    let ccr = Ccr::builder(t(0, 0, 10)).manifests(empty).build().unwrap();
    assert_eq!(Ccr::decode(&ccr.to_der()).unwrap(), ccr);

    let rks = RouterKeyState::new(vec![
        RouterKeySet::new(Asn::new(1), vec![RouterKey::new(ki(TA2), spki(SPKI1))]).unwrap(),
        RouterKeySet::new(
            Asn::new(1),
            vec![
                RouterKey::new(ki(TA1), spki(SPKI2)),
                RouterKey::new(ki(TA2), spki(SPKI3)),
            ],
        )
        .unwrap(),
    ])
    .unwrap();
    let keys: Vec<(u32, String, String)> = rks
        .router_keys()
        .map(|(asn, k)| {
            (
                asn.into_u32(),
                k.ski().to_string(),
                BASE64_STANDARD.encode(k.spki().as_der()),
            )
        })
        .collect();
    assert_eq!(
        keys,
        [
            (1, TA1.to_string(), SPKI2.to_string()),
            (1, TA2.to_string(), SPKI1.to_string())
        ]
    );
}

/// Round-trips an arbitrary CCR file named by `RPKI_CCR_ROUNDTRIP_FILE`,
/// e.g. a current `https://console.rpki-client.org/rpki.ccr`:
/// `RPKI_CCR_ROUNDTRIP_FILE=rpki.ccr cargo test --release --test encode -- --ignored`.
#[test]
#[ignore = "needs RPKI_CCR_ROUNDTRIP_FILE"]
fn round_trip_external_file() {
    let path = std::env::var_os("RPKI_CCR_ROUNDTRIP_FILE").expect("RPKI_CCR_ROUNDTRIP_FILE");
    let data = std::fs::read(&path).unwrap();
    let der = if Ccr::is_gzip(&data) {
        use std::io::Read as _;
        let mut out = Vec::new();
        flate2::read::MultiGzDecoder::new(&data[..])
            .read_to_end(&mut out)
            .unwrap();
        out
    } else {
        data
    };
    let ccr = Ccr::decode_der(&der).unwrap();
    let encoded = ccr.to_der();
    assert_eq!(encoded.len(), der.len());
    assert!(
        encoded.as_ref() == der.as_slice(),
        "re-encoding differs from the input"
    );
    assert_eq!(Ccr::decode_der(&encoded).unwrap(), ccr);
}
