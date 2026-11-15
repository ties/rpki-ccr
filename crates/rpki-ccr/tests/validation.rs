//! Negative tests: every MUST of the specification, exercised with
//! synthesized CCR files.

mod common;

use common::*;
use rpki_ccr::{Asn, Aspect, Ccr, Error, ValidationOptions};

const FIXTURE: &[u8] = include_bytes!("data/example.ccr");

#[track_caller]
fn strict_err(data: &[u8]) -> Error {
    Ccr::decode(data).expect_err("decode should fail")
}

#[track_caller]
fn assert_der_err(data: &[u8], needle: &str) {
    match strict_err(data) {
        Error::Der(err) => {
            let msg = err.to_string();
            assert!(msg.contains(needle), "expected {needle:?} in {msg:?}");
        }
        other => panic!("expected a DER error containing {needle:?}, got {other:?}"),
    }
    assert!(
        matches!(
            Ccr::decode_with(data, &ValidationOptions::lenient()),
            Err(Error::Der(_))
        ),
        "structural errors must not be suppressed by lenient mode"
    );
}

fn ta_only(skis: &[[u8; 20]]) -> Vec<u8> {
    ccr(T0, &[ta_state(skis, None)])
}

#[test]
fn minimal_file_decodes() {
    let ccr = Ccr::decode(&ta_only(&[ski(1), ski(2)])).unwrap();
    assert_eq!(ccr.trust_anchors().unwrap().skis().len(), 2);
    assert!(ccr.manifests().is_none());
    assert!(ccr.roa_payloads().is_none());
    assert!(ccr.aspa_payloads().is_none());
    assert!(ccr.router_keys().is_none());
}

#[test]
fn hash_mismatch() {
    let data = ccr(T0, &[ta_state(&[ski(1)], Some(&digest(0)))]);
    match strict_err(&data) {
        Error::HashMismatch {
            aspect: Aspect::TrustAnchors,
            declared,
            computed,
        } => {
            assert_eq!(declared.as_slice(), &digest(0));
            assert_ne!(computed, declared);
        }
        other => panic!("{other:?}"),
    }
    assert!(Ccr::decode_with(&data, &ValidationOptions::lenient()).is_ok());
    assert!(Ccr::decode_with(&data, &ValidationOptions::strict().verify_hashes(false)).is_ok());
    assert!(Ccr::decode_with(&data, &ValidationOptions::strict().check_ordering(false)).is_err());
}

#[test]
fn hash_mismatch_in_the_real_fixture() {
    let mut data = FIXTURE.to_vec();
    data[752] ^= 1; // inside the ManifestState hash octet string
    assert!(matches!(
        strict_err(&data),
        Error::HashMismatch {
            aspect: Aspect::Manifests,
            ..
        }
    ));
    assert!(Ccr::decode_with(&data, &ValidationOptions::strict().verify_hashes(false)).is_ok());
}

#[test]
fn trust_anchor_ordering() {
    assert!(matches!(
        strict_err(&ta_only(&[ski(2), ski(1)])),
        Error::NotSorted {
            aspect: Aspect::TrustAnchors,
            index: 1,
            ..
        }
    ));
    assert!(matches!(
        strict_err(&ta_only(&[ski(1), ski(1)])),
        Error::Duplicate {
            aspect: Aspect::TrustAnchors,
            index: 1,
            ..
        }
    ));
    let unsorted = ta_only(&[ski(2), ski(1)]);
    assert!(Ccr::decode_with(&unsorted, &ValidationOptions::lenient()).is_ok());
    assert!(
        Ccr::decode_with(&unsorted, &ValidationOptions::strict().verify_hashes(false)).is_err()
    );
    assert!(
        Ccr::decode_with(
            &unsorted,
            &ValidationOptions::strict().check_ordering(false)
        )
        .is_ok()
    );
    // Unsigned 160-bit comparison: a leading 0x80 octet sorts after 0x7f.
    let mut hi = ski(0x7f);
    hi[0] = 0x80;
    assert!(Ccr::decode(&ta_only(&[ski(0x7f), hi])).is_ok());
    assert_der_err(
        &ccr(T0, &[hashed_state(4, &seq(&[]), &[], None)]),
        "at least one",
    );
    assert_der_err(
        &ccr(T0, &[hashed_state(4, &seq(&[oct(&[1; 19])]), &[], None)]),
        "20 octets",
    );
}

#[test]
fn aspa_rules() {
    let ok = ccr(
        T0,
        &[aspa_state(
            &[
                aspa_set(64511, &[64496]),
                aspa_set(65536, &[65540, 65544]),
                aspa_set(65550, &[0]),
            ],
            None,
        )],
    );
    let ccr_ok = Ccr::decode(&ok).unwrap();
    assert_eq!(
        ccr_ok.aspa_payloads().unwrap().sets()[2].providers(),
        [Asn::new(0)]
    );

    let unsorted = ccr(
        T0,
        &[aspa_state(
            &[aspa_set(65536, &[65540]), aspa_set(64511, &[64496])],
            None,
        )],
    );
    assert!(matches!(
        strict_err(&unsorted),
        Error::NotSorted {
            aspect: Aspect::AspaPayloads,
            index: 1,
            ..
        }
    ));
    let dup = ccr(
        T0,
        &[aspa_state(
            &[aspa_set(64511, &[1]), aspa_set(64511, &[2])],
            None,
        )],
    );
    assert!(matches!(
        strict_err(&dup),
        Error::Duplicate {
            aspect: Aspect::AspaPayloads,
            ..
        }
    ));
    let providers_unsorted = ccr(T0, &[aspa_state(&[aspa_set(64511, &[65544, 65540])], None)]);
    assert!(matches!(
        strict_err(&providers_unsorted),
        Error::NotSorted {
            aspect: Aspect::AspaPayloads,
            ..
        }
    ));
    let providers_dup = ccr(T0, &[aspa_state(&[aspa_set(64511, &[65540, 65540])], None)]);
    assert!(matches!(
        strict_err(&providers_dup),
        Error::Duplicate {
            aspect: Aspect::AspaPayloads,
            ..
        }
    ));
    let as0_with_others = ccr(T0, &[aspa_state(&[aspa_set(64511, &[0, 65540])], None)]);
    assert!(matches!(
        strict_err(&as0_with_others),
        Error::Consistency {
            aspect: Aspect::AspaPayloads,
            ..
        }
    ));
    assert!(
        Ccr::decode_with(
            &as0_with_others,
            &ValidationOptions::strict().check_consistency(false)
        )
        .is_ok()
    );
    // The customer AS must not be one of its own providers.
    let customer_as_provider = ccr(T0, &[aspa_state(&[aspa_set(64511, &[64496, 64511])], None)]);
    assert!(matches!(
        strict_err(&customer_as_provider),
        Error::Consistency {
            aspect: Aspect::AspaPayloads,
            ..
        }
    ));
    assert!(
        Ccr::decode_with(
            &customer_as_provider,
            &ValidationOptions::strict().check_consistency(false)
        )
        .is_ok()
    );
    assert_der_err(
        &ccr(T0, &[aspa_state(&[aspa_set(64511, &[])], None)]),
        "at least one AS",
    );
    assert_der_err(
        &ccr(T0, &[aspa_state(&[aspa_set(1 << 32, &[1])], None)]),
        "",
    );
    // An empty aps sequence is allowed.
    assert!(
        Ccr::decode(&ccr(T0, &[aspa_state(&[], None)]))
            .unwrap()
            .aspa_payloads()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn roa_rules() {
    let v4 = |addrs: Vec<Vec<u8>>| roa_family(1, &addrs);
    let v6 = |addrs: Vec<Vec<u8>>| roa_family(2, &addrs);
    let a = roa_address(0, &[192, 0, 2], None);
    let a28 = roa_address(0, &[192, 0, 2], Some(28));
    let b = roa_address(0, &[198, 51, 100], None);
    let six = roa_address(0, &[0x20, 0x01, 0x0d, 0xb8], None);

    let ok = ccr(
        T0,
        &[roa_state(
            &[
                roa_set(
                    0,
                    &[
                        v4(vec![a.clone(), a28.clone(), b.clone()]),
                        v6(vec![six.clone()]),
                    ],
                ),
                roa_set(1, &[v6(vec![six.clone()])]),
            ],
            None,
        )],
    );
    let decoded = Ccr::decode(&ok).unwrap();
    let vrps: Vec<String> = decoded
        .roa_payloads()
        .unwrap()
        .vrps()
        .map(|v| v.to_string())
        .collect();
    assert_eq!(
        vrps,
        [
            "192.0.2.0/24 AS 0",
            "192.0.2.0/24-28 AS 0",
            "198.51.100.0/24 AS 0",
            "2001:db8::/32 AS 0",
            "2001:db8::/32 AS 1"
        ]
    );

    let sets_unsorted = ccr(
        T0,
        &[roa_state(
            &[
                roa_set(1, &[v4(vec![a.clone()])]),
                roa_set(0, &[v4(vec![a.clone()])]),
            ],
            None,
        )],
    );
    assert!(matches!(
        strict_err(&sets_unsorted),
        Error::NotSorted {
            aspect: Aspect::RoaPayloads,
            ..
        }
    ));
    let family_order = ccr(
        T0,
        &[roa_state(
            &[roa_set(0, &[v6(vec![six.clone()]), v4(vec![a.clone()])])],
            None,
        )],
    );
    assert!(matches!(
        strict_err(&family_order),
        Error::NotSorted {
            aspect: Aspect::RoaPayloads,
            ..
        }
    ));
    let family_dup = ccr(
        T0,
        &[roa_state(
            &[roa_set(0, &[v4(vec![a.clone()]), v4(vec![b.clone()])])],
            None,
        )],
    );
    assert!(matches!(
        strict_err(&family_dup),
        Error::Duplicate {
            aspect: Aspect::RoaPayloads,
            ..
        }
    ));
    let addr_unsorted = ccr(
        T0,
        &[roa_state(
            &[roa_set(0, &[v4(vec![b.clone(), a.clone()])])],
            None,
        )],
    );
    assert!(matches!(
        strict_err(&addr_unsorted),
        Error::NotSorted {
            aspect: Aspect::RoaPayloads,
            ..
        }
    ));
    let addr_dup = ccr(
        T0,
        &[roa_state(
            &[roa_set(0, &[v4(vec![a.clone(), a.clone()])])],
            None,
        )],
    );
    assert!(matches!(
        strict_err(&addr_dup),
        Error::Duplicate {
            aspect: Aspect::RoaPayloads,
            ..
        }
    ));
    // maxLength equal to the prefix length is a duplicate of the bare prefix.
    let addr_dup_effective = ccr(
        T0,
        &[roa_state(
            &[roa_set(
                0,
                &[v4(vec![a.clone(), roa_address(0, &[192, 0, 2], Some(24))])],
            )],
            None,
        )],
    );
    assert!(matches!(
        strict_err(&addr_dup_effective),
        Error::Duplicate {
            aspect: Aspect::RoaPayloads,
            ..
        }
    ));
    // maxLength equal to the prefix length must not be encoded, even when
    // the bare prefix is not present.
    let redundant_max_length = ccr(
        T0,
        &[roa_state(
            &[roa_set(
                0,
                &[v4(vec![roa_address(0, &[192, 0, 2], Some(24)), b.clone()])],
            )],
            None,
        )],
    );
    assert!(matches!(
        strict_err(&redundant_max_length),
        Error::Consistency {
            aspect: Aspect::RoaPayloads,
            ..
        }
    ));
    assert!(
        Ccr::decode_with(
            &redundant_max_length,
            &ValidationOptions::strict().check_consistency(false)
        )
        .is_ok()
    );

    assert_der_err(
        &ccr(
            T0,
            &[roa_state(
                &[roa_set(
                    0,
                    &[v4(vec![roa_address(0, &[192, 0, 2], Some(23))])],
                )],
                None,
            )],
        ),
        "maxLength",
    );
    assert_der_err(
        &ccr(
            T0,
            &[roa_state(
                &[roa_set(
                    0,
                    &[v4(vec![roa_address(0, &[192, 0, 2], Some(33))])],
                )],
                None,
            )],
        ),
        "maxLength",
    );
    assert_der_err(
        &ccr(
            T0,
            &[roa_state(
                &[roa_set(
                    0,
                    &[v4(vec![roa_address(0, &[1, 2, 3, 4, 5], None)])],
                )],
                None,
            )],
        ),
        "longer",
    );
    assert_der_err(
        &ccr(
            T0,
            &[roa_state(
                &[roa_set(0, &[roa_family(3, std::slice::from_ref(&a))])],
                None,
            )],
        ),
        "addressFamily",
    );
    assert_der_err(
        &ccr(T0, &[roa_state(&[roa_set(0, &[v4(vec![])])], None)]),
        "at least one ROAIPAddress",
    );
    assert_der_err(
        &ccr(T0, &[roa_state(&[roa_set(0, &[])], None)]),
        "one or two",
    );
    assert_der_err(
        &ccr(
            T0,
            &[roa_state(
                &[roa_set(
                    0,
                    &[
                        v4(vec![a.clone()]),
                        v6(vec![six.clone()]),
                        v6(vec![six.clone()]),
                    ],
                )],
                None,
            )],
        ),
        "one or two",
    );
    // An empty rps sequence is allowed.
    assert!(
        Ccr::decode(&ccr(T0, &[roa_state(&[], None)]))
            .unwrap()
            .roa_payloads()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn manifest_rules() {
    let instance = |hash: u8, this_update: &str| {
        mft_instance(
            &digest(hash),
            1000,
            &ski(9),
            &[0x01, 0x01],
            this_update,
            &["rsync://example.net/a.mft"],
            None,
        )
    };
    let ok = ccr(
        T0,
        &[mft_state(
            &[
                instance(1, "20260515000008Z"),
                instance(2, "20260515000009Z"),
            ],
            "20260515000009Z",
            None,
        )],
    );
    let decoded = Ccr::decode(&ok).unwrap();
    assert_eq!(decoded.manifests().unwrap().len(), 2);
    assert_eq!(
        decoded.manifests().unwrap().instances()[0]
            .manifest_number()
            .to_string(),
        "0101"
    );

    let unsorted = ccr(
        T0,
        &[mft_state(
            &[
                instance(2, "20260515000009Z"),
                instance(1, "20260515000008Z"),
            ],
            "20260515000009Z",
            None,
        )],
    );
    assert!(matches!(
        strict_err(&unsorted),
        Error::NotSorted {
            aspect: Aspect::Manifests,
            ..
        }
    ));
    let wrong_mru = ccr(
        T0,
        &[mft_state(
            &[instance(1, "20260515000008Z")],
            "20260515000009Z",
            None,
        )],
    );
    assert!(matches!(
        strict_err(&wrong_mru),
        Error::Consistency {
            aspect: Aspect::Manifests,
            ..
        }
    ));
    let later_than_produced = ccr(
        "20260515000008Z",
        &[mft_state(
            &[instance(1, "20260515000009Z")],
            "20260515000009Z",
            None,
        )],
    );
    assert!(matches!(
        strict_err(&later_than_produced),
        Error::Consistency {
            aspect: Aspect::Manifests,
            ..
        }
    ));
    assert!(
        Ccr::decode_with(
            &later_than_produced,
            &ValidationOptions::strict().check_consistency(false)
        )
        .is_ok()
    );
    let empty_non_epoch = ccr(T0, &[mft_state(&[], T0, None)]);
    assert!(matches!(
        strict_err(&empty_non_epoch),
        Error::Consistency {
            aspect: Aspect::Manifests,
            ..
        }
    ));
    let empty_epoch = ccr(T0, &[mft_state(&[], EPOCH, None)]);
    assert!(
        Ccr::decode(&empty_epoch)
            .unwrap()
            .manifests()
            .unwrap()
            .is_empty()
    );

    let subs_ok = ccr(
        T0,
        &[mft_state(
            &[mft_instance(
                &digest(1),
                1000,
                &ski(9),
                &[1],
                T0,
                &["rsync://a", "https://b"],
                Some(&[ski(1), ski(2)]),
            )],
            T0,
            None,
        )],
    );
    let decoded = Ccr::decode(&subs_ok).unwrap();
    let inst = &decoded.manifests().unwrap().instances()[0];
    assert_eq!(inst.subordinates(), [ski(1).into(), ski(2).into()]);
    assert_eq!(
        inst.locations().iter().map(|l| l.uri()).collect::<Vec<_>>(),
        ["rsync://a", "https://b"]
    );
    let subs_unsorted = ccr(
        T0,
        &[mft_state(
            &[mft_instance(
                &digest(1),
                1000,
                &ski(9),
                &[1],
                T0,
                &["rsync://a"],
                Some(&[ski(2), ski(1)]),
            )],
            T0,
            None,
        )],
    );
    assert!(matches!(
        strict_err(&subs_unsorted),
        Error::NotSorted {
            aspect: Aspect::Manifests,
            ..
        }
    ));

    let bad = |data: Vec<u8>, needle: &str| {
        assert_der_err(&ccr(T0, &[mft_state(&[data], T0, None)]), needle)
    };
    // size INTEGER (0..MAX): the lower bound of 1000 in draft -11 was dropped
    // afterwards and is not enforced.
    let small = mft_instance(&digest(1), 1, &ski(9), &[1], T0, &["rsync://a"], None);
    assert!(Ccr::decode(&ccr(T0, &[mft_state(&[small], T0, None)])).is_ok());
    let zero = mft_instance(&digest(1), 0, &ski(9), &[1], T0, &["rsync://a"], None);
    assert!(Ccr::decode(&ccr(T0, &[mft_state(&[zero], T0, None)])).is_ok());
    // A negative size is not.
    bad(
        seq(&[
            oct(&digest(1)),
            int_raw(&[0x80]),
            oct(&ski(9)),
            int_raw(&[1]),
            gentime(T0),
            seq(&[access_description("rsync://a")]),
        ]),
        "integer",
    );
    bad(
        mft_instance(
            &digest(1),
            1000,
            &ski(9),
            &[1; 21],
            T0,
            &["rsync://a"],
            None,
        ),
        "20 octets",
    );
    bad(
        mft_instance(&digest(1), 1000, &ski(9), &[0x80], T0, &["rsync://a"], None),
        "integer",
    );
    bad(
        mft_instance(&digest(1), 1000, &ski(9), &[1], T0, &[], None),
        "at least one AccessDescription",
    );
    bad(
        mft_instance(
            &digest(1),
            1000,
            &ski(9),
            &[1],
            T0,
            &["rsync://a"],
            Some(&[]),
        ),
        "subordinates",
    );
    bad(
        mft_instance(&digest(1), 1000, &[9; 19], &[1], T0, &["rsync://a"], None),
        "20 octets",
    );
    bad(
        mft_instance(&[1; 31], 1000, &ski(9), &[1], T0, &["rsync://a"], None),
        "32 octets",
    );
    bad(
        mft_instance(
            &digest(1),
            1000,
            &ski(9),
            &[1],
            "20260515000010.5Z",
            &["rsync://a"],
            None,
        ),
        "GeneralizedTime",
    );
    bad(
        mft_instance(&digest(1), 1000, &ski(9), &[1], T0, &[""], None),
        "empty",
    );
    // A 20-octet manifest number is the maximum.
    assert!(
        Ccr::decode(&ccr(
            T0,
            &[mft_state(
                &[mft_instance(
                    &digest(1),
                    1000,
                    &ski(9),
                    &[1; 20],
                    T0,
                    &["rsync://a"],
                    None
                )],
                T0,
                None
            )]
        ))
        .is_ok()
    );
    // accessLocation must be a URI GeneralName.
    let dns_name = seq(&[seq(&[oid(SIGNED_OBJECT_OID), tlv(0x82, b"example.net")])]);
    let mut items = vec![
        oct(&digest(1)),
        uint(1000),
        oct(&ski(9)),
        int_raw(&[1]),
        gentime(T0),
        dns_name,
    ];
    items.truncate(6);
    assert_der_err(&ccr(T0, &[mft_state(&[seq(&items)], T0, None)]), "");
}

#[test]
fn router_key_rules() {
    let key = |n: u8| router_key(&ski(n), &spki_p256(n));
    let ok = ccr(
        T0,
        &[router_key_state(
            &[
                router_key_set(1, &[key(1), key(2)]),
                router_key_set(2, &[key(1)]),
            ],
            None,
        )],
    );
    let decoded = Ccr::decode(&ok).unwrap();
    let state = decoded.router_keys().unwrap();
    assert_eq!(state.router_keys().count(), 3);
    let (asn, first) = state.router_keys().next().unwrap();
    assert_eq!(asn, Asn::new(1));
    assert_eq!(first.spki().as_der(), spki_p256(1));
    assert!(first.spki().is_p256_ec());
    assert_eq!(first.spki().parameters(), Some(&oid(SECP256R1_OID)[..]));

    let sets_unsorted = ccr(
        T0,
        &[router_key_state(
            &[router_key_set(2, &[key(1)]), router_key_set(1, &[key(1)])],
            None,
        )],
    );
    assert!(matches!(
        strict_err(&sets_unsorted),
        Error::NotSorted {
            aspect: Aspect::RouterKeys,
            ..
        }
    ));
    let keys_unsorted = ccr(
        T0,
        &[router_key_state(
            &[router_key_set(1, &[key(2), key(1)])],
            None,
        )],
    );
    assert!(matches!(
        strict_err(&keys_unsorted),
        Error::NotSorted {
            aspect: Aspect::RouterKeys,
            ..
        }
    ));
    let keys_dup = ccr(
        T0,
        &[router_key_state(
            &[router_key_set(1, &[key(1), key(1)])],
            None,
        )],
    );
    assert!(matches!(
        strict_err(&keys_dup),
        Error::Duplicate {
            aspect: Aspect::RouterKeys,
            ..
        }
    ));
    assert_der_err(
        &ccr(T0, &[router_key_state(&[router_key_set(1, &[])], None)]),
        "at least one RouterKey",
    );
    let unused_bits = seq(&[
        seq(&[oid(EC_PUBLIC_KEY_OID), oid(SECP256R1_OID)]),
        bitstr(4, &[0x40]),
    ]);
    assert_der_err(
        &ccr(
            T0,
            &[router_key_state(
                &[router_key_set(1, &[router_key(&ski(1), &unused_bits)])],
                None,
            )],
        ),
        "unused bits",
    );
    // Keys with an RSA-style NULL parameter still decode; they are just not P-256.
    let rsa_like = seq(&[
        seq(&[oid(&[42, 134, 72, 134, 247, 13, 1, 1, 1]), null()]),
        bitstr(0, &[0x30, 0x00]),
    ]);
    let decoded = Ccr::decode(&ccr(
        T0,
        &[router_key_state(
            &[router_key_set(1, &[router_key(&ski(1), &rsa_like)])],
            None,
        )],
    ))
    .unwrap();
    let (_, k) = decoded.router_keys().unwrap().router_keys().next().unwrap();
    assert!(!k.spki().is_p256_ec());
    assert_eq!(k.spki().parameters(), Some(&null()[..]));
}

#[test]
fn top_level_rules() {
    let ta = ta_state(&[ski(1)], None);
    let header = |extra_before_aspects: &[Vec<u8>], aspects: &[Vec<u8>]| {
        let mut body = extra_before_aspects.concat();
        body.extend(hash_alg());
        body.extend(gentime(T0));
        body.extend(aspects.concat());
        content_info(&tlv(0x30, &body))
    };

    assert_der_err(&ccr(T0, &[]), "at least one state aspect");
    assert_der_err(&seq(&[oid(SHA256_OID), ctx(0, &[])]), "content type");
    assert_der_err(
        &header(&[ctx(0, &uint(0))], std::slice::from_ref(&ta)),
        "version 0",
    );
    assert_der_err(
        &header(&[ctx(0, &uint(1))], std::slice::from_ref(&ta)),
        "unsupported CCR version 1",
    );
    let mut with_null = seq(&[oid(CCR_OID)]);
    with_null.clear();
    with_null.extend(content_info(&tlv(
        0x30,
        &[seq(&[oid(SHA256_OID), null()]), gentime(T0), ta.clone()].concat(),
    )));
    assert_der_err(&with_null, "parameters must be absent");
    let wrong_alg = content_info(&tlv(
        0x30,
        &[seq(&[oid(&[43, 14, 3, 2, 26])]), gentime(T0), ta.clone()].concat(),
    ));
    assert_der_err(&wrong_alg, "id-sha256");
    let mut trailing = ccr(T0, std::slice::from_ref(&ta));
    trailing.push(0);
    assert_der_err(&trailing, "");
    let utc_time = content_info(&tlv(
        0x30,
        &[hash_alg(), tlv(0x17, b"260515000010Z"), ta.clone()].concat(),
    ));
    assert_der_err(&utc_time, "");
    assert_der_err(&ccr(T0, &[ta.clone(), ta.clone()]), "unexpected element");
    assert_der_err(&ccr(T0, &[ta.clone(), uint(1)]), "unexpected element");
    assert_der_err(
        &ccr(T0, &[ta.clone(), ctx(0, &uint(0))]),
        "unexpected element",
    );

    // Future state aspects with higher context tags are tolerated and retained.
    let future = ccr(
        T0,
        &[ta.clone(), ctx(6, &seq(&[uint(42)])), tlv(0x87, &[1, 2, 3])],
    );
    let decoded = Ccr::decode(&future).unwrap();
    assert_eq!(
        decoded.extensions(),
        [ctx(6, &seq(&[uint(42)])), tlv(0x87, &[1, 2, 3])]
    );
    assert_eq!(decoded.trust_anchors().unwrap().skis().len(), 1);
    // Aspects out of order are not tolerated (the [4] after [6] is "unexpected").
    assert_der_err(
        &ccr(T0, &[ctx(6, &seq(&[])), ta.clone()]),
        "unexpected element",
    );
}

#[test]
fn encoding_validates_by_default() {
    let mut tampered = FIXTURE.to_vec();
    tampered[752] ^= 1; // inside the ManifestState hash octet string
    let lenient = ValidationOptions::lenient();
    let decoded = Ccr::decode_with(&tampered, &lenient).unwrap();
    assert!(matches!(
        decoded.to_der(),
        Err(Error::HashMismatch {
            aspect: Aspect::Manifests,
            ..
        })
    ));
    assert!(matches!(
        decoded.validate(&ValidationOptions::strict()),
        Err(Error::HashMismatch {
            aspect: Aspect::Manifests,
            ..
        })
    ));
    assert!(
        decoded
            .validate(&ValidationOptions::strict().verify_hashes(false))
            .is_ok()
    );
    assert_eq!(
        decoded.to_der_with(&lenient).unwrap().as_ref(),
        tampered.as_slice()
    );
    assert_eq!(
        decoded
            .to_der_with(&ValidationOptions::strict().verify_hashes(false))
            .unwrap()
            .as_ref(),
        tampered.as_slice()
    );
    let mut out = Vec::new();
    assert!(matches!(
        decoded.write_der(&mut out),
        Err(Error::HashMismatch { .. })
    ));
    assert!(out.is_empty());
    decoded.write_der_with(&mut out, &lenient).unwrap();
    assert_eq!(out, tampered);
    #[cfg(feature = "gzip")]
    {
        assert!(decoded.to_der_gzip().is_err());
        let gz = decoded.to_der_gzip_with(&lenient).unwrap();
        assert_eq!(Ccr::decode_with(&gz, &lenient).unwrap(), decoded);
    }

    let unsorted = ccr(T0, &[ta_state(&[ski(2), ski(1)], None)]);
    let decoded = Ccr::decode_with(&unsorted, &lenient).unwrap();
    assert!(matches!(
        decoded.validate(&ValidationOptions::strict()),
        Err(Error::NotSorted {
            aspect: Aspect::TrustAnchors,
            ..
        })
    ));
    assert!(matches!(decoded.to_der(), Err(Error::NotSorted { .. })));
    assert_eq!(
        decoded.to_der_with(&lenient).unwrap().as_ref(),
        unsorted.as_slice()
    );

    // A redundant maxLength is kept as encoded, so a lenient round trip is exact.
    let redundant = ccr(
        T0,
        &[roa_state(
            &[roa_set(
                0,
                &[roa_family(1, &[roa_address(0, &[192, 0, 2], Some(24))])],
            )],
            None,
        )],
    );
    let decoded = Ccr::decode_with(&redundant, &lenient).unwrap();
    assert!(matches!(
        decoded.to_der(),
        Err(Error::Consistency {
            aspect: Aspect::RoaPayloads,
            ..
        })
    ));
    assert_eq!(
        decoded.to_der_with(&lenient).unwrap().as_ref(),
        redundant.as_slice()
    );

    // A validly decoded or built object passes and re-encodes unchanged.
    let valid = Ccr::decode(FIXTURE).unwrap();
    valid.validate(&ValidationOptions::strict()).unwrap();
    assert_eq!(valid.to_der().unwrap().as_ref(), FIXTURE);
}
