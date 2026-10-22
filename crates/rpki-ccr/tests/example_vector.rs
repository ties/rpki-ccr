//! Decodes the test vector from Appendix B of the specification and checks
//! every value listed in its textual dump.

use base64::prelude::*;
use chrono::{TimeZone, Utc};
use rpki_ccr::{Afi, Asn, Ccr, Digest, KeyIdentifier};

const DATA: &[u8] = include_bytes!("data/example.ccr");

fn b64(bytes: &[u8]) -> String {
    BASE64_STANDARD.encode(bytes)
}

fn ki(hex: &str) -> KeyIdentifier {
    KeyIdentifier::from_hex(hex).unwrap()
}

#[test]
fn header() {
    let ccr = Ccr::decode(DATA).unwrap();
    assert_eq!(
        b64(Digest::sha256(DATA).as_slice()),
        "qChLcuAmeva44qYAJrJ04E/wLiPjVU8XTKiDlgy7948="
    );
    assert_eq!(ccr.version(), 0);
    assert_eq!(ccr.hash_algorithm().to_string(), "sha256");
    assert_eq!(
        ccr.produced_at(),
        Utc.with_ymd_and_hms(2026, 5, 15, 0, 0, 10).unwrap()
    );
    assert!(ccr.extensions().is_empty());
    assert_eq!(Ccr::decode_der(DATA).unwrap(), ccr);
    assert_eq!(
        Ccr::decode_der_bytes(bytes::Bytes::from_static(DATA)).unwrap(),
        ccr
    );
}

#[test]
#[allow(clippy::type_complexity)]
fn manifest_state() {
    let ccr = Ccr::decode(DATA).unwrap();
    let state = ccr.manifests().unwrap();
    assert_eq!(
        b64(state.hash().as_slice()),
        "Y41AjkpiFr/AzR2/c8cItZOmICwuIaZOGqYdKaonbBI="
    );
    assert_eq!(
        state.most_recent_update(),
        Utc.with_ymd_and_hms(2026, 5, 15, 0, 0, 9).unwrap()
    );
    assert_eq!(state.len(), 4);

    // Encoded order is ascending by hash; the draft's dump lists them by AKI.
    let expected: [(&str, u64, &str, &str, i64, &str, &[&str]); 4] = [
        (
            "KF60zgHHRNmQSUXcsAcAPB2cB7kvToWUF60GADJuG5E=",
            1001,
            "A2DF042FE8B0006311E894851AC11411307B6043",
            "1321",
            1778803209,
            "rsync://example.net/ca4/QksbQZMC7YWsNrREt4l4dWAQ1sE.mft",
            &[],
        ),
        (
            "PH84tOOYN8EterYimODMa4sDj9HkMeyTNyCsy/9Q/48=",
            2040,
            "FACBD02CA47E3BD9666FCBD823B37DEDD0BCEE00",
            "0203",
            1778803207,
            "rsync://example.net/ca2/z0nzVS7SOB_9y6tapHk7-YuKkm8.mft",
            &[],
        ),
        (
            "vee5m+i2FKhzHwldksC2IX0WlVcHHVu3B8qAMnk+/Xo=",
            3995,
            "E7315EA515D7C20538681249D3E30D6777162585",
            "0508",
            1778803208,
            "rsync://example.net/ca3/sbhFzz4wTqsFo2NVRM8mWfsPBKQ.mft",
            &[],
        ),
        (
            "48JkKNPGfzSWjkALB4rFbaktXGSFaAV5qj0gj7zCCFY=",
            1729,
            "25F8CCFCEFC046D8DCD00FC0E444E0AA7B790F96",
            "0101",
            1778803206,
            "rsync://example.net/ca1/OaVUOIDSaLzUbeiz6VPogXxsK5o.mft",
            &[
                "A2DF042FE8B0006311E894851AC11411307B6043",
                "E7315EA515D7C20538681249D3E30D6777162585",
            ],
        ),
    ];
    for (instance, (hash, size, aki, seqnum, this_update, sia, subordinates)) in
        state.instances().iter().zip(expected)
    {
        assert_eq!(b64(instance.hash().as_slice()), hash);
        assert_eq!(instance.size(), size);
        assert_eq!(instance.aki().to_string(), aki);
        assert_eq!(instance.manifest_number().to_string(), seqnum);
        assert_eq!(
            instance.manifest_number().as_u128(),
            Some(u128::from_str_radix(seqnum, 16).unwrap())
        );
        assert_eq!(instance.this_update().timestamp(), this_update);
        assert_eq!(instance.locations().len(), 1);
        assert_eq!(instance.locations()[0].uri(), sia);
        assert!(instance.locations()[0].is_signed_object());
        assert_eq!(
            instance.locations()[0].access_method().to_string(),
            "1.3.6.1.5.5.7.48.11"
        );
        let subs: Vec<String> = instance
            .subordinates()
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(subs, subordinates);
    }
}

#[test]
fn roa_payload_state() {
    let ccr = Ccr::decode(DATA).unwrap();
    let state = ccr.roa_payloads().unwrap();
    assert_eq!(
        b64(state.hash().as_slice()),
        "D7GXkab9xejDm5KqaoYNDnApeP+5BX/9ExEBesfHTHo="
    );
    let vrps: Vec<String> = state.vrps().map(|v| v.to_string()).collect();
    assert_eq!(
        vrps,
        [
            "192.0.2.0/24 AS 0",
            "198.51.100.0/24-28 AS 65536",
            "2001:db8::/48 AS 65536",
            "3fff::/32 AS 65550",
            "3fff::/32 AS 65551",
        ]
    );
    assert_eq!(state.len(), 4);
    let sets = state.sets();
    assert_eq!(sets[0].as_id(), Asn::new(0));
    assert_eq!(
        sets[0].ip_addr_blocks()[0].addresses()[0].max_length(),
        None
    );
    assert_eq!(sets[1].as_id(), Asn::new(65536));
    assert_eq!(sets[1].ip_addr_blocks().len(), 2);
    assert_eq!(sets[1].ip_addr_blocks()[0].afi(), Afi::Ipv4);
    assert_eq!(
        sets[1].ip_addr_blocks()[0].addresses()[0].max_length(),
        Some(28)
    );
    assert_eq!(sets[1].ip_addr_blocks()[1].afi(), Afi::Ipv6);
    assert_eq!(
        sets[1].ip_addr_blocks()[1].addresses()[0]
            .prefix()
            .to_string(),
        "2001:db8::/48"
    );
    assert_eq!(sets[3].as_id(), Asn::new(65551));
}

#[test]
fn aspa_payload_state() {
    let ccr = Ccr::decode(DATA).unwrap();
    let state = ccr.aspa_payloads().unwrap();
    assert_eq!(
        b64(state.hash().as_slice()),
        "JzffEMksigs1JT58SSU+Yhq0UAiy27wg3beHrAslFFM="
    );
    let sets: Vec<(u32, Vec<u32>)> = state
        .sets()
        .iter()
        .map(|s| {
            (
                s.customer_as_id().into_u32(),
                s.providers().iter().map(|p| p.into_u32()).collect(),
            )
        })
        .collect();
    assert_eq!(
        sets,
        [
            (64511, vec![64496]),
            (65536, vec![65540, 65544]),
            (65550, vec![0])
        ]
    );
}

#[test]
fn trust_anchor_state() {
    let ccr = Ccr::decode(DATA).unwrap();
    let state = ccr.trust_anchors().unwrap();
    assert_eq!(
        b64(state.hash().as_slice()),
        "DuZCxMlR+Gx9e3jABEpX/YGGHtWvfQH1vquOP43XAxE="
    );
    assert_eq!(
        state.skis(),
        [
            ki("25F8CCFCEFC046D8DCD00FC0E444E0AA7B790F96"),
            ki("FACBD02CA47E3BD9666FCBD823B37DEDD0BCEE00"),
        ]
    );
}

#[test]
fn router_key_state() {
    let ccr = Ccr::decode(DATA).unwrap();
    let state = ccr.router_keys().unwrap();
    assert_eq!(
        b64(state.hash().as_slice()),
        "57BYFM3TNz47lJ6rbykyP58kkXVe/dOKFSLgOVi1GsE="
    );
    assert_eq!(state.len(), 2);
    let keys: Vec<(u32, String, String)> = state
        .router_keys()
        .map(|(asn, key)| {
            (
                asn.into_u32(),
                key.ski().to_string(),
                b64(key.spki().as_der()),
            )
        })
        .collect();
    assert_eq!(
        keys,
        [
            (
                65542,
                "88C5DE295A3276D69E9BB7469BD46EF972DE32AC".to_string(),
                "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE64mxtNmdKd1bxIjgWrGJutr11LDeA56L8cc1NLL/WW9RZ+rbi+G4rFSvfrEjxzRPt6tcNWpgEINq7tOR7J5dAg==".to_string(),
            ),
            (
                65542,
                "BE16E74E10F4BDF3F8C2618B024A9457DFBF89FA".to_string(),
                "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKjqTNoxSLK3UnLMNj2AdN/5sk5SITnYWK5e/JebKlJPFFxmBrOXWQyijRQBFFus7GtLLIZBYgp4K/u8o2/D4ig==".to_string(),
            ),
            (
                65551,
                "4602B621B017681E61EE1F4A5EFC1D02C3B46F2C".to_string(),
                "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4Xt6+dRDhjmH0QVmXlUPndJeXyzlMcsco6WkrjBf6NoX6gYahESgCm67xkBK4ZxhvCZRFWLxqH8cgT/Pgvl94w==".to_string(),
            ),
        ]
    );
    for (_, key) in state.router_keys() {
        assert!(key.spki().is_p256_ec());
        assert_eq!(key.spki().algorithm().to_string(), "1.2.840.10045.2.1");
        assert_eq!(key.spki().public_key().len(), 65);
    }
}
