//! A tiny DER builder for constructing (and deliberately breaking) CCR files.
#![allow(dead_code)]

use sha2::{Digest as _, Sha256};

pub const CCR_OID: &[u8] = &[42, 134, 72, 134, 247, 13, 1, 9, 16, 1, 54];
pub const SHA256_OID: &[u8] = &[96, 134, 72, 1, 101, 3, 4, 2, 1];
pub const SIGNED_OBJECT_OID: &[u8] = &[43, 6, 1, 5, 5, 7, 48, 11];
pub const EC_PUBLIC_KEY_OID: &[u8] = &[42, 134, 72, 206, 61, 2, 1];
pub const SECP256R1_OID: &[u8] = &[42, 134, 72, 206, 61, 3, 1, 7];

pub const T0: &str = "20260515000010Z";
pub const EPOCH: &str = "19700101000000Z";

fn length(n: usize) -> Vec<u8> {
    if n < 128 {
        return vec![n as u8];
    }
    let bytes = n.to_be_bytes();
    let first = bytes.iter().position(|&b| b != 0).unwrap();
    let mut out = vec![0x80 | (bytes.len() - first) as u8];
    out.extend_from_slice(&bytes[first..]);
    out
}

pub fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(length(body.len()));
    out.extend_from_slice(body);
    out
}

pub fn seq(items: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &items.concat())
}

/// Explicitly tagged constructed context-specific element `[n]`.
pub fn ctx(n: u8, body: &[u8]) -> Vec<u8> {
    tlv(0xa0 | n, body)
}

pub fn oct(body: &[u8]) -> Vec<u8> {
    tlv(0x04, body)
}

pub fn uint(value: u64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let first = bytes.iter().position(|&b| b != 0).unwrap_or(7);
    let mut body = bytes[first..].to_vec();
    if body[0] & 0x80 != 0 {
        body.insert(0, 0);
    }
    tlv(0x02, &body)
}

pub fn int_raw(content: &[u8]) -> Vec<u8> {
    tlv(0x02, content)
}

pub fn oid(body: &[u8]) -> Vec<u8> {
    tlv(0x06, body)
}

pub fn gentime(s: &str) -> Vec<u8> {
    tlv(0x18, s.as_bytes())
}

pub fn bitstr(unused: u8, bytes: &[u8]) -> Vec<u8> {
    let mut body = vec![unused];
    body.extend_from_slice(bytes);
    tlv(0x03, &body)
}

/// `GeneralName` `uniformResourceIdentifier` (`[6] IMPLICIT IA5String`).
pub fn uri(s: &str) -> Vec<u8> {
    tlv(0x86, s.as_bytes())
}

pub fn null() -> Vec<u8> {
    vec![0x05, 0x00]
}

pub fn sha256(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

pub fn ski(n: u8) -> [u8; 20] {
    [n; 20]
}

pub fn digest(n: u8) -> [u8; 32] {
    [n; 32]
}

pub fn hash_alg() -> Vec<u8> {
    seq(&[oid(SHA256_OID)])
}

pub fn content_info(content: &[u8]) -> Vec<u8> {
    seq(&[oid(CCR_OID), ctx(0, content)])
}

/// A complete CCR file with the standard header and the given tagged aspects.
pub fn ccr(produced_at: &str, aspects: &[Vec<u8>]) -> Vec<u8> {
    let mut body = hash_alg();
    body.extend(gentime(produced_at));
    for aspect in aspects {
        body.extend_from_slice(aspect);
    }
    content_info(&tlv(0x30, &body))
}

/// `[tag] SEQUENCE { payload, middle..., hash }` with the hash computed over
/// `payload` unless overridden.
pub fn hashed_state(tag: u8, payload: &[u8], middle: &[u8], hash: Option<&[u8]>) -> Vec<u8> {
    let hash = hash.map(<[u8]>::to_vec).unwrap_or_else(|| sha256(payload));
    let mut body = payload.to_vec();
    body.extend_from_slice(middle);
    body.extend(oct(&hash));
    ctx(tag, &tlv(0x30, &body))
}

pub fn access_description(location: &str) -> Vec<u8> {
    seq(&[oid(SIGNED_OBJECT_OID), uri(location)])
}

#[allow(clippy::too_many_arguments)]
pub fn mft_instance(
    hash: &[u8],
    size: u64,
    aki: &[u8],
    seqnum: &[u8],
    this_update: &str,
    locations: &[&str],
    subordinates: Option<&[[u8; 20]]>,
) -> Vec<u8> {
    let mut items = vec![
        oct(hash),
        uint(size),
        oct(aki),
        int_raw(seqnum),
        gentime(this_update),
        seq(&locations
            .iter()
            .map(|l| access_description(l))
            .collect::<Vec<_>>()),
    ];
    if let Some(subs) = subordinates {
        items.push(seq(&subs.iter().map(|s| oct(s)).collect::<Vec<_>>()));
    }
    seq(&items)
}

pub fn mft_state(instances: &[Vec<u8>], most_recent_update: &str, hash: Option<&[u8]>) -> Vec<u8> {
    hashed_state(1, &seq(instances), &gentime(most_recent_update), hash)
}

pub fn roa_address(unused: u8, bits: &[u8], max_length: Option<u64>) -> Vec<u8> {
    let mut items = vec![bitstr(unused, bits)];
    if let Some(max) = max_length {
        items.push(uint(max));
    }
    seq(&items)
}

pub fn roa_family(afi: u16, addresses: &[Vec<u8>]) -> Vec<u8> {
    seq(&[oct(&afi.to_be_bytes()), seq(addresses)])
}

pub fn roa_set(asn: u64, families: &[Vec<u8>]) -> Vec<u8> {
    seq(&[uint(asn), seq(families)])
}

pub fn roa_state(sets: &[Vec<u8>], hash: Option<&[u8]>) -> Vec<u8> {
    hashed_state(2, &seq(sets), &[], hash)
}

pub fn aspa_set(customer: u64, providers: &[u64]) -> Vec<u8> {
    seq(&[
        uint(customer),
        seq(&providers.iter().map(|p| uint(*p)).collect::<Vec<_>>()),
    ])
}

pub fn aspa_state(sets: &[Vec<u8>], hash: Option<&[u8]>) -> Vec<u8> {
    hashed_state(3, &seq(sets), &[], hash)
}

pub fn ta_state(skis: &[[u8; 20]], hash: Option<&[u8]>) -> Vec<u8> {
    hashed_state(
        4,
        &seq(&skis.iter().map(|s| oct(s)).collect::<Vec<_>>()),
        &[],
        hash,
    )
}

pub fn spki_p256(point_byte: u8) -> Vec<u8> {
    let mut point = vec![0x04];
    point.extend(std::iter::repeat_n(point_byte, 64));
    seq(&[
        seq(&[oid(EC_PUBLIC_KEY_OID), oid(SECP256R1_OID)]),
        bitstr(0, &point),
    ])
}

pub fn router_key(ski: &[u8], spki: &[u8]) -> Vec<u8> {
    seq(&[oct(ski), spki.to_vec()])
}

pub fn router_key_set(asn: u64, keys: &[Vec<u8>]) -> Vec<u8> {
    seq(&[uint(asn), seq(keys)])
}

pub fn router_key_state(sets: &[Vec<u8>], hash: Option<&[u8]>) -> Vec<u8> {
    hashed_state(5, &seq(sets), &[], hash)
}
