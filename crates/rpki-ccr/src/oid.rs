//! Object identifiers used by the CCR profile.

use bcder::{ConstOid, Oid};

/// `id-ct-rpkiCanonicalCacheRepresentation`, 1.2.840.113549.1.9.16.1.54.
pub const CCR_CONTENT_TYPE: ConstOid = Oid(&[42, 134, 72, 134, 247, 13, 1, 9, 16, 1, 54]);

/// `id-sha256`, 2.16.840.1.101.3.4.2.1.
pub const SHA256: ConstOid = Oid(&[96, 134, 72, 1, 101, 3, 4, 2, 1]);

/// `id-ad-signedObject`, 1.3.6.1.5.5.7.48.11 (the SIA access method of a
/// manifest's EE certificate, RFC 6487 section 4.8.8.2).
pub const SIGNED_OBJECT: ConstOid = Oid(&[43, 6, 1, 5, 5, 7, 48, 11]);

/// `id-ecPublicKey`, 1.2.840.10045.2.1.
pub const EC_PUBLIC_KEY: ConstOid = Oid(&[42, 134, 72, 206, 61, 2, 1]);

/// `secp256r1` (P-256), 1.2.840.10045.3.1.7.
pub const SECP256R1: ConstOid = Oid(&[42, 134, 72, 206, 61, 3, 1, 7]);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dotted_forms() {
        assert_eq!(CCR_CONTENT_TYPE.to_string(), "1.2.840.113549.1.9.16.1.54");
        assert_eq!(SHA256.to_string(), "2.16.840.1.101.3.4.2.1");
        assert_eq!(SIGNED_OBJECT.to_string(), "1.3.6.1.5.5.7.48.11");
        assert_eq!(EC_PUBLIC_KEY.to_string(), "1.2.840.10045.2.1");
        assert_eq!(SECP256R1.to_string(), "1.2.840.10045.3.1.7");
    }
}
