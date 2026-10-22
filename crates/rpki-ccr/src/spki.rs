//! `SubjectPublicKeyInfo` (RFC 5280 section 4.1.2.7).

use bcder::decode::{Constructed, DecodeError, Source};
use bcder::{BitString, Oid};
use bytes::Bytes;

use crate::oid;

/// DER encoding of the `secp256r1` named-curve parameters.
const SECP256R1_PARAMETERS: [u8; 10] = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

/// A subject public key with its algorithm identifier.
///
/// The complete DER encoding is retained so that it can be re-emitted
/// byte-for-byte.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SubjectPublicKeyInfo {
    der: Bytes,
    algorithm: Oid<Bytes>,
    parameters: Option<Bytes>,
    public_key: Bytes,
}

impl SubjectPublicKeyInfo {
    /// The complete DER encoding of the `SubjectPublicKeyInfo`.
    pub fn as_der(&self) -> &[u8] {
        &self.der
    }

    /// The complete DER encoding as shared bytes.
    pub fn to_der_bytes(&self) -> Bytes {
        self.der.clone()
    }

    /// The `algorithm` object identifier.
    pub fn algorithm(&self) -> &Oid<Bytes> {
        &self.algorithm
    }

    /// The DER encoding of the algorithm `parameters`, if present.
    pub fn parameters(&self) -> Option<&[u8]> {
        self.parameters.as_deref()
    }

    /// The `subjectPublicKey` octets (the bit string has no unused bits).
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Whether this is an ECDSA P-256 key as required for BGPsec router
    /// certificates (RFC 8208 section 3.1).
    pub fn is_p256_ec(&self) -> bool {
        self.algorithm == oid::EC_PUBLIC_KEY
            && self.parameters.as_deref() == Some(&SECP256R1_PARAMETERS[..])
    }

    pub(crate) fn take_from<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        let mut inner = None;
        let der = cons.capture(|cons| {
            inner = Some(cons.take_sequence(|cons| {
                let (algorithm, parameters) = cons.take_sequence(|cons| {
                    let algorithm = Oid::take_from(cons)?;
                    let parameters = cons.capture_all()?;
                    let parameters = (!parameters.is_empty()).then(|| parameters.into_bytes());
                    Ok((algorithm, parameters))
                })?;
                let public_key = BitString::take_from(cons)?;
                if public_key.unused() != 0 {
                    return Err(cons.content_err("subjectPublicKey must not have unused bits"));
                }
                Ok((algorithm, parameters, public_key.octet_bytes()))
            })?);
            Ok(())
        })?;
        let (algorithm, parameters, public_key) =
            inner.expect("capture closure populates the parsed value on success");
        Ok(SubjectPublicKeyInfo {
            der: der.into_bytes(),
            algorithm,
            parameters,
            public_key,
        })
    }
}
