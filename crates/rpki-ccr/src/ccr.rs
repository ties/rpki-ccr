//! The top-level `RpkiCanonicalCacheRepresentation` structure.

use std::convert::Infallible;
use std::fmt;
use std::path::Path;

use bcder::decode::{Constructed, Content, DecodeError, Source};
use bcder::{Mode, Oid, Tag};
use bytes::Bytes;
use chrono::{DateTime, Utc};

use crate::time::take_generalized_time;
use crate::validate::{self, HashedPayload};
use crate::{
    AspaPayloadState, DecodeOptions, Error, ManifestState, RoaPayloadState, RouterKeyState,
    TrustAnchorState, oid,
};

/// The digest algorithm of a CCR. Only SHA-256 is defined.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HashAlgorithm {
    /// SHA-256, OID 2.16.840.1.101.3.4.2.1.
    Sha256,
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("sha256")
    }
}

/// A decoded Canonical Cache Representation.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Ccr {
    produced_at: DateTime<Utc>,
    manifests: Option<ManifestState>,
    roa_payloads: Option<RoaPayloadState>,
    aspa_payloads: Option<AspaPayloadState>,
    trust_anchors: Option<TrustAnchorState>,
    router_keys: Option<RouterKeyState>,
    extensions: Vec<Bytes>,
}

impl Ccr {
    /// Decodes a CCR file with strict validation.
    ///
    /// Gzip-compressed input (`application/rpki-ccr+gzip`) is detected by its
    /// magic number and inflated when the `gzip` feature is enabled.
    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        Self::decode_with(data, &DecodeOptions::strict())
    }

    /// Decodes a CCR file, possibly gzip-compressed, with the given options.
    pub fn decode_with(data: &[u8], options: &DecodeOptions) -> Result<Self, Error> {
        if Self::is_gzip(data) {
            let inflated = inflate(data)?;
            Self::decode_der_bytes_with(Bytes::from(inflated), options)
        } else {
            Self::decode_der_bytes_with(Bytes::copy_from_slice(data), options)
        }
    }

    /// Decodes an uncompressed DER-encoded CCR with strict validation.
    pub fn decode_der(der: &[u8]) -> Result<Self, Error> {
        Self::decode_der_with(der, &DecodeOptions::strict())
    }

    /// Decodes an uncompressed DER-encoded CCR with the given options.
    pub fn decode_der_with(der: &[u8], options: &DecodeOptions) -> Result<Self, Error> {
        Self::decode_der_bytes_with(Bytes::copy_from_slice(der), options)
    }

    /// Decodes an uncompressed DER-encoded CCR held in shared bytes with
    /// strict validation. Public keys and other byte values are sliced from
    /// the input without copying.
    pub fn decode_der_bytes(der: Bytes) -> Result<Self, Error> {
        Self::decode_der_bytes_with(der, &DecodeOptions::strict())
    }

    /// Decodes an uncompressed DER-encoded CCR held in shared bytes with the
    /// given options.
    pub fn decode_der_bytes_with(der: Bytes, options: &DecodeOptions) -> Result<Self, Error> {
        let (ccr, hashed) = parse(der)?;
        validate::validate(&ccr, &hashed, options)?;
        Ok(ccr)
    }

    /// Reads and decodes a CCR file, possibly gzip-compressed, with strict
    /// validation.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, Error> {
        Self::from_file_with(path, &DecodeOptions::strict())
    }

    /// Reads and decodes a CCR file, possibly gzip-compressed, with the given
    /// options.
    pub fn from_file_with(path: impl AsRef<Path>, options: &DecodeOptions) -> Result<Self, Error> {
        let data = std::fs::read(path)?;
        Self::decode_with(&data, options)
    }

    /// Whether `data` starts with the gzip magic number.
    pub fn is_gzip(data: &[u8]) -> bool {
        data.starts_with(&[0x1f, 0x8b])
    }

    /// The format version. Always 0 for this specification.
    pub fn version(&self) -> u8 {
        0
    }

    /// The digest algorithm used for the state aspect hashes.
    pub fn hash_algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::Sha256
    }

    /// The time at which the CCR was finalized.
    pub fn produced_at(&self) -> DateTime<Utc> {
        self.produced_at
    }

    /// The manifest state (`mfts`), if present.
    pub fn manifests(&self) -> Option<&ManifestState> {
        self.manifests.as_ref()
    }

    /// The ROA payload state (`vrps`), if present.
    pub fn roa_payloads(&self) -> Option<&RoaPayloadState> {
        self.roa_payloads.as_ref()
    }

    /// The ASPA payload state (`vaps`), if present.
    pub fn aspa_payloads(&self) -> Option<&AspaPayloadState> {
        self.aspa_payloads.as_ref()
    }

    /// The trust anchor state (`tas`), if present.
    pub fn trust_anchors(&self) -> Option<&TrustAnchorState> {
        self.trust_anchors.as_ref()
    }

    /// The router key state (`rks`), if present.
    pub fn router_keys(&self) -> Option<&RouterKeyState> {
        self.router_keys.as_ref()
    }

    /// The raw DER encodings of any state aspects unknown to this crate
    /// (context-specific tags above `[5]`, anticipated by the extension
    /// marker in the specification). Usually empty.
    pub fn extensions(&self) -> &[Bytes] {
        &self.extensions
    }
}

#[cfg(feature = "gzip")]
fn inflate(data: &[u8]) -> Result<Vec<u8>, Error> {
    use std::io::Read as _;

    let mut out = Vec::new();
    flate2::read::MultiGzDecoder::new(data).read_to_end(&mut out)?;
    Ok(out)
}

#[cfg(not(feature = "gzip"))]
fn inflate(_data: &[u8]) -> Result<Vec<u8>, Error> {
    Err(Error::GzipUnsupported)
}

/// Decodes the CMS `ContentInfo` wrapper and the CCR content.
fn parse(der: Bytes) -> Result<(Ccr, Vec<HashedPayload>), DecodeError<Infallible>> {
    let trailing = der_tlv_len(&der).is_some_and(|len| len < der.len());
    Mode::Der.decode(der, |cons| {
        // bcder does not check for input after a top-level value; a CCR file
        // is exactly one ContentInfo.
        if trailing {
            return Err(cons.content_err("trailing data after the CMS ContentInfo"));
        }
        cons.take_sequence(|cons| {
            let content_type = Oid::take_from(cons)?;
            if content_type != oid::CCR_CONTENT_TYPE {
                return Err(cons.content_err(format!(
                    "unexpected CMS content type {content_type}, expected {}",
                    oid::CCR_CONTENT_TYPE
                )));
            }
            cons.take_constructed_if(Tag::CTX_0, |cons| cons.take_sequence(parse_content))
        })
    })
}

/// Returns the total length of the DER TLV at the start of `der`, or `None`
/// if the header is malformed (bcder reports those errors itself).
fn der_tlv_len(der: &[u8]) -> Option<usize> {
    let mut i = 0;
    if der.first()? & 0x1f == 0x1f {
        while der.get(i + 1)? & 0x80 != 0 {
            i += 1;
        }
        i += 1;
    }
    i += 1;
    let first = *der.get(i)?;
    i += 1;
    let len = if first < 0x80 {
        usize::from(first)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > std::mem::size_of::<usize>() {
            return None;
        }
        let bytes = der.get(i..i + count)?;
        i += count;
        bytes
            .iter()
            .fold(0usize, |acc, &b| (acc << 8) | usize::from(b))
    };
    i.checked_add(len)
}

/// Decodes `RpkiCanonicalCacheRepresentation`.
fn parse_content<S: Source>(
    cons: &mut Constructed<S>,
) -> Result<(Ccr, Vec<HashedPayload>), DecodeError<S::Error>> {
    match cons.take_opt_constructed_if(Tag::CTX_0, |cons| cons.take_u64())? {
        None => {}
        Some(0) => {
            return Err(
                cons.content_err("version 0 must not be encoded explicitly (DEFAULT under DER)")
            );
        }
        Some(version) => {
            return Err(cons.content_err(format!("unsupported CCR version {version}")));
        }
    }
    cons.take_sequence(|cons| {
        let algorithm = Oid::take_from(cons)?;
        if algorithm != oid::SHA256 {
            return Err(cons.content_err(format!("hashAlg must be id-sha256, found {algorithm}")));
        }
        if !cons.capture_all()?.is_empty() {
            return Err(cons.content_err("hashAlg parameters must be absent"));
        }
        Ok(())
    })?;
    let produced_at = take_generalized_time(cons)?;

    let mut hashed = Vec::new();
    let manifests = cons.take_opt_constructed_if(Tag::CTX_1, |cons| {
        ManifestState::take_from(cons, &mut hashed)
    })?;
    let roa_payloads = cons.take_opt_constructed_if(Tag::CTX_2, |cons| {
        RoaPayloadState::take_from(cons, &mut hashed)
    })?;
    let aspa_payloads = cons.take_opt_constructed_if(Tag::CTX_3, |cons| {
        AspaPayloadState::take_from(cons, &mut hashed)
    })?;
    let trust_anchors = cons.take_opt_constructed_if(Tag::CTX_4, |cons| {
        TrustAnchorState::take_from(cons, &mut hashed)
    })?;
    let router_keys = cons.take_opt_constructed_if(Tag::CTX_5, |cons| {
        RouterKeyState::take_from(cons, &mut hashed)
    })?;
    let extensions = take_extensions(cons)?;

    if manifests.is_none()
        && roa_payloads.is_none()
        && aspa_payloads.is_none()
        && trust_anchors.is_none()
        && router_keys.is_none()
    {
        return Err(cons.content_err(
            "at least one state aspect (mfts, vrps, vaps, tas or rks) must be present",
        ));
    }

    Ok((
        Ccr {
            produced_at,
            manifests,
            roa_payloads,
            aspa_payloads,
            trust_anchors,
            router_keys,
            extensions,
        },
        hashed,
    ))
}

/// Captures any trailing state aspects unknown to this crate. Only
/// context-specific tags above `[5]` are tolerated, as anticipated by the
/// extension marker in the ASN.1 module.
fn take_extensions<S: Source>(
    cons: &mut Constructed<S>,
) -> Result<Vec<Bytes>, DecodeError<S::Error>> {
    let mut extensions = Vec::new();
    loop {
        let mut found = false;
        let captured = cons.capture(|cons| {
            found = cons
                .take_opt_value(|tag, content| {
                    if !tag.is_context_specific() || tag.number() <= 5 {
                        return Err(
                            content.content_err("unexpected element after the state aspects")
                        );
                    }
                    match content {
                        Content::Primitive(prim) => prim.skip_all(),
                        Content::Constructed(cons) => cons.skip_all(),
                    }
                })?
                .is_some();
            Ok(())
        })?;
        if !found {
            break;
        }
        extensions.push(captured.into_bytes());
    }
    Ok(extensions)
}

#[cfg(test)]
mod tests {
    use super::der_tlv_len;

    #[test]
    fn tlv_length() {
        assert_eq!(der_tlv_len(&[0x30, 0x00]), Some(2));
        assert_eq!(der_tlv_len(&[0x30, 0x03, 1, 2, 3]), Some(5));
        assert_eq!(der_tlv_len(&[0x30, 0x82, 0x05, 0xf4]), Some(4 + 1524));
        assert_eq!(der_tlv_len(&[0x30, 0x81, 0x80]), Some(3 + 128));
        assert_eq!(der_tlv_len(&[0xbf, 0x81, 0x01, 0x02, 0, 0]), Some(6));
        assert_eq!(der_tlv_len(&[0x30]), None);
        assert_eq!(der_tlv_len(&[0x30, 0x82, 0x05]), None);
        assert_eq!(der_tlv_len(&[0x30, 0x80]), None);
        assert_eq!(der_tlv_len(&[]), None);
    }
}
