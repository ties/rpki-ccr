//! `AccessDescription` (RFC 5280 section 4.2.2.1) as used in SIA extensions.

use bcder::decode::{Constructed, DecodeError, Source};
use bcder::{Ia5String, Oid, Tag};
use bytes::Bytes;

use crate::oid;

/// An `AccessDescription`: an access method OID and a URI.
///
/// Only the `uniformResourceIdentifier` form of `GeneralName` is accepted,
/// as required for RPKI certificates by RFC 6487 section 4.8.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AccessDescription {
    access_method: Oid<Bytes>,
    uri: String,
}

impl AccessDescription {
    /// The `accessMethod` object identifier.
    pub fn access_method(&self) -> &Oid<Bytes> {
        &self.access_method
    }

    /// The `accessLocation` URI.
    pub fn uri(&self) -> &str {
        &self.uri
    }

    /// Whether the access method is `id-ad-signedObject` (the method used by
    /// the SIA extension of a manifest's EE certificate).
    pub fn is_signed_object(&self) -> bool {
        self.access_method == oid::SIGNED_OBJECT
    }

    pub(crate) fn take_opt_from<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Option<Self>, DecodeError<S::Error>> {
        cons.take_opt_sequence(|cons| {
            let access_method = Oid::take_from(cons)?;
            let uri = cons.take_value_if(Tag::CTX_6, |content| Ia5String::from_content(content))?;
            let uri = String::from_utf8(uri.into_bytes().to_vec())
                .map_err(|_| cons.content_err("accessLocation URI is not ASCII"))?;
            if uri.is_empty() {
                return Err(cons.content_err("accessLocation URI must not be empty"));
            }
            Ok(AccessDescription { access_method, uri })
        })
    }
}
