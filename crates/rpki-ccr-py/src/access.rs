//! `AccessDescription`.

use pyo3::prelude::*;
use rpki_ccr::AccessDescription;

use crate::convert::{oid_from_str, repr_str};
use crate::error::to_pyerr;

const SIGNED_OBJECT: &str = "1.3.6.1.5.5.7.48.11";

/// An SIA access description: an access method OID and a URI.
#[pyclass(frozen, eq, hash, ord, module = "rpki_ccr", name = "AccessDescription")]
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PyAccessDescription(pub AccessDescription);

#[pymethods]
impl PyAccessDescription {
    /// The `id-ad-signedObject` access method, the default.
    #[classattr]
    const SIGNED_OBJECT: &'static str = SIGNED_OBJECT;

    #[new]
    #[pyo3(signature = (uri, access_method = SIGNED_OBJECT))]
    fn new(py: Python<'_>, uri: String, access_method: &str) -> PyResult<Self> {
        let oid = oid_from_str(access_method)?;
        AccessDescription::new(oid, uri)
            .map(PyAccessDescription)
            .map_err(|e| to_pyerr(py, e))
    }

    /// The URI.
    #[getter]
    fn uri(&self) -> &str {
        self.0.uri()
    }

    /// The access method as a dotted OID.
    #[getter]
    fn access_method(&self) -> String {
        self.0.access_method().to_string()
    }

    /// Whether the access method is `id-ad-signedObject`.
    #[getter]
    fn is_signed_object(&self) -> bool {
        self.0.is_signed_object()
    }

    fn __repr__(&self) -> String {
        if self.0.is_signed_object() {
            format!("AccessDescription({})", repr_str(self.0.uri()))
        } else {
            format!(
                "AccessDescription({}, access_method='{}')",
                repr_str(self.0.uri()),
                self.0.access_method()
            )
        }
    }

    fn __getnewargs__(&self) -> (String, String) {
        (self.0.uri().to_string(), self.0.access_method().to_string())
    }

    fn __copy__<'py>(slf: Bound<'py, Self>) -> Bound<'py, Self> {
        slf
    }

    fn __deepcopy__<'py>(slf: Bound<'py, Self>, _memo: Bound<'py, PyAny>) -> Bound<'py, Self> {
        slf
    }
}
