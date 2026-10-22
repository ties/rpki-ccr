//! `ManifestInstance` and the `ManifestState` view.

use std::hash::{Hash, Hasher};
use std::sync::Arc;

use base64::prelude::*;
use chrono::{DateTime, Utc};
use num_bigint::BigUint;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyTuple};
use rpki_ccr::{AccessDescription, ManifestInstance, ManifestState};

use crate::access::PyAccessDescription;
use crate::ccr::Inner;
use crate::convert::{
    collect, digest, key_identifier, manifest_number_from_py, manifest_number_to_py,
};
use crate::error::to_pyerr;

/// A current manifest together with its issuer's subordinate CA certificates.
#[pyclass(frozen, eq, hash, module = "rpki_ccr", name = "ManifestInstance")]
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PyManifestInstance(pub ManifestInstance);

#[pymethods]
impl PyManifestInstance {
    #[new]
    #[pyo3(signature = (*, hash, size, aki, manifest_number, this_update, locations, subordinates = None))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        py: Python<'_>,
        hash: &[u8],
        size: u64,
        aki: &[u8],
        manifest_number: BigUint,
        this_update: DateTime<Utc>,
        locations: &Bound<'_, PyAny>,
        subordinates: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        let hash = digest("hash", hash)?;
        let aki = key_identifier("aki", aki)?;
        let manifest_number = manifest_number_from_py(&manifest_number)?;
        let locations = collect(locations, |item| {
            if let Ok(description) = item.cast::<PyAccessDescription>() {
                return Ok(description.get().0.clone());
            }
            AccessDescription::signed_object(item.extract::<String>()?).map_err(|e| to_pyerr(py, e))
        })?;
        let subordinates = match subordinates {
            Some(items) => collect(items, |item| {
                key_identifier("subordinate", item.extract::<&[u8]>()?)
            })?,
            None => Vec::new(),
        };
        ManifestInstance::new(
            hash,
            size,
            aki,
            manifest_number,
            this_update,
            locations,
            subordinates,
        )
        .map(PyManifestInstance)
        .map_err(|e| to_pyerr(py, e))
    }

    /// The SHA-256 digest of the manifest object.
    #[getter]
    fn hash<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.0.hash().as_slice())
    }

    /// The size of the manifest object in octets.
    #[getter]
    fn size(&self) -> u64 {
        self.0.size()
    }

    /// The key identifier of the manifest issuer.
    #[getter]
    fn aki<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.0.aki().as_slice())
    }

    /// The manifest number.
    #[getter]
    fn manifest_number(&self) -> BigUint {
        manifest_number_to_py(self.0.manifest_number())
    }

    /// The manifest's `thisUpdate` time.
    #[getter]
    fn this_update(&self) -> DateTime<Utc> {
        self.0.this_update()
    }

    /// The SIA access descriptions of the manifest's EE certificate.
    #[getter]
    fn locations(&self) -> Vec<PyAccessDescription> {
        self.0
            .locations()
            .iter()
            .cloned()
            .map(PyAccessDescription)
            .collect()
    }

    /// The key identifiers of the subordinate CA certificates.
    #[getter]
    fn subordinates<'py>(&self, py: Python<'py>) -> Vec<Bound<'py, PyBytes>> {
        self.0
            .subordinates()
            .iter()
            .map(|ski| PyBytes::new(py, ski.as_slice()))
            .collect()
    }

    /// The line format used by the specification's Appendix B and `rpki-client -f`.
    fn __str__(&self) -> String {
        let mut line = format!(
            "hash:{} size:{} aki:{} seqnum:{} thisupdate:{} sia:{}",
            BASE64_STANDARD.encode(self.0.hash().as_slice()),
            self.0.size(),
            self.0.aki(),
            self.0.manifest_number(),
            self.0.this_update().timestamp(),
            self.0
                .locations()
                .iter()
                .map(AccessDescription::uri)
                .collect::<Vec<_>>()
                .join(",")
        );
        if !self.0.subordinates().is_empty() {
            line.push_str(" subordinates:");
            line.push_str(
                &self
                    .0
                    .subordinates()
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
            );
        }
        line
    }

    fn __repr__(&self) -> String {
        format!(
            "ManifestInstance(hash='{}', size={}, aki='{}', manifest_number={}, this_update={:?}, locations={}, subordinates={})",
            self.0.hash(),
            self.0.size(),
            self.0.aki(),
            manifest_number_to_py(self.0.manifest_number()),
            self.0.this_update(),
            self.0.locations().len(),
            self.0.subordinates().len(),
        )
    }

    fn __getnewargs_ex__<'py>(
        &self,
        py: Python<'py>,
    ) -> PyResult<(Bound<'py, PyTuple>, Bound<'py, PyDict>)> {
        let kwargs = PyDict::new(py);
        kwargs.set_item("hash", self.hash(py))?;
        kwargs.set_item("size", self.size())?;
        kwargs.set_item("aki", self.aki(py))?;
        kwargs.set_item("manifest_number", self.manifest_number())?;
        kwargs.set_item("this_update", self.this_update())?;
        kwargs.set_item("locations", self.locations())?;
        kwargs.set_item("subordinates", self.subordinates(py))?;
        Ok((PyTuple::empty(py), kwargs))
    }

    fn __copy__<'py>(slf: Bound<'py, Self>) -> Bound<'py, Self> {
        slf
    }

    fn __deepcopy__<'py>(slf: Bound<'py, Self>, _memo: Bound<'py, PyAny>) -> Bound<'py, Self> {
        slf
    }
}

/// The manifest state of a CCR: a sequence of `ManifestInstance`.
#[pyclass(
    frozen,
    eq,
    hash,
    sequence,
    module = "rpki_ccr",
    name = "ManifestState"
)]
pub struct PyManifestState {
    pub(crate) inner: Arc<Inner>,
}

impl PyManifestState {
    fn state(&self) -> &ManifestState {
        self.inner
            .ccr
            .manifests()
            .expect("view exists only when the aspect is present")
    }
}

impl PartialEq for PyManifestState {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner) || self.state() == other.state()
    }
}

impl Eq for PyManifestState {}

impl Hash for PyManifestState {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.state().hash().as_slice().hash(state);
    }
}

sequence_view!(
    extra: {
    /// The digest declared over the DER-encoded instances.
    #[getter]
    fn hash<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.state().hash().as_slice())
    }

    /// The most recent `thisUpdate` among the instances, or the POSIX epoch.
    #[getter]
    fn most_recent_update(&self) -> DateTime<Utc> {
        self.state().most_recent_update()
    }

    fn __repr__(&self) -> String {
        format!(
            "ManifestState(len={}, most_recent_update={:?}, hash='{}')",
            self.state().len(),
            self.state().most_recent_update(),
            self.state().hash()
        )
    }
    },
    view: PyManifestState,
    iter: ManifestStateIter,
    attr: "manifests",
    elem: ManifestInstance,
    len: |inner| inner.ccr.manifests().map_or(0, ManifestState::len),
    get: |inner, index| inner.ccr.manifests().expect("present").instances()[index].clone(),
    to_py: |py, value| Ok(PyManifestInstance(value).into_pyobject(py)?.into_any()),
    needle: |obj| obj.cast::<PyManifestInstance>().ok().map(|i| i.get().0.clone()),
);
