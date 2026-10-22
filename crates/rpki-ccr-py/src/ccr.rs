//! The `Ccr` class.

use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use chrono::{DateTime, Utc};
use pyo3::prelude::*;
use pyo3::pybacked::PyBackedBytes;
use pyo3::types::PyBytes;
use rpki_ccr::{
    AspaPayloadState, Ccr, ManifestState, RoaPayloadState, RouterKeySet, RouterKeyState,
    TrustAnchorState, ValidationOptions,
};

use crate::aspa::{PyAspaPayloadSet, PyAspaPayloadState};
use crate::convert::{collect, key_identifier};
use crate::error::{os_error, to_pyerr};
use crate::manifest::{PyManifestInstance, PyManifestState};
use crate::resources::PyVrp;
use crate::roa::{PyRoaPayloadState, VrpIndex};
use crate::router_key::{PyRouterKey, PyRouterKeyState, RouterKeyIndex};
use crate::trust_anchor::PyTrustAnchorState;

/// The decoded or built CCR shared by a `Ccr` and all views derived from it.
pub(crate) struct Inner {
    pub(crate) ccr: Ccr,
    pub(crate) vrp_index: OnceLock<VrpIndex>,
    pub(crate) router_key_index: OnceLock<RouterKeyIndex>,
}

impl Inner {
    fn new(ccr: Ccr) -> Arc<Self> {
        Arc::new(Inner {
            ccr,
            vrp_index: OnceLock::new(),
            router_key_index: OnceLock::new(),
        })
    }
}

enum FileError {
    Io(std::io::Error),
    Decode(rpki_ccr::Error),
}

fn options(
    verify_hashes: bool,
    check_ordering: bool,
    check_consistency: bool,
) -> ValidationOptions {
    ValidationOptions::strict()
        .verify_hashes(verify_hashes)
        .check_ordering(check_ordering)
        .check_consistency(check_consistency)
}

/// A Canonical Cache Representation.
#[pyclass(frozen, eq, hash, module = "rpki_ccr", name = "Ccr")]
pub struct PyCcr {
    pub(crate) inner: Arc<Inner>,
}

impl PartialEq for PyCcr {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner) || self.inner.ccr == other.inner.ccr
    }
}

impl Eq for PyCcr {}

impl Hash for PyCcr {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let ccr = &self.inner.ccr;
        ccr.produced_at().hash(state);
        ccr.manifests().map(|s| *s.hash()).hash(state);
        ccr.roa_payloads().map(|s| *s.hash()).hash(state);
        ccr.aspa_payloads().map(|s| *s.hash()).hash(state);
        ccr.trust_anchors().map(|s| *s.hash()).hash(state);
        ccr.router_keys().map(|s| *s.hash()).hash(state);
        ccr.extensions().hash(state);
    }
}

#[pymethods]
impl PyCcr {
    #[new]
    #[pyo3(signature = (produced_at, *, manifests = None, roa_payloads = None, aspa_payloads = None, trust_anchors = None, router_keys = None))]
    fn new(
        py: Python<'_>,
        produced_at: DateTime<Utc>,
        manifests: Option<&Bound<'_, PyAny>>,
        roa_payloads: Option<&Bound<'_, PyAny>>,
        aspa_payloads: Option<&Bound<'_, PyAny>>,
        trust_anchors: Option<&Bound<'_, PyAny>>,
        router_keys: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        let manifests = manifests
            .map(|items| {
                collect(items, |item| {
                    Ok(item.cast::<PyManifestInstance>()?.get().0.clone())
                })
            })
            .transpose()?;
        let vrps = roa_payloads
            .map(|items| collect(items, |item| Ok(item.cast::<PyVrp>()?.get().0)))
            .transpose()?;
        let aspas = aspa_payloads
            .map(|items| {
                collect(items, |item| {
                    Ok(item.cast::<PyAspaPayloadSet>()?.get().0.clone())
                })
            })
            .transpose()?;
        let skis = trust_anchors
            .map(|items| {
                collect(items, |item| {
                    key_identifier("trust anchor", item.extract::<&[u8]>()?)
                })
            })
            .transpose()?;
        let keys = router_keys
            .map(|items| {
                collect(items, |item| {
                    let key = item.cast::<PyRouterKey>()?.get();
                    Ok((key.asn, key.key.clone()))
                })
            })
            .transpose()?;

        let build = move || -> Result<Ccr, rpki_ccr::Error> {
            let mut builder = Ccr::builder(produced_at);
            if let Some(instances) = manifests {
                builder = builder.manifests(ManifestState::new(instances));
            }
            if let Some(vrps) = vrps {
                builder = builder.roa_payloads(RoaPayloadState::from_vrps(vrps));
            }
            if let Some(sets) = aspas {
                builder = builder.aspa_payloads(AspaPayloadState::new(sets)?);
            }
            if let Some(skis) = skis {
                builder = builder.trust_anchors(TrustAnchorState::new(skis)?);
            }
            if let Some(keys) = keys {
                let sets = keys
                    .into_iter()
                    .map(|(asn, key)| RouterKeySet::new(asn, vec![key]))
                    .collect::<Result<Vec<_>, _>>()?;
                builder = builder.router_keys(RouterKeyState::new(sets)?);
            }
            builder.build()
        };
        let ccr = py.detach(build).map_err(|e| to_pyerr(py, e))?;
        Ok(PyCcr {
            inner: Inner::new(ccr),
        })
    }

    /// Decodes a CCR file (plain DER or gzip-compressed).
    #[staticmethod]
    #[pyo3(signature = (data, *, verify_hashes = true, check_ordering = true, check_consistency = true))]
    fn decode(
        py: Python<'_>,
        data: PyBackedBytes,
        verify_hashes: bool,
        check_ordering: bool,
        check_consistency: bool,
    ) -> PyResult<Self> {
        let opts = options(verify_hashes, check_ordering, check_consistency);
        let ccr = py
            .detach(move || Ccr::decode_with(&data, &opts))
            .map_err(|e| to_pyerr(py, e))?;
        Ok(PyCcr {
            inner: Inner::new(ccr),
        })
    }

    /// Reads and decodes a CCR file (plain DER or gzip-compressed).
    #[staticmethod]
    #[pyo3(signature = (path, *, verify_hashes = true, check_ordering = true, check_consistency = true))]
    fn from_file(
        py: Python<'_>,
        path: PathBuf,
        verify_hashes: bool,
        check_ordering: bool,
        check_consistency: bool,
    ) -> PyResult<Self> {
        let opts = options(verify_hashes, check_ordering, check_consistency);
        let result = py.detach(|| -> Result<Ccr, FileError> {
            let data = std::fs::read(&path).map_err(FileError::Io)?;
            Ccr::decode_with(&data, &opts).map_err(FileError::Decode)
        });
        match result {
            Ok(ccr) => Ok(PyCcr {
                inner: Inner::new(ccr),
            }),
            Err(FileError::Io(err)) => Err(os_error(err, &path)),
            Err(FileError::Decode(err)) => Err(to_pyerr(py, err)),
        }
    }

    /// Decodes without any semantic checks; used to unpickle.
    #[staticmethod]
    fn _from_der_unchecked(py: Python<'_>, data: PyBackedBytes) -> PyResult<Self> {
        Self::decode(py, data, false, false, false)
    }

    /// The format version, always 0.
    #[getter]
    fn version(&self) -> u8 {
        self.inner.ccr.version()
    }

    /// The digest algorithm, always "sha256".
    #[getter]
    fn hash_algorithm(&self) -> String {
        self.inner.ccr.hash_algorithm().to_string()
    }

    /// The time at which the CCR was finalized.
    #[getter]
    fn produced_at(&self) -> DateTime<Utc> {
        self.inner.ccr.produced_at()
    }

    /// The manifest state, if present.
    #[getter]
    fn manifests(&self) -> Option<PyManifestState> {
        self.inner.ccr.manifests().map(|_| PyManifestState {
            inner: Arc::clone(&self.inner),
        })
    }

    /// The ROA payload state (VRPs), if present.
    #[getter]
    fn roa_payloads(&self) -> Option<PyRoaPayloadState> {
        self.inner.ccr.roa_payloads().map(|_| PyRoaPayloadState {
            inner: Arc::clone(&self.inner),
        })
    }

    /// The ASPA payload state, if present.
    #[getter]
    fn aspa_payloads(&self) -> Option<PyAspaPayloadState> {
        self.inner.ccr.aspa_payloads().map(|_| PyAspaPayloadState {
            inner: Arc::clone(&self.inner),
        })
    }

    /// The trust anchor state, if present.
    #[getter]
    fn trust_anchors(&self) -> Option<PyTrustAnchorState> {
        self.inner.ccr.trust_anchors().map(|_| PyTrustAnchorState {
            inner: Arc::clone(&self.inner),
        })
    }

    /// The router key state, if present.
    #[getter]
    fn router_keys(&self) -> Option<PyRouterKeyState> {
        self.inner.ccr.router_keys().map(|_| PyRouterKeyState {
            inner: Arc::clone(&self.inner),
        })
    }

    /// The raw DER of state aspects unknown to this library (usually empty).
    #[getter]
    fn extensions<'py>(&self, py: Python<'py>) -> Vec<Bound<'py, PyBytes>> {
        self.inner
            .ccr
            .extensions()
            .iter()
            .map(|ext| PyBytes::new(py, ext))
            .collect()
    }

    /// Validates the current contents, raising the same exceptions as `decode`.
    #[pyo3(signature = (*, verify_hashes = true, check_ordering = true, check_consistency = true))]
    fn validate(
        &self,
        py: Python<'_>,
        verify_hashes: bool,
        check_ordering: bool,
        check_consistency: bool,
    ) -> PyResult<()> {
        let opts = options(verify_hashes, check_ordering, check_consistency);
        let inner = Arc::clone(&self.inner);
        py.detach(move || inner.ccr.validate(&opts))
            .map_err(|e| to_pyerr(py, e))
    }

    /// Validates, then encodes as DER.
    #[pyo3(signature = (*, verify_hashes = true, check_ordering = true, check_consistency = true))]
    fn to_der<'py>(
        &self,
        py: Python<'py>,
        verify_hashes: bool,
        check_ordering: bool,
        check_consistency: bool,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let opts = options(verify_hashes, check_ordering, check_consistency);
        let inner = Arc::clone(&self.inner);
        let der = py
            .detach(move || inner.ccr.to_der_with(&opts))
            .map_err(|e| to_pyerr(py, e))?;
        Ok(PyBytes::new(py, &der))
    }

    /// Validates, then encodes as gzip-compressed DER.
    #[pyo3(signature = (*, verify_hashes = true, check_ordering = true, check_consistency = true))]
    fn to_der_gzip<'py>(
        &self,
        py: Python<'py>,
        verify_hashes: bool,
        check_ordering: bool,
        check_consistency: bool,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let opts = options(verify_hashes, check_ordering, check_consistency);
        let inner = Arc::clone(&self.inner);
        let gz = py
            .detach(move || inner.ccr.to_der_gzip_with(&opts))
            .map_err(|e| to_pyerr(py, e))?;
        Ok(PyBytes::new(py, &gz))
    }

    /// Computes the changes from this (older) CCR to `after`.
    fn diff(&self, py: Python<'_>, after: PyRef<'_, PyCcr>) -> crate::diff::PyCcrDiff {
        let before = Arc::clone(&self.inner);
        let after = Arc::clone(&after.inner);
        let diff = py.detach(move || before.ccr.diff(&after.ccr));
        crate::diff::PyCcrDiff {
            inner: Arc::new(diff),
        }
    }

    fn __repr__(&self) -> String {
        let ccr = &self.inner.ccr;
        let count = |n: Option<usize>| n.map_or("None".to_string(), |n| n.to_string());
        format!(
            "Ccr(produced_at={:?}, manifests={}, roa_payloads={}, aspa_payloads={}, trust_anchors={}, router_keys={})",
            ccr.produced_at(),
            count(ccr.manifests().map(ManifestState::len)),
            count(ccr.roa_payloads().map(|s| s.vrps().count())),
            count(ccr.aspa_payloads().map(AspaPayloadState::len)),
            count(ccr.trust_anchors().map(TrustAnchorState::len)),
            count(ccr.router_keys().map(|s| s.router_keys().count())),
        )
    }

    fn __reduce__<'py>(
        &self,
        py: Python<'py>,
    ) -> PyResult<(Bound<'py, PyAny>, (Bound<'py, PyBytes>,))> {
        let inner = Arc::clone(&self.inner);
        let der = py
            .detach(move || inner.ccr.to_der_with(&ValidationOptions::lenient()))
            .map_err(|e| to_pyerr(py, e))?;
        let restore = py.get_type::<PyCcr>().getattr("_from_der_unchecked")?;
        Ok((restore, (PyBytes::new(py, &der),)))
    }
}
