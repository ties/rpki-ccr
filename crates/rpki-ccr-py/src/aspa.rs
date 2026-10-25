//! `AspaPayloadSet` and the `AspaPayloadState` view.

use std::hash::{Hash, Hasher};
use std::sync::Arc;

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use rpki_ccr::{Asn, AspaPayloadSet, AspaPayloadState};

use crate::ccr::Inner;
use crate::convert::collect;
use crate::error::to_pyerr;

/// The provider set of one customer AS.
#[pyclass(frozen, eq, hash, module = "rpki_ccr", name = "AspaPayloadSet")]
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PyAspaPayloadSet(pub AspaPayloadSet);

#[pymethods]
impl PyAspaPayloadSet {
    #[new]
    fn new(py: Python<'_>, customer_asn: u32, providers: &Bound<'_, PyAny>) -> PyResult<Self> {
        let providers = collect(providers, |item| Ok(Asn::new(item.extract::<u32>()?)))?;
        AspaPayloadSet::new(Asn::new(customer_asn), providers)
            .map(PyAspaPayloadSet)
            .map_err(|e| to_pyerr(py, e))
    }

    /// The customer AS number.
    #[getter]
    fn customer_asn(&self) -> u32 {
        self.0.customer_as_id().into_u32()
    }

    /// The provider AS numbers, ascending.
    #[getter]
    fn providers(&self) -> Vec<u32> {
        self.0.providers().iter().map(|p| p.into_u32()).collect()
    }

    fn __repr__(&self) -> String {
        format!(
            "AspaPayloadSet(customer_asn={}, providers={:?})",
            self.customer_asn(),
            self.providers()
        )
    }

    fn __getnewargs__(&self) -> (u32, Vec<u32>) {
        (self.customer_asn(), self.providers())
    }

    fn __copy__<'py>(slf: Bound<'py, Self>) -> Bound<'py, Self> {
        slf
    }

    fn __deepcopy__<'py>(slf: Bound<'py, Self>, _memo: Bound<'py, PyAny>) -> Bound<'py, Self> {
        slf
    }
}

/// The ASPA payload state of a CCR: a sequence of `AspaPayloadSet`.
#[pyclass(
    frozen,
    eq,
    hash,
    sequence,
    module = "rpki_ccr",
    name = "AspaPayloadState"
)]
pub struct PyAspaPayloadState {
    pub(crate) inner: Arc<Inner>,
}

impl PyAspaPayloadState {
    fn state(&self) -> &AspaPayloadState {
        self.inner
            .ccr
            .aspa_payloads()
            .expect("view exists only when the aspect is present")
    }
}

impl PartialEq for PyAspaPayloadState {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner) || self.state() == other.state()
    }
}

impl Eq for PyAspaPayloadState {}

impl Hash for PyAspaPayloadState {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.state().hash().as_slice().hash(state);
    }
}

sequence_view!(
    extra: {
    /// The digest declared over the DER-encoded payload sets.
    #[getter]
    fn hash<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.state().hash().as_slice())
    }

    fn __repr__(&self) -> String {
        format!(
            "AspaPayloadState(len={}, hash='{}')",
            self.state().len(),
            self.state().hash()
        )
    }
    },
    view: PyAspaPayloadState,
    iter: AspaPayloadStateIter,
    attr: "aspa_payloads",
    elem: AspaPayloadSet,
    state: |inner| inner.ccr.aspa_payloads().expect("present"),
    len: |inner| inner.ccr.aspa_payloads().map_or(0, AspaPayloadState::len),
    get: |inner, index| inner.ccr.aspa_payloads().expect("present").sets()[index].clone(),
    to_py: |py, value| Ok(PyAspaPayloadSet(value).into_pyobject(py)?.into_any()),
    needle: |obj| obj.cast::<PyAspaPayloadSet>().ok().map(|s| s.get().0.clone()),
);
