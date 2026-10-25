//! `SubjectPublicKeyInfo`, `RouterKey` and the flattened `RouterKeyState` view.

use std::hash::{Hash, Hasher};
use std::sync::Arc;

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use rpki_ccr::{Asn, RouterKey, RouterKeyState, SubjectPublicKeyInfo};

use crate::ccr::Inner;
use crate::convert::key_identifier;
use crate::error::to_pyerr;

/// A subject public key with its algorithm identifier.
#[pyclass(frozen, eq, hash, module = "rpki_ccr", name = "SubjectPublicKeyInfo")]
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PySubjectPublicKeyInfo(pub SubjectPublicKeyInfo);

#[pymethods]
impl PySubjectPublicKeyInfo {
    #[new]
    fn new(py: Python<'_>, der: &[u8]) -> PyResult<Self> {
        SubjectPublicKeyInfo::from_der(der)
            .map(PySubjectPublicKeyInfo)
            .map_err(|e| to_pyerr(py, e))
    }

    /// The complete DER encoding.
    #[getter]
    fn der<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.0.as_der())
    }

    /// The algorithm as a dotted OID.
    #[getter]
    fn algorithm(&self) -> String {
        self.0.algorithm().to_string()
    }

    /// The DER encoding of the algorithm parameters, if present.
    #[getter]
    fn parameters<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.0.parameters().map(|p| PyBytes::new(py, p))
    }

    /// The `subjectPublicKey` octets.
    #[getter]
    fn public_key<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.0.public_key())
    }

    /// Whether this is an ECDSA P-256 key as required for BGPsec.
    #[getter]
    fn is_p256_ec(&self) -> bool {
        self.0.is_p256_ec()
    }

    fn __bytes__<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        self.der(py)
    }

    fn __repr__(&self) -> String {
        format!(
            "SubjectPublicKeyInfo(algorithm='{}', public_key='{}')",
            self.0.algorithm(),
            hex(self.0.public_key())
        )
    }

    fn __getnewargs__<'py>(&self, py: Python<'py>) -> (Bound<'py, PyBytes>,) {
        (self.der(py),)
    }

    fn __copy__<'py>(slf: Bound<'py, Self>) -> Bound<'py, Self> {
        slf
    }

    fn __deepcopy__<'py>(slf: Bound<'py, Self>, _memo: Bound<'py, PyAny>) -> Bound<'py, Self> {
        slf
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A BGPsec router key together with its AS number.
#[pyclass(frozen, eq, hash, module = "rpki_ccr", name = "RouterKey")]
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PyRouterKey {
    pub asn: Asn,
    pub key: RouterKey,
}

#[pymethods]
impl PyRouterKey {
    #[new]
    fn new(py: Python<'_>, asn: u32, ski: &[u8], spki: &Bound<'_, PyAny>) -> PyResult<Self> {
        let ski = key_identifier("ski", ski)?;
        let spki = if let Ok(spki) = spki.cast::<PySubjectPublicKeyInfo>() {
            spki.get().0.clone()
        } else {
            SubjectPublicKeyInfo::from_der(spki.extract::<&[u8]>()?).map_err(|e| to_pyerr(py, e))?
        };
        Ok(PyRouterKey {
            asn: Asn::new(asn),
            key: RouterKey::new(ski, spki),
        })
    }

    /// The AS number.
    #[getter]
    fn asn(&self) -> u32 {
        self.asn.into_u32()
    }

    /// The subject key identifier of the router certificate.
    #[getter]
    fn ski<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.key.ski().as_slice())
    }

    /// The subject public key info.
    #[getter]
    fn spki(&self) -> PySubjectPublicKeyInfo {
        PySubjectPublicKeyInfo(self.key.spki().clone())
    }

    fn __repr__(&self) -> String {
        format!(
            "RouterKey(asn={}, ski='{}', spki={})",
            self.asn,
            self.key.ski(),
            self.spki().__repr__()
        )
    }

    fn __getnewargs__<'py>(
        &self,
        py: Python<'py>,
    ) -> (u32, Bound<'py, PyBytes>, PySubjectPublicKeyInfo) {
        (self.asn(), self.ski(py), self.spki())
    }

    fn __copy__<'py>(slf: Bound<'py, Self>) -> Bound<'py, Self> {
        slf
    }

    fn __deepcopy__<'py>(slf: Bound<'py, Self>, _memo: Bound<'py, PyAny>) -> Bound<'py, Self> {
        slf
    }
}

/// Cumulative key counts per set for indexing the flattened view.
pub(crate) struct RouterKeyIndex {
    starts: Vec<usize>,
    total: usize,
}

impl RouterKeyIndex {
    fn build(state: &RouterKeyState) -> Self {
        let mut starts = Vec::with_capacity(state.len());
        let mut total = 0;
        for set in state.sets() {
            starts.push(total);
            total += set.router_keys().len();
        }
        RouterKeyIndex { starts, total }
    }

    fn get(&self, state: &RouterKeyState, index: usize) -> (Asn, RouterKey) {
        let k = self.starts.partition_point(|&start| start <= index) - 1;
        let set = &state.sets()[k];
        (
            set.as_id(),
            set.router_keys()[index - self.starts[k]].clone(),
        )
    }
}

fn state_of(inner: &Inner) -> &RouterKeyState {
    inner
        .ccr
        .router_keys()
        .expect("view exists only when the aspect is present")
}

fn index_of(inner: &Inner) -> &RouterKeyIndex {
    inner
        .router_key_index
        .get_or_init(|| RouterKeyIndex::build(state_of(inner)))
}

/// The router key state of a CCR: a sequence of `RouterKey`.
#[pyclass(
    frozen,
    eq,
    hash,
    sequence,
    module = "rpki_ccr",
    name = "RouterKeyState"
)]
pub struct PyRouterKeyState {
    pub(crate) inner: Arc<Inner>,
}

impl PyRouterKeyState {
    fn state(&self) -> &RouterKeyState {
        state_of(&self.inner)
    }
}

impl PartialEq for PyRouterKeyState {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner) || self.state() == other.state()
    }
}

impl Eq for PyRouterKeyState {}

impl Hash for PyRouterKeyState {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.state().hash().as_slice().hash(state);
    }
}

sequence_view!(
    extra: {
    /// The digest declared over the DER-encoded router key sets.
    #[getter]
    fn hash<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.state().hash().as_slice())
    }

    fn __repr__(&self) -> String {
        format!(
            "RouterKeyState(len={}, hash='{}')",
            index_of(&self.inner).total,
            self.state().hash()
        )
    }
    },
    view: PyRouterKeyState,
    iter: RouterKeyStateIter,
    attr: "router_keys",
    elem: (Asn, RouterKey),
    state: |inner| state_of(inner),
    len: |inner| inner.ccr.router_keys().map_or(0, |_| index_of(inner).total),
    get: |inner, index| index_of(inner).get(state_of(inner), index),
    to_py: |py, value| Ok(PyRouterKey { asn: value.0, key: value.1 }.into_pyobject(py)?.into_any()),
    needle: |obj| obj.cast::<PyRouterKey>().ok().map(|k| (k.get().asn, k.get().key.clone())),
);
