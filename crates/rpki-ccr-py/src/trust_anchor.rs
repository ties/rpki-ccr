//! The `TrustAnchorState` view.

use std::hash::{Hash, Hasher};
use std::sync::Arc;

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use rpki_ccr::{KeyIdentifier, TrustAnchorState};

use crate::ccr::Inner;

/// The trust anchor state of a CCR: a sequence of 20-byte key identifiers.
#[pyclass(
    frozen,
    eq,
    hash,
    sequence,
    module = "rpki_ccr",
    name = "TrustAnchorState"
)]
pub struct PyTrustAnchorState {
    pub(crate) inner: Arc<Inner>,
}

impl PyTrustAnchorState {
    fn state(&self) -> &TrustAnchorState {
        self.inner
            .ccr
            .trust_anchors()
            .expect("view exists only when the aspect is present")
    }
}

impl PartialEq for PyTrustAnchorState {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner) || self.state() == other.state()
    }
}

impl Eq for PyTrustAnchorState {}

impl Hash for PyTrustAnchorState {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.state().hash().as_slice().hash(state);
    }
}

sequence_view!(
    extra: {
    /// The digest declared over the DER-encoded key identifiers.
    #[getter]
    fn hash<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.state().hash().as_slice())
    }

    fn __repr__(&self) -> String {
        format!(
            "TrustAnchorState(len={}, hash='{}')",
            self.state().len(),
            self.state().hash()
        )
    }
    },
    view: PyTrustAnchorState,
    iter: TrustAnchorStateIter,
    attr: "trust_anchors",
    elem: KeyIdentifier,
    len: |inner| inner.ccr.trust_anchors().map_or(0, TrustAnchorState::len),
    get: |inner, index| inner.ccr.trust_anchors().expect("present").skis()[index],
    to_py: |py, value| Ok(PyBytes::new(py, value.as_slice()).into_any()),
    needle: |obj| obj.extract::<&[u8]>().ok().and_then(|b| KeyIdentifier::try_from(b).ok()),
);
