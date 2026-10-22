//! The flattened `RoaPayloadState` view.

use std::hash::{Hash, Hasher};
use std::sync::Arc;

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use rpki_ccr::{RoaPayloadState, Vrp};

use crate::ccr::Inner;
use crate::resources::PyVrp;

/// Cumulative VRP counts per (set, family) for O(log n) indexing.
pub(crate) struct VrpIndex {
    starts: Vec<usize>,
    loc: Vec<(usize, usize)>,
    total: usize,
}

impl VrpIndex {
    pub(crate) fn build(state: &RoaPayloadState) -> Self {
        let mut starts = Vec::new();
        let mut loc = Vec::new();
        let mut total = 0;
        for (set_index, set) in state.sets().iter().enumerate() {
            for (family_index, family) in set.ip_addr_blocks().iter().enumerate() {
                starts.push(total);
                loc.push((set_index, family_index));
                total += family.addresses().len();
            }
        }
        VrpIndex { starts, loc, total }
    }

    pub(crate) fn total(&self) -> usize {
        self.total
    }

    pub(crate) fn get(&self, state: &RoaPayloadState, index: usize) -> Vrp {
        let k = self.starts.partition_point(|&start| start <= index) - 1;
        let (set_index, family_index) = self.loc[k];
        let set = &state.sets()[set_index];
        let address = &set.ip_addr_blocks()[family_index].addresses()[index - self.starts[k]];
        Vrp::from_address(set.as_id(), address)
    }
}

/// The ROA payload state of a CCR: a sequence of `Vrp`.
#[pyclass(
    frozen,
    eq,
    hash,
    sequence,
    module = "rpki_ccr",
    name = "RoaPayloadState"
)]
pub struct PyRoaPayloadState {
    pub(crate) inner: Arc<Inner>,
}

impl PyRoaPayloadState {
    fn state(&self) -> &RoaPayloadState {
        state_of(&self.inner)
    }
}

fn state_of(inner: &Inner) -> &RoaPayloadState {
    inner
        .ccr
        .roa_payloads()
        .expect("view exists only when the aspect is present")
}

fn index_of(inner: &Inner) -> &VrpIndex {
    inner
        .vrp_index
        .get_or_init(|| VrpIndex::build(state_of(inner)))
}

impl PartialEq for PyRoaPayloadState {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner) || self.state() == other.state()
    }
}

impl Eq for PyRoaPayloadState {}

impl Hash for PyRoaPayloadState {
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
            "RoaPayloadState(len={}, hash='{}')",
            index_of(&self.inner).total(),
            self.state().hash()
        )
    }
    },
    view: PyRoaPayloadState,
    iter: RoaPayloadStateIter,
    attr: "roa_payloads",
    elem: Vrp,
    len: |inner| inner.ccr.roa_payloads().map_or(0, |_| index_of(inner).total()),
    get: |inner, index| index_of(inner).get(state_of(inner), index),
    to_py: |py, value| Ok(PyVrp(value).into_pyobject(py)?.into_any()),
    needle: |obj| obj.cast::<PyVrp>().ok().map(|v| v.get().0),
);
