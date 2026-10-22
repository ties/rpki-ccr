//! `CcrDiff` and its per-aspect parts.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use rpki_ccr::{AspaUpdate, CcrDiff, ChangeKind, IssuerChange};

use crate::aspa::PyAspaPayloadSet;
use crate::manifest::PyManifestInstance;
use crate::resources::PyVrp;
use crate::router_key::PyRouterKey;

/// The changes from one CCR to another, as returned by `Ccr.diff`.
#[pyclass(frozen, module = "rpki_ccr", name = "CcrDiff")]
pub struct PyCcrDiff {
    pub(crate) inner: Arc<CcrDiff>,
}

#[pymethods]
impl PyCcrDiff {
    /// `producedAt` of the older CCR.
    #[getter]
    fn before_produced_at(&self) -> DateTime<Utc> {
        self.inner.before_produced_at()
    }

    /// `producedAt` of the newer CCR.
    #[getter]
    fn after_produced_at(&self) -> DateTime<Utc> {
        self.inner.after_produced_at()
    }

    /// The manifest difference, unless both CCRs lack the aspect.
    #[getter]
    fn manifests(&self) -> Option<PyManifestDiff> {
        self.inner.manifests().map(|_| PyManifestDiff {
            inner: Arc::clone(&self.inner),
        })
    }

    /// The VRP difference, unless both CCRs lack the aspect.
    #[getter]
    fn roa_payloads(&self) -> Option<PyRoaPayloadDiff> {
        self.inner.roa_payloads().map(|_| PyRoaPayloadDiff {
            inner: Arc::clone(&self.inner),
        })
    }

    /// The ASPA difference, unless both CCRs lack the aspect.
    #[getter]
    fn aspa_payloads(&self) -> Option<PyAspaPayloadDiff> {
        self.inner.aspa_payloads().map(|_| PyAspaPayloadDiff {
            inner: Arc::clone(&self.inner),
        })
    }

    /// The trust anchor difference, unless both CCRs lack the aspect.
    #[getter]
    fn trust_anchors(&self) -> Option<PyTrustAnchorDiff> {
        self.inner.trust_anchors().map(|_| PyTrustAnchorDiff {
            inner: Arc::clone(&self.inner),
        })
    }

    /// The router key difference, unless both CCRs lack the aspect.
    #[getter]
    fn router_keys(&self) -> Option<PyRouterKeyDiff> {
        self.inner.router_keys().map(|_| PyRouterKeyDiff {
            inner: Arc::clone(&self.inner),
        })
    }

    /// True when any aspect changed.
    fn __bool__(&self) -> bool {
        !self.inner.is_empty()
    }

    fn __repr__(&self) -> String {
        let count = |n: Option<(usize, usize)>| match n {
            Some((added, removed)) => format!("+{added}/-{removed}"),
            None => "None".to_string(),
        };
        format!(
            "CcrDiff(manifests={}, roa_payloads={}, aspa_payloads={}, trust_anchors={}, router_keys={})",
            count(
                self.inner
                    .manifests()
                    .map(|d| (d.added().len(), d.removed().len()))
            ),
            count(
                self.inner
                    .roa_payloads()
                    .map(|d| (d.added().len(), d.removed().len()))
            ),
            match self.inner.aspa_payloads() {
                Some(d) => format!(
                    "+{}/-{}/~{}",
                    d.added().len(),
                    d.removed().len(),
                    d.updated().len()
                ),
                None => "None".to_string(),
            },
            count(
                self.inner
                    .trust_anchors()
                    .map(|d| (d.added().len(), d.removed().len()))
            ),
            count(
                self.inner
                    .router_keys()
                    .map(|d| (d.added().len(), d.removed().len()))
            ),
        )
    }
}

/// Defines a set-difference class over one aspect of a `CcrDiff`.
macro_rules! set_diff_class {
    ($name:ident, $pyname:literal, $accessor:ident, $elem:ty, |$py:ident, $value:ident| $to_py:expr) => {
        #[doc = concat!("Added and removed elements of the ", stringify!($accessor), " aspect.")]
        #[pyclass(frozen, module = "rpki_ccr", name = $pyname)]
        pub struct $name {
            inner: Arc<CcrDiff>,
        }

        impl $name {
            fn diff(&self) -> &rpki_ccr::SetDiff<$elem> {
                self.inner.$accessor().expect("created only when present")
            }

            fn convert<'py>(py: Python<'py>, items: &[$elem]) -> PyResult<Vec<Bound<'py, PyAny>>> {
                items
                    .iter()
                    .map(|item| {
                        let $py = py;
                        let $value = item;
                        $to_py
                    })
                    .collect()
            }
        }

        #[pymethods]
        impl $name {
            /// Elements present in the newer CCR only, in canonical order.
            #[getter]
            fn added<'py>(&self, py: Python<'py>) -> PyResult<Vec<Bound<'py, PyAny>>> {
                Self::convert(py, self.diff().added())
            }

            /// Elements present in the older CCR only, in canonical order.
            #[getter]
            fn removed<'py>(&self, py: Python<'py>) -> PyResult<Vec<Bound<'py, PyAny>>> {
                Self::convert(py, self.diff().removed())
            }

            /// The number of elements present in both.
            #[getter]
            fn unchanged(&self) -> usize {
                self.diff().unchanged()
            }

            /// True when something was added or removed.
            fn __bool__(&self) -> bool {
                !self.diff().is_empty()
            }

            fn __repr__(&self) -> String {
                format!(
                    "{}(added={}, removed={}, unchanged={})",
                    $pyname,
                    self.diff().added().len(),
                    self.diff().removed().len(),
                    self.diff().unchanged()
                )
            }
        }
    };
}

set_diff_class!(
    PyRoaPayloadDiff,
    "RoaPayloadDiff",
    roa_payloads,
    rpki_ccr::Vrp,
    |py, vrp| Ok(PyVrp(*vrp).into_pyobject(py)?.into_any())
);
set_diff_class!(
    PyTrustAnchorDiff,
    "TrustAnchorDiff",
    trust_anchors,
    rpki_ccr::KeyIdentifier,
    |py, ski| Ok(PyBytes::new(py, ski.as_slice()).into_any())
);
set_diff_class!(
    PyRouterKeyDiff,
    "RouterKeyDiff",
    router_keys,
    (rpki_ccr::Asn, rpki_ccr::RouterKey),
    |py, entry| Ok(PyRouterKey {
        asn: entry.0,
        key: entry.1.clone()
    }
    .into_pyobject(py)?
    .into_any())
);

/// The manifests of one issuer before and after.
#[pyclass(frozen, eq, hash, module = "rpki_ccr", name = "IssuerChange")]
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PyIssuerChange(pub IssuerChange);

#[pymethods]
impl PyIssuerChange {
    /// The issuer's 20-byte key identifier.
    #[getter]
    fn aki<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.0.aki().as_slice())
    }

    /// "added", "removed" or "updated".
    #[getter]
    fn kind(&self) -> &'static str {
        match self.0.kind() {
            ChangeKind::Added => "added",
            ChangeKind::Removed => "removed",
            ChangeKind::Updated => "updated",
        }
    }

    /// The issuer's manifest instances in the older CCR (usually one).
    #[getter]
    fn before(&self) -> Vec<PyManifestInstance> {
        self.0
            .before()
            .iter()
            .cloned()
            .map(PyManifestInstance)
            .collect()
    }

    /// The issuer's manifest instances in the newer CCR (usually one).
    #[getter]
    fn after(&self) -> Vec<PyManifestInstance> {
        self.0
            .after()
            .iter()
            .cloned()
            .map(PyManifestInstance)
            .collect()
    }

    fn __repr__(&self) -> String {
        format!(
            "IssuerChange(aki='{}', kind='{}', before={}, after={})",
            self.0.aki(),
            self.kind(),
            self.0.before().len(),
            self.0.after().len()
        )
    }
}

/// The manifest difference: by hash and grouped by issuer.
#[pyclass(frozen, module = "rpki_ccr", name = "ManifestDiff")]
pub struct PyManifestDiff {
    inner: Arc<CcrDiff>,
}

impl PyManifestDiff {
    fn diff(&self) -> &rpki_ccr::ManifestDiff {
        self.inner.manifests().expect("created only when present")
    }
}

#[pymethods]
impl PyManifestDiff {
    /// Manifest instances present in the newer CCR only (by hash).
    #[getter]
    fn added(&self) -> Vec<PyManifestInstance> {
        self.diff()
            .added()
            .iter()
            .cloned()
            .map(PyManifestInstance)
            .collect()
    }

    /// Manifest instances present in the older CCR only (by hash).
    #[getter]
    fn removed(&self) -> Vec<PyManifestInstance> {
        self.diff()
            .removed()
            .iter()
            .cloned()
            .map(PyManifestInstance)
            .collect()
    }

    /// The number of manifest instances present in both (by hash).
    #[getter]
    fn unchanged(&self) -> usize {
        self.diff().unchanged()
    }

    /// Issuers whose manifests changed, appeared or disappeared, ascending by AKI.
    #[getter]
    fn issuers(&self) -> Vec<PyIssuerChange> {
        self.diff()
            .issuers()
            .iter()
            .cloned()
            .map(PyIssuerChange)
            .collect()
    }

    /// The number of issuers with exactly the same manifests in both.
    #[getter]
    fn unchanged_issuers(&self) -> usize {
        self.diff().unchanged_issuers()
    }

    /// True when any manifest changed.
    fn __bool__(&self) -> bool {
        !self.diff().is_empty()
    }

    fn __repr__(&self) -> String {
        format!(
            "ManifestDiff(added={}, removed={}, unchanged={}, issuers={}, unchanged_issuers={})",
            self.diff().added().len(),
            self.diff().removed().len(),
            self.diff().unchanged(),
            self.diff().issuers().len(),
            self.diff().unchanged_issuers()
        )
    }
}

/// A customer AS whose provider set changed.
#[pyclass(frozen, eq, hash, module = "rpki_ccr", name = "AspaUpdate")]
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PyAspaUpdate(pub AspaUpdate);

#[pymethods]
impl PyAspaUpdate {
    /// The customer AS number.
    #[getter]
    fn customer_asn(&self) -> u32 {
        self.0.customer_as_id().into_u32()
    }

    /// The payload set in the older CCR.
    #[getter]
    fn before(&self) -> PyAspaPayloadSet {
        PyAspaPayloadSet(self.0.before().clone())
    }

    /// The payload set in the newer CCR.
    #[getter]
    fn after(&self) -> PyAspaPayloadSet {
        PyAspaPayloadSet(self.0.after().clone())
    }

    /// Providers present in the newer set only.
    #[getter]
    fn providers_added(&self) -> Vec<u32> {
        self.0
            .providers_added()
            .iter()
            .map(|p| p.into_u32())
            .collect()
    }

    /// Providers present in the older set only.
    #[getter]
    fn providers_removed(&self) -> Vec<u32> {
        self.0
            .providers_removed()
            .iter()
            .map(|p| p.into_u32())
            .collect()
    }

    fn __repr__(&self) -> String {
        format!(
            "AspaUpdate(customer_asn={}, providers_added={:?}, providers_removed={:?})",
            self.customer_asn(),
            self.providers_added(),
            self.providers_removed()
        )
    }
}

/// The ASPA difference, keyed by customer AS.
#[pyclass(frozen, module = "rpki_ccr", name = "AspaPayloadDiff")]
pub struct PyAspaPayloadDiff {
    inner: Arc<CcrDiff>,
}

impl PyAspaPayloadDiff {
    fn diff(&self) -> &rpki_ccr::AspaPayloadDiff {
        self.inner
            .aspa_payloads()
            .expect("created only when present")
    }
}

#[pymethods]
impl PyAspaPayloadDiff {
    /// Customers present in the newer CCR only.
    #[getter]
    fn added(&self) -> Vec<PyAspaPayloadSet> {
        self.diff()
            .added()
            .iter()
            .cloned()
            .map(PyAspaPayloadSet)
            .collect()
    }

    /// Customers present in the older CCR only.
    #[getter]
    fn removed(&self) -> Vec<PyAspaPayloadSet> {
        self.diff()
            .removed()
            .iter()
            .cloned()
            .map(PyAspaPayloadSet)
            .collect()
    }

    /// Customers present in both with different providers.
    #[getter]
    fn updated(&self) -> Vec<PyAspaUpdate> {
        self.diff()
            .updated()
            .iter()
            .cloned()
            .map(PyAspaUpdate)
            .collect()
    }

    /// The number of customers with identical providers in both.
    #[getter]
    fn unchanged(&self) -> usize {
        self.diff().unchanged()
    }

    /// True when any customer changed.
    fn __bool__(&self) -> bool {
        !self.diff().is_empty()
    }

    fn __repr__(&self) -> String {
        format!(
            "AspaPayloadDiff(added={}, removed={}, updated={}, unchanged={})",
            self.diff().added().len(),
            self.diff().removed().len(),
            self.diff().updated().len(),
            self.diff().unchanged()
        )
    }
}
