//! `CcrDiff` and its per-aspect parts.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use rpki_ccr::{
    Asn, AspaPayloadDiff, AspaUpdate, CcrDiff, ChangeKind, IssuerChange, KeyIdentifier,
    ManifestDiff, RouterKey, SetDiff, Vrp,
};

use crate::aspa::PyAspaPayloadSet;
use crate::manifest::PyManifestInstance;
use crate::resources::PyVrp;
use crate::router_key::PyRouterKey;

/// The changes from one CCR to another, as returned by `Ccr.diff` and `new - old`.
#[pyclass(frozen, module = "rpki_ccr", name = "CcrDiff")]
pub struct PyCcrDiff {
    before_produced_at: DateTime<Utc>,
    after_produced_at: DateTime<Utc>,
    manifests: Option<Arc<ManifestDiff>>,
    roa_payloads: Option<Arc<SetDiff<Vrp>>>,
    aspa_payloads: Option<Arc<AspaPayloadDiff>>,
    trust_anchors: Option<Arc<SetDiff<KeyIdentifier>>>,
    router_keys: Option<Arc<SetDiff<(Asn, RouterKey)>>>,
}

impl PyCcrDiff {
    pub(crate) fn from_diff(diff: &CcrDiff) -> Self {
        PyCcrDiff {
            before_produced_at: diff.before_produced_at(),
            after_produced_at: diff.after_produced_at(),
            manifests: diff.manifests().map(|d| Arc::new(d.clone())),
            roa_payloads: diff.roa_payloads().map(|d| Arc::new(d.clone())),
            aspa_payloads: diff.aspa_payloads().map(|d| Arc::new(d.clone())),
            trust_anchors: diff.trust_anchors().map(|d| Arc::new(d.clone())),
            router_keys: diff.router_keys().map(|d| Arc::new(d.clone())),
        }
    }

    fn is_empty(&self) -> bool {
        self.manifests.as_ref().is_none_or(|d| d.is_empty())
            && self.roa_payloads.as_ref().is_none_or(|d| d.is_empty())
            && self.aspa_payloads.as_ref().is_none_or(|d| d.is_empty())
            && self.trust_anchors.as_ref().is_none_or(|d| d.is_empty())
            && self.router_keys.as_ref().is_none_or(|d| d.is_empty())
    }
}

#[pymethods]
impl PyCcrDiff {
    /// `producedAt` of the older CCR.
    #[getter]
    fn before_produced_at(&self) -> DateTime<Utc> {
        self.before_produced_at
    }

    /// `producedAt` of the newer CCR.
    #[getter]
    fn after_produced_at(&self) -> DateTime<Utc> {
        self.after_produced_at
    }

    /// The manifest difference, unless both CCRs lack the aspect.
    #[getter]
    fn manifests(&self) -> Option<PyManifestDiff> {
        self.manifests.as_ref().map(|d| PyManifestDiff {
            inner: Arc::clone(d),
        })
    }

    /// The VRP difference, unless both CCRs lack the aspect.
    #[getter]
    fn roa_payloads(&self) -> Option<PyRoaPayloadDiff> {
        self.roa_payloads.as_ref().map(|d| PyRoaPayloadDiff {
            inner: Arc::clone(d),
        })
    }

    /// The ASPA difference, unless both CCRs lack the aspect.
    #[getter]
    fn aspa_payloads(&self) -> Option<PyAspaPayloadDiff> {
        self.aspa_payloads.as_ref().map(|d| PyAspaPayloadDiff {
            inner: Arc::clone(d),
        })
    }

    /// The trust anchor difference, unless both CCRs lack the aspect.
    #[getter]
    fn trust_anchors(&self) -> Option<PyTrustAnchorDiff> {
        self.trust_anchors.as_ref().map(|d| PyTrustAnchorDiff {
            inner: Arc::clone(d),
        })
    }

    /// The router key difference, unless both CCRs lack the aspect.
    #[getter]
    fn router_keys(&self) -> Option<PyRouterKeyDiff> {
        self.router_keys.as_ref().map(|d| PyRouterKeyDiff {
            inner: Arc::clone(d),
        })
    }

    /// The same difference seen from the other direction.
    fn reversed(&self) -> Self {
        PyCcrDiff {
            before_produced_at: self.after_produced_at,
            after_produced_at: self.before_produced_at,
            manifests: self.manifests.as_ref().map(|d| Arc::new(d.reversed())),
            roa_payloads: self.roa_payloads.as_ref().map(|d| Arc::new(d.reversed())),
            aspa_payloads: self.aspa_payloads.as_ref().map(|d| Arc::new(d.reversed())),
            trust_anchors: self.trust_anchors.as_ref().map(|d| Arc::new(d.reversed())),
            router_keys: self.router_keys.as_ref().map(|d| Arc::new(d.reversed())),
        }
    }

    fn __neg__(&self) -> Self {
        self.reversed()
    }

    /// True when any aspect changed.
    fn __bool__(&self) -> bool {
        !self.is_empty()
    }

    fn __repr__(&self) -> String {
        fn count<T>(diff: &Option<Arc<SetDiff<T>>>) -> String {
            match diff {
                Some(d) => format!("+{}/-{}", d.added().len(), d.removed().len()),
                None => "None".to_string(),
            }
        }
        format!(
            "CcrDiff(manifests={}, roa_payloads={}, aspa_payloads={}, trust_anchors={}, router_keys={})",
            match &self.manifests {
                Some(d) => format!("+{}/-{}", d.added().len(), d.removed().len()),
                None => "None".to_string(),
            },
            count(&self.roa_payloads),
            match &self.aspa_payloads {
                Some(d) => format!(
                    "+{}/-{}/~{}",
                    d.added().len(),
                    d.removed().len(),
                    d.updated().len()
                ),
                None => "None".to_string(),
            },
            count(&self.trust_anchors),
            count(&self.router_keys),
        )
    }
}

/// Defines a set-difference class over one element type.
macro_rules! set_diff_class {
    ($name:ident, $pyname:literal, $elem:ty, |$py:ident, $value:ident| $to_py:expr) => {
        #[doc = concat!("Added and removed elements (", $pyname, ").")]
        #[pyclass(frozen, module = "rpki_ccr", name = $pyname)]
        pub struct $name {
            inner: Arc<SetDiff<$elem>>,
        }

        impl $name {
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
                Self::convert(py, self.inner.added())
            }

            /// Elements present in the older CCR only, in canonical order.
            #[getter]
            fn removed<'py>(&self, py: Python<'py>) -> PyResult<Vec<Bound<'py, PyAny>>> {
                Self::convert(py, self.inner.removed())
            }

            /// The number of elements present in both.
            #[getter]
            fn unchanged(&self) -> usize {
                self.inner.unchanged()
            }

            /// The same difference seen from the other direction.
            fn reversed(&self) -> Self {
                $name {
                    inner: Arc::new(self.inner.reversed()),
                }
            }

            fn __neg__(&self) -> Self {
                self.reversed()
            }

            /// True when something was added or removed.
            fn __bool__(&self) -> bool {
                !self.inner.is_empty()
            }

            fn __repr__(&self) -> String {
                format!(
                    "{}(added={}, removed={}, unchanged={})",
                    $pyname,
                    self.inner.added().len(),
                    self.inner.removed().len(),
                    self.inner.unchanged()
                )
            }
        }
    };
}

set_diff_class!(PyRoaPayloadDiff, "RoaPayloadDiff", Vrp, |py, vrp| Ok(
    PyVrp(*vrp).into_pyobject(py)?.into_any()
));
set_diff_class!(
    PyTrustAnchorDiff,
    "TrustAnchorDiff",
    KeyIdentifier,
    |py, ski| Ok(PyBytes::new(py, ski.as_slice()).into_any())
);
set_diff_class!(
    PyRouterKeyDiff,
    "RouterKeyDiff",
    (Asn, RouterKey),
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

    /// The same change seen from the other direction.
    fn reversed(&self) -> Self {
        PyIssuerChange(self.0.reversed())
    }

    fn __neg__(&self) -> Self {
        self.reversed()
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
    inner: Arc<ManifestDiff>,
}

#[pymethods]
impl PyManifestDiff {
    /// Manifest instances present in the newer CCR only (by hash).
    #[getter]
    fn added(&self) -> Vec<PyManifestInstance> {
        self.inner
            .added()
            .iter()
            .cloned()
            .map(PyManifestInstance)
            .collect()
    }

    /// Manifest instances present in the older CCR only (by hash).
    #[getter]
    fn removed(&self) -> Vec<PyManifestInstance> {
        self.inner
            .removed()
            .iter()
            .cloned()
            .map(PyManifestInstance)
            .collect()
    }

    /// The number of manifest instances present in both (by hash).
    #[getter]
    fn unchanged(&self) -> usize {
        self.inner.unchanged()
    }

    /// Issuers whose manifests changed, appeared or disappeared, ascending by AKI.
    #[getter]
    fn issuers(&self) -> Vec<PyIssuerChange> {
        self.inner
            .issuers()
            .iter()
            .cloned()
            .map(PyIssuerChange)
            .collect()
    }

    /// The number of issuers with exactly the same manifests in both.
    #[getter]
    fn unchanged_issuers(&self) -> usize {
        self.inner.unchanged_issuers()
    }

    /// The same difference seen from the other direction.
    fn reversed(&self) -> Self {
        PyManifestDiff {
            inner: Arc::new(self.inner.reversed()),
        }
    }

    fn __neg__(&self) -> Self {
        self.reversed()
    }

    /// True when any manifest changed.
    fn __bool__(&self) -> bool {
        !self.inner.is_empty()
    }

    fn __repr__(&self) -> String {
        format!(
            "ManifestDiff(added={}, removed={}, unchanged={}, issuers={}, unchanged_issuers={})",
            self.inner.added().len(),
            self.inner.removed().len(),
            self.inner.unchanged(),
            self.inner.issuers().len(),
            self.inner.unchanged_issuers()
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

    /// The same update seen from the other direction.
    fn reversed(&self) -> Self {
        PyAspaUpdate(self.0.reversed())
    }

    fn __neg__(&self) -> Self {
        self.reversed()
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
    inner: Arc<AspaPayloadDiff>,
}

#[pymethods]
impl PyAspaPayloadDiff {
    /// Customers present in the newer CCR only.
    #[getter]
    fn added(&self) -> Vec<PyAspaPayloadSet> {
        self.inner
            .added()
            .iter()
            .cloned()
            .map(PyAspaPayloadSet)
            .collect()
    }

    /// Customers present in the older CCR only.
    #[getter]
    fn removed(&self) -> Vec<PyAspaPayloadSet> {
        self.inner
            .removed()
            .iter()
            .cloned()
            .map(PyAspaPayloadSet)
            .collect()
    }

    /// Customers present in both with different providers.
    #[getter]
    fn updated(&self) -> Vec<PyAspaUpdate> {
        self.inner
            .updated()
            .iter()
            .cloned()
            .map(PyAspaUpdate)
            .collect()
    }

    /// The number of customers with identical providers in both.
    #[getter]
    fn unchanged(&self) -> usize {
        self.inner.unchanged()
    }

    /// The same difference seen from the other direction.
    fn reversed(&self) -> Self {
        PyAspaPayloadDiff {
            inner: Arc::new(self.inner.reversed()),
        }
    }

    fn __neg__(&self) -> Self {
        self.reversed()
    }

    /// True when any customer changed.
    fn __bool__(&self) -> bool {
        !self.inner.is_empty()
    }

    fn __repr__(&self) -> String {
        format!(
            "AspaPayloadDiff(added={}, removed={}, updated={}, unchanged={})",
            self.inner.added().len(),
            self.inner.removed().len(),
            self.inner.updated().len(),
            self.inner.unchanged()
        )
    }
}
