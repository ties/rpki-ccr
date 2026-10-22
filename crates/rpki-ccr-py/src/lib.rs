//! Python bindings for the `rpki-ccr` crate.

#[macro_use]
mod view;

mod access;
mod aspa;
mod ccr;
mod convert;
mod error;
mod manifest;
mod resources;
mod roa;
mod router_key;
mod trust_anchor;

use pyo3::prelude::*;

#[pymodule(name = "rpki_ccr")]
fn init(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = m.py();
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    error::register(m)?;
    m.add_class::<resources::PyPrefix>()?;
    m.add_class::<resources::PyVrp>()?;
    m.add_class::<access::PyAccessDescription>()?;
    m.add_class::<manifest::PyManifestInstance>()?;
    m.add_class::<manifest::PyManifestState>()?;
    m.add_class::<roa::PyRoaPayloadState>()?;
    m.add_class::<aspa::PyAspaPayloadSet>()?;
    m.add_class::<aspa::PyAspaPayloadState>()?;
    m.add_class::<trust_anchor::PyTrustAnchorState>()?;
    m.add_class::<router_key::PySubjectPublicKeyInfo>()?;
    m.add_class::<router_key::PyRouterKey>()?;
    m.add_class::<router_key::PyRouterKeyState>()?;
    m.add_class::<ccr::PyCcr>()?;

    let sequence = py.import("collections.abc")?.getattr("Sequence")?;
    for name in [
        "ManifestState",
        "RoaPayloadState",
        "AspaPayloadState",
        "TrustAnchorState",
        "RouterKeyState",
    ] {
        sequence.call_method1("register", (m.getattr(name)?,))?;
    }
    Ok(())
}
