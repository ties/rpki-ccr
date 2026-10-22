//! The exception hierarchy and the mapping from `rpki_ccr::Error`.

use pyo3::create_exception;
use pyo3::exceptions::{PyBaseException, PyOSError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use rpki_ccr::Aspect;

create_exception!(
    rpki_ccr,
    Error,
    PyValueError,
    "Base class of every CCR error."
);
create_exception!(
    rpki_ccr,
    DerError,
    Error,
    "The input is not a well-formed CCR."
);
create_exception!(rpki_ccr, GzipError, Error, "Gzip decompression failed.");
create_exception!(
    rpki_ccr,
    HashMismatchError,
    Error,
    "A state aspect's digest does not match its payload (attributes: aspect, declared, computed)."
);
create_exception!(
    rpki_ccr,
    NotSortedError,
    Error,
    "A sequence is not in ascending order (attributes: aspect, what, index)."
);
create_exception!(
    rpki_ccr,
    DuplicateError,
    Error,
    "A sequence contains a duplicate (attributes: aspect, what, index)."
);
create_exception!(
    rpki_ccr,
    ConsistencyError,
    Error,
    "A cross-field rule of the specification does not hold (attribute: aspect)."
);
create_exception!(
    rpki_ccr,
    InvalidValueError,
    Error,
    "A value violates the specification."
);

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = m.py();
    m.add("Error", py.get_type::<Error>())?;
    m.add("DerError", py.get_type::<DerError>())?;
    m.add("GzipError", py.get_type::<GzipError>())?;
    m.add("HashMismatchError", py.get_type::<HashMismatchError>())?;
    m.add("NotSortedError", py.get_type::<NotSortedError>())?;
    m.add("DuplicateError", py.get_type::<DuplicateError>())?;
    m.add("ConsistencyError", py.get_type::<ConsistencyError>())?;
    m.add("InvalidValueError", py.get_type::<InvalidValueError>())?;
    Ok(())
}

/// The `Ccr` attribute name of an aspect, so `getattr(ccr, exc.aspect)` works.
pub(crate) fn aspect_name(aspect: Aspect) -> &'static str {
    match aspect {
        Aspect::Manifests => "manifests",
        Aspect::RoaPayloads => "roa_payloads",
        Aspect::AspaPayloads => "aspa_payloads",
        Aspect::TrustAnchors => "trust_anchors",
        Aspect::RouterKeys => "router_keys",
    }
}

/// An `InvalidValueError`.
pub(crate) fn invalid(message: impl Into<String>) -> PyErr {
    InvalidValueError::new_err(message.into())
}

fn with_attrs(
    py: Python<'_>,
    err: PyErr,
    set: impl FnOnce(&Bound<'_, PyBaseException>) -> PyResult<()>,
) -> PyErr {
    let value = err.value(py).clone();
    match set(&value) {
        Ok(()) => err,
        Err(failure) => failure,
    }
}

/// Converts a crate error into the matching Python exception.
pub(crate) fn to_pyerr(py: Python<'_>, err: rpki_ccr::Error) -> PyErr {
    use rpki_ccr::Error as E;

    let message = err.to_string();
    match err {
        E::Der(_) => DerError::new_err(message),
        E::Io(inner) => GzipError::new_err(format!("gzip: {inner}")),
        E::GzipUnsupported => GzipError::new_err(message),
        E::HashMismatch {
            aspect,
            declared,
            computed,
        } => with_attrs(py, HashMismatchError::new_err(message), |value| {
            value.setattr("aspect", aspect_name(aspect))?;
            value.setattr("declared", PyBytes::new(py, declared.as_slice()))?;
            value.setattr("computed", PyBytes::new(py, computed.as_slice()))
        }),
        E::NotSorted {
            aspect,
            what,
            index,
        } => with_attrs(py, NotSortedError::new_err(message), |value| {
            value.setattr("aspect", aspect_name(aspect))?;
            value.setattr("what", what)?;
            value.setattr("index", index)
        }),
        E::Duplicate {
            aspect,
            what,
            index,
        } => with_attrs(py, DuplicateError::new_err(message), |value| {
            value.setattr("aspect", aspect_name(aspect))?;
            value.setattr("what", what)?;
            value.setattr("index", index)
        }),
        E::Consistency { aspect, .. } => {
            with_attrs(py, ConsistencyError::new_err(message), |value| {
                value.setattr("aspect", aspect_name(aspect))
            })
        }
        E::InvalidValue { .. } => InvalidValueError::new_err(message),
        _ => Error::new_err(message),
    }
}

/// An `OSError` (or the matching subclass) carrying errno and the file name.
pub(crate) fn os_error(err: std::io::Error, path: &std::path::Path) -> PyErr {
    let text = err.to_string();
    let message = text
        .split(" (os error ")
        .next()
        .unwrap_or(&text)
        .to_string();
    match err.raw_os_error() {
        Some(errno) => PyOSError::new_err((errno, message, path.display().to_string())),
        None => PyOSError::new_err(format!("{}: {message}", path.display())),
    }
}
