//! `Prefix` and `Vrp`.

use pyo3::prelude::*;
use rpki_ccr::{Asn, Prefix, Vrp};

use crate::convert::{address_arg, ip_address, ip_network, prefix_arg};
use crate::error::invalid;

/// An IP prefix.
#[pyclass(frozen, eq, hash, ord, module = "rpki_ccr", name = "Prefix")]
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PyPrefix(pub Prefix);

#[pymethods]
impl PyPrefix {
    #[new]
    #[pyo3(signature = (spec, length = None))]
    fn new(spec: &Bound<'_, PyAny>, length: Option<u8>) -> PyResult<Self> {
        match length {
            Some(length) => {
                let addr = address_arg(spec)?;
                Prefix::new(addr, length).map(PyPrefix).ok_or_else(|| {
                    invalid(format!(
                        "{addr}/{length} is not a valid prefix (length out of range or host bits set)"
                    ))
                })
            }
            None => prefix_arg(spec).map(PyPrefix),
        }
    }

    /// The network address as an `ipaddress` object.
    #[getter]
    fn address<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        ip_address(py, self.0.addr())
    }

    /// The prefix length in bits.
    #[getter]
    fn length(&self) -> u8 {
        self.0.length()
    }

    /// The prefix as an `ipaddress` network.
    fn network<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        ip_network(py, &self.0)
    }

    fn __str__(&self) -> String {
        self.0.to_string()
    }

    fn __repr__(&self) -> String {
        format!("Prefix('{}')", self.0)
    }

    fn __getnewargs__(&self) -> (String,) {
        (self.0.to_string(),)
    }

    fn __copy__<'py>(slf: Bound<'py, Self>) -> Bound<'py, Self> {
        slf
    }

    fn __deepcopy__<'py>(slf: Bound<'py, Self>, _memo: Bound<'py, PyAny>) -> Bound<'py, Self> {
        slf
    }
}

/// A Validated ROA Payload.
#[pyclass(frozen, eq, hash, ord, module = "rpki_ccr", name = "Vrp")]
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PyVrp(pub Vrp);

#[pymethods]
impl PyVrp {
    #[new]
    #[pyo3(signature = (asn, prefix, max_length = None))]
    fn new(asn: u32, prefix: &Bound<'_, PyAny>, max_length: Option<u8>) -> PyResult<Self> {
        let prefix = prefix_arg(prefix)?;
        let max_length = max_length.unwrap_or(prefix.length());
        Vrp::new(Asn::new(asn), prefix, max_length)
            .map(PyVrp)
            .ok_or_else(|| {
                invalid(format!(
                    "max_length {max_length} is out of range for {prefix}"
                ))
            })
    }

    /// The origin AS number.
    #[getter]
    fn asn(&self) -> u32 {
        self.0.asn().into_u32()
    }

    /// The prefix.
    #[getter]
    fn prefix(&self) -> PyPrefix {
        PyPrefix(self.0.prefix())
    }

    /// The maximum length (equal to the prefix length when not specified).
    #[getter]
    fn max_length(&self) -> u8 {
        self.0.max_length()
    }

    fn __str__(&self) -> String {
        self.0.to_string()
    }

    fn __repr__(&self) -> String {
        format!(
            "Vrp(asn={}, prefix='{}', max_length={})",
            self.0.asn(),
            self.0.prefix(),
            self.0.max_length()
        )
    }

    fn __getnewargs__(&self) -> (u32, PyPrefix, u8) {
        (self.asn(), self.prefix(), self.max_length())
    }

    fn __copy__<'py>(slf: Bound<'py, Self>) -> Bound<'py, Self> {
        slf
    }

    fn __deepcopy__<'py>(slf: Bound<'py, Self>, _memo: Bound<'py, PyAny>) -> Bound<'py, Self> {
        slf
    }
}
