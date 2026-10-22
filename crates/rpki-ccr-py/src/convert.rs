//! Conversions between Python values and crate types.

use std::net::IpAddr;

use bytes::Bytes;
use num_bigint::BigUint;
use pyo3::exceptions::PyTypeError;
use pyo3::prelude::*;
use rpki_ccr::bcder::Oid;
use rpki_ccr::{Digest, KeyIdentifier, ManifestNumber, Prefix};

use crate::error::invalid;
use crate::resources::PyPrefix;

pub(crate) fn key_identifier(what: &str, bytes: &[u8]) -> PyResult<KeyIdentifier> {
    KeyIdentifier::try_from(bytes)
        .map_err(|_| invalid(format!("{what} must be 20 bytes, got {}", bytes.len())))
}

pub(crate) fn digest(what: &str, bytes: &[u8]) -> PyResult<Digest> {
    Digest::try_from(bytes)
        .map_err(|_| invalid(format!("{what} must be 32 bytes, got {}", bytes.len())))
}

pub(crate) fn manifest_number_to_py(number: &ManifestNumber) -> BigUint {
    BigUint::from_bytes_be(number.as_bytes())
}

pub(crate) fn manifest_number_from_py(number: &BigUint) -> PyResult<ManifestNumber> {
    ManifestNumber::try_from_be_bytes(&number.to_bytes_be()).map_err(|e| invalid(e.to_string()))
}

pub(crate) fn oid_from_str(text: &str) -> PyResult<Oid<Bytes>> {
    text.parse::<Oid<Bytes>>()
        .map_err(|_| invalid(format!("invalid object identifier {text:?}")))
}

/// Python's `repr()` of a string.
pub(crate) fn repr_str(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('\'');
    for c in text.chars() {
        match c {
            '\'' => out.push_str("\\'"),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\x{:02x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('\'');
    out
}

/// An `ipaddress.IPv4Address` / `IPv6Address`.
pub(crate) fn ip_address<'py>(py: Python<'py>, addr: IpAddr) -> PyResult<Bound<'py, PyAny>> {
    py.import("ipaddress")?
        .call_method1("ip_address", (addr.to_string(),))
}

/// An `ipaddress.IPv4Network` / `IPv6Network`.
pub(crate) fn ip_network<'py>(py: Python<'py>, prefix: &Prefix) -> PyResult<Bound<'py, PyAny>> {
    py.import("ipaddress")?
        .call_method1("ip_network", (prefix.to_string(),))
}

/// An address given as an `ipaddress` object or a string.
pub(crate) fn address_arg(obj: &Bound<'_, PyAny>) -> PyResult<IpAddr> {
    if let Ok(addr) = obj.extract::<IpAddr>() {
        return Ok(addr);
    }
    if let Ok(text) = obj.extract::<String>() {
        return text
            .parse()
            .map_err(|_| invalid(format!("invalid IP address {text:?}")));
    }
    Err(PyTypeError::new_err(
        "expected an ipaddress.IPv4Address, ipaddress.IPv6Address or str",
    ))
}

/// A prefix given as a `Prefix`, a string or an `ipaddress` network.
pub(crate) fn prefix_arg(obj: &Bound<'_, PyAny>) -> PyResult<Prefix> {
    if let Ok(prefix) = obj.cast::<PyPrefix>() {
        return Ok(prefix.get().0);
    }
    if let Ok(text) = obj.extract::<String>() {
        return text
            .parse()
            .map_err(|_| invalid(format!("invalid prefix {text:?}")));
    }
    let network = obj
        .getattr("network_address")
        .and_then(|addr| addr.extract::<IpAddr>());
    let length = obj.getattr("prefixlen").and_then(|len| len.extract::<u8>());
    if let (Ok(addr), Ok(len)) = (network, length) {
        return Prefix::new(addr, len)
            .ok_or_else(|| invalid(format!("{addr}/{len} is not a valid prefix")));
    }
    Err(PyTypeError::new_err(
        "expected a Prefix, a prefix string or an ipaddress network",
    ))
}

/// Collects an arbitrary iterable, converting each item with `convert`.
pub(crate) fn collect<T>(
    iterable: &Bound<'_, PyAny>,
    mut convert: impl FnMut(&Bound<'_, PyAny>) -> PyResult<T>,
) -> PyResult<Vec<T>> {
    let mut items = Vec::new();
    for item in iterable.try_iter()? {
        items.push(convert(&item?)?);
    }
    Ok(items)
}
