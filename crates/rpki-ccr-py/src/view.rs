//! The sequence protocol and set operators shared by the five state views.

/// A set operation between two views of the same class.
#[derive(Clone, Copy)]
pub(crate) enum SetOp {
    Difference,
    Intersection,
    Union,
    SymmetricDifference,
}

/// The four set operations of a state type, in canonical order.
pub(crate) trait SetOps {
    type Elem;
    fn set_op(&self, other: &Self, op: SetOp) -> Vec<Self::Elem>;
}

macro_rules! impl_set_ops {
    ($state:ty, $elem:ty) => {
        impl SetOps for $state {
            type Elem = $elem;

            fn set_op(&self, other: &Self, op: SetOp) -> Vec<$elem> {
                match op {
                    SetOp::Difference => self.difference(other),
                    SetOp::Intersection => self.intersection(other),
                    SetOp::Union => self.union(other),
                    SetOp::SymmetricDifference => self.symmetric_difference(other),
                }
            }
        }
    };
}

impl_set_ops!(rpki_ccr::ManifestState, rpki_ccr::ManifestInstance);
impl_set_ops!(rpki_ccr::RoaPayloadState, rpki_ccr::Vrp);
impl_set_ops!(rpki_ccr::AspaPayloadState, rpki_ccr::AspaPayloadSet);
impl_set_ops!(rpki_ccr::TrustAnchorState, rpki_ccr::KeyIdentifier);
impl_set_ops!(
    rpki_ccr::RouterKeyState,
    (rpki_ccr::Asn, rpki_ccr::RouterKey)
);

/// Implements `__len__`, `__getitem__` (indices and slices), `__iter__`,
/// `__contains__`, `index`, `count` and `__reduce__` for a view type that
/// holds an `Arc<Inner>`, plus the matching iterator class. The view's own
/// methods go in `extra`, because a class may have only one `#[pymethods]`
/// block.
macro_rules! sequence_view {
    (
        extra: { $($extra:tt)* },
        view: $view:ident,
        iter: $iter:ident,
        attr: $attr:literal,
        elem: $elem:ty,
        state: |$inner_state:ident| $state:expr,
        len: |$inner_len:ident| $len:expr,
        get: |$inner_get:ident, $index:ident| $get:expr,
        to_py: |$py:ident, $value:ident| $to_py:expr,
        needle: |$obj:ident| $needle:expr $(,)?
    ) => {
        impl $view {
            pub(crate) fn len_of(inner: &$crate::ccr::Inner) -> usize {
                let $inner_len = inner;
                $len
            }

            pub(crate) fn get_of(inner: &$crate::ccr::Inner, index: usize) -> $elem {
                let $inner_get = inner;
                let $index = index;
                $get
            }

            fn elem_to_py<'py>(
                py: ::pyo3::Python<'py>,
                value: $elem,
            ) -> ::pyo3::PyResult<::pyo3::Bound<'py, ::pyo3::PyAny>> {
                let $py = py;
                let $value = value;
                $to_py
            }

            fn needle_of(obj: &::pyo3::Bound<'_, ::pyo3::PyAny>) -> Option<$elem> {
                let $obj = obj;
                $needle
            }

            fn state_of(
                inner: &$crate::ccr::Inner,
            ) -> &impl $crate::view::SetOps<Elem = $elem> {
                let $inner_state = inner;
                $state
            }

            /// Runs a set operation against another view of the same class,
            /// returning a list in canonical order, or `NotImplemented`.
            fn set_op<'py>(
                &self,
                py: ::pyo3::Python<'py>,
                other: &::pyo3::Bound<'py, ::pyo3::PyAny>,
                op: $crate::view::SetOp,
            ) -> ::pyo3::PyResult<::pyo3::Bound<'py, ::pyo3::PyAny>> {
                use ::pyo3::prelude::*;
                let Ok(other) = other.cast::<Self>() else {
                    return Ok(py.NotImplemented().into_bound(py).into_any());
                };
                let left = ::std::sync::Arc::clone(&self.inner);
                let right = ::std::sync::Arc::clone(&other.get().inner);
                let items = py.detach(move || {
                    $crate::view::SetOps::set_op(Self::state_of(&left), Self::state_of(&right), op)
                });
                let list = ::pyo3::types::PyList::empty(py);
                for item in items {
                    list.append(Self::elem_to_py(py, item)?)?;
                }
                Ok(list.into_any())
            }

            fn normalize(&self, index: isize) -> ::pyo3::PyResult<usize> {
                let len = Self::len_of(&self.inner) as isize;
                let index = if index < 0 { index + len } else { index };
                if index < 0 || index >= len {
                    Err(::pyo3::exceptions::PyIndexError::new_err("index out of range"))
                } else {
                    Ok(index as usize)
                }
            }

            fn position(
                &self,
                item: &::pyo3::Bound<'_, ::pyo3::PyAny>,
                start: isize,
                stop: Option<isize>,
            ) -> Option<usize> {
                let needle = Self::needle_of(item)?;
                let len = Self::len_of(&self.inner);
                // Python's slice semantics for the bounds: negative counts from the end, then clamp.
                let clamp = |bound: isize| -> usize {
                    let bound = if bound < 0 { bound + len as isize } else { bound };
                    bound.clamp(0, len as isize) as usize
                };
                let start = clamp(start);
                let stop = stop.map_or(len, clamp);
                (start..stop).find(|&i| Self::get_of(&self.inner, i) == needle)
            }
        }

        #[::pyo3::pymethods]
        impl $view {
            $($extra)*

            fn __len__(&self) -> usize {
                Self::len_of(&self.inner)
            }

            fn __getitem__<'py>(
                &self,
                py: ::pyo3::Python<'py>,
                index: &::pyo3::Bound<'py, ::pyo3::PyAny>,
            ) -> ::pyo3::PyResult<::pyo3::Bound<'py, ::pyo3::PyAny>> {
                use ::pyo3::prelude::*;
                if let Ok(slice) = index.cast::<::pyo3::types::PySlice>() {
                    let len = Self::len_of(&self.inner);
                    let indices = slice.indices(len as isize)?;
                    let list = ::pyo3::types::PyList::empty(py);
                    let mut i = indices.start;
                    for _ in 0..indices.slicelength {
                        list.append(Self::elem_to_py(py, Self::get_of(&self.inner, i as usize))?)?;
                        i += indices.step;
                    }
                    return Ok(list.into_any());
                }
                let i = self.normalize(index.extract::<isize>()?)?;
                Self::elem_to_py(py, Self::get_of(&self.inner, i))
            }

            fn __iter__(&self) -> $iter {
                $iter {
                    inner: ::std::sync::Arc::clone(&self.inner),
                    next: 0,
                    len: Self::len_of(&self.inner),
                }
            }

            fn __contains__(&self, item: &::pyo3::Bound<'_, ::pyo3::PyAny>) -> bool {
                self.position(item, 0, None).is_some()
            }

            /// The index of the first occurrence of `item` in `[start, stop)`.
            #[pyo3(signature = (item, start = 0, stop = None, /))]
            fn index(
                &self,
                item: &::pyo3::Bound<'_, ::pyo3::PyAny>,
                start: isize,
                stop: Option<isize>,
            ) -> ::pyo3::PyResult<usize> {
                self.position(item, start, stop)
                    .ok_or_else(|| ::pyo3::exceptions::PyValueError::new_err("item is not in the sequence"))
            }

            /// The number of occurrences of `item` (0 or 1 for a canonical file).
            fn count(&self, item: &::pyo3::Bound<'_, ::pyo3::PyAny>) -> usize {
                match Self::needle_of(item) {
                    Some(needle) => (0..Self::len_of(&self.inner))
                        .filter(|&i| Self::get_of(&self.inner, i) == needle)
                        .count(),
                    None => 0,
                }
            }

            /// Elements of this view that `other` lacks, in canonical order.
            fn __sub__<'py>(
                &self,
                py: ::pyo3::Python<'py>,
                other: &::pyo3::Bound<'py, ::pyo3::PyAny>,
            ) -> ::pyo3::PyResult<::pyo3::Bound<'py, ::pyo3::PyAny>> {
                self.set_op(py, other, $crate::view::SetOp::Difference)
            }

            /// Elements present in both views, in canonical order.
            fn __and__<'py>(
                &self,
                py: ::pyo3::Python<'py>,
                other: &::pyo3::Bound<'py, ::pyo3::PyAny>,
            ) -> ::pyo3::PyResult<::pyo3::Bound<'py, ::pyo3::PyAny>> {
                self.set_op(py, other, $crate::view::SetOp::Intersection)
            }

            /// Elements present in either view, in canonical order.
            fn __or__<'py>(
                &self,
                py: ::pyo3::Python<'py>,
                other: &::pyo3::Bound<'py, ::pyo3::PyAny>,
            ) -> ::pyo3::PyResult<::pyo3::Bound<'py, ::pyo3::PyAny>> {
                self.set_op(py, other, $crate::view::SetOp::Union)
            }

            /// Elements present in exactly one of the views, in canonical order.
            fn __xor__<'py>(
                &self,
                py: ::pyo3::Python<'py>,
                other: &::pyo3::Bound<'py, ::pyo3::PyAny>,
            ) -> ::pyo3::PyResult<::pyo3::Bound<'py, ::pyo3::PyAny>> {
                self.set_op(py, other, $crate::view::SetOp::SymmetricDifference)
            }

            fn __reduce__<'py>(
                &self,
                py: ::pyo3::Python<'py>,
            ) -> ::pyo3::PyResult<(::pyo3::Bound<'py, ::pyo3::PyAny>, ($crate::ccr::PyCcr, &'static str))> {
                use ::pyo3::prelude::*;
                let getattr = py.import("builtins")?.getattr("getattr")?;
                let ccr = $crate::ccr::PyCcr {
                    inner: ::std::sync::Arc::clone(&self.inner),
                };
                Ok((getattr, (ccr, $attr)))
            }
        }

        #[::pyo3::pyclass(module = "rpki_ccr")]
        pub struct $iter {
            inner: ::std::sync::Arc<$crate::ccr::Inner>,
            next: usize,
            len: usize,
        }

        #[::pyo3::pymethods]
        impl $iter {
            fn __iter__(slf: ::pyo3::PyRef<'_, Self>) -> ::pyo3::PyRef<'_, Self> {
                slf
            }

            fn __next__<'py>(
                mut slf: ::pyo3::PyRefMut<'py, Self>,
                py: ::pyo3::Python<'py>,
            ) -> ::pyo3::PyResult<Option<::pyo3::Bound<'py, ::pyo3::PyAny>>> {
                if slf.next >= slf.len {
                    return Ok(None);
                }
                let i = slf.next;
                slf.next += 1;
                $view::elem_to_py(py, $view::get_of(&slf.inner, i)).map(Some)
            }

            fn __length_hint__(&self) -> usize {
                self.len - self.next
            }
        }
    };
}
