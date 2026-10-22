//! The sequence protocol shared by the five state views.

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
