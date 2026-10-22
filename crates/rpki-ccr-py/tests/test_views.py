"""Sequence behaviour of the state views."""

import collections.abc

import pytest

import rpki_ccr
from rpki_ccr import Ccr


@pytest.mark.parametrize("attr", ["manifests", "roa_payloads", "aspa_payloads", "trust_anchors", "router_keys"])
def test_sequence_protocol(example: Ccr, example_der: bytes, attr: str) -> None:
    view = getattr(example, attr)
    assert view is not None
    assert isinstance(view, collections.abc.Sequence)
    n = len(view)
    assert n > 0
    items = list(view)
    assert len(items) == n
    assert [view[i] for i in range(n)] == items
    assert [view[-i - 1] for i in range(n)] == items[::-1]
    assert list(reversed(view)) == items[::-1]
    assert view[1:] == items[1:]
    assert view[::-1] == items[::-1]
    assert view[10:] == []
    with pytest.raises(IndexError):
        view[n]
    with pytest.raises(IndexError):
        view[-n - 1]
    with pytest.raises(TypeError):
        view["x"]
    for i, item in enumerate(items):
        assert item in view
        assert view.index(item) == i
        assert view.count(item) == 1
    assert "not an element" not in view
    assert view.count("not an element") == 0
    with pytest.raises(ValueError):
        view.index("not an element")
    it = iter(view)
    assert iter(it) is it
    assert it.__length_hint__() == n

    other = getattr(Ccr.decode(example_der), attr)
    assert view == other
    assert hash(view) == hash(other)
    assert view is not getattr(example, attr)
    assert view == getattr(example, attr)
    assert view != getattr(Ccr.decode(example_der, verify_hashes=False), "produced_at")
    assert isinstance(view.hash, bytes) and len(view.hash) == 32
    assert repr(view).startswith(type(view).__name__ + "(len=")


def test_views_from_different_files_differ(example: Ccr, multi_location_der: bytes) -> None:
    other = Ccr.decode(multi_location_der)
    assert example.manifests != other.manifests
    assert example.trust_anchors == other.trust_anchors  # same two SKIs
    assert example != other
    assert hash(example) != hash(other)


def test_views_are_immutable(example: Ccr) -> None:
    assert example.roa_payloads is not None
    with pytest.raises(TypeError):
        example.roa_payloads[0] = None  # type: ignore[index]
    with pytest.raises(TypeError):
        rpki_ccr.RoaPayloadState()  # type: ignore[call-arg]
