"""Operator overloads: set algebra on views, `new - old` on Ccr, unary minus on diffs."""

import pytest

import rpki_ccr
from rpki_ccr import AspaPayloadSet, Ccr, Vrp

VIEWS = ["manifests", "roa_payloads", "aspa_payloads", "trust_anchors", "router_keys"]


def test_vrp_set_algebra(example: Ccr, multi_location_der: bytes) -> None:
    new = Ccr.decode(multi_location_der)
    old = example
    assert old.roa_payloads is not None and new.roa_payloads is not None
    added = new.roa_payloads - old.roa_payloads
    removed = old.roa_payloads - new.roa_payloads
    common = new.roa_payloads & old.roa_payloads
    assert [str(v) for v in added] == ["192.0.2.0/24-25 AS 64496", "2001:db8::/32 AS 64496"]
    assert len(removed) == 5 and all(isinstance(v, Vrp) for v in removed)
    assert common == []
    union = old.roa_payloads | new.roa_payloads
    assert [str(v) for v in union] == [
        "192.0.2.0/24 AS 0",
        "192.0.2.0/24-25 AS 64496",
        "2001:db8::/32 AS 64496",
        "198.51.100.0/24-28 AS 65536",
        "2001:db8::/48 AS 65536",
        "3fff::/32 AS 65550",
        "3fff::/32 AS 65551",
    ]
    assert (old.roa_payloads ^ new.roa_payloads) == union
    # The report agrees with the set algebra.
    report = new - old
    assert report.roa_payloads is not None
    assert report.roa_payloads.added == added
    assert report.roa_payloads.removed == removed
    # Results are plain lists in canonical order and can seed a new Ccr.
    rebuilt = Ccr(new.produced_at, roa_payloads=union)
    assert rebuilt.roa_payloads is not None and list(rebuilt.roa_payloads) == union


@pytest.mark.parametrize("attr", VIEWS)
def test_identities(example: Ccr, example_der: bytes, attr: str) -> None:
    view = getattr(example, attr)
    other = getattr(Ccr.decode(example_der), attr)
    items = list(view)
    assert view - other == []
    assert view & other == items
    assert view | other == items
    assert view ^ other == []
    assert view - view == []


def test_trust_anchors_and_manifests(example: Ccr, multi_location_der: bytes) -> None:
    new = Ccr.decode(multi_location_der)
    assert example.trust_anchors is not None and new.trust_anchors is not None
    assert example.trust_anchors - new.trust_anchors == []
    assert example.trust_anchors & new.trust_anchors == list(example.trust_anchors)
    assert all(isinstance(ski, bytes) for ski in example.trust_anchors | new.trust_anchors)
    assert example.manifests is not None and new.manifests is not None
    union = example.manifests | new.manifests
    assert len(union) == 6
    assert [mi.hash for mi in union] == sorted(mi.hash for mi in union)
    assert example.manifests - new.manifests == list(example.manifests)
    assert new.manifests & example.manifests == []


def test_aspa_and_router_keys(example: Ccr) -> None:
    assert example.aspa_payloads is not None and example.router_keys is not None
    other = Ccr(
        example.produced_at,
        aspa_payloads=[AspaPayloadSet(64512, [64496]), AspaPayloadSet(65536, [65540, 65545]), AspaPayloadSet(65550, [0])],
        router_keys=list(example.router_keys)[:2],
    )
    assert other.aspa_payloads is not None and other.router_keys is not None
    customers = lambda sets: [s.customer_asn for s in sets]  # noqa: E731
    assert customers(example.aspa_payloads - other.aspa_payloads) == [64511, 65536]
    assert customers(example.aspa_payloads & other.aspa_payloads) == [65550]
    assert customers(example.aspa_payloads | other.aspa_payloads) == [64511, 64512, 65536, 65536, 65550]
    assert [k.asn for k in example.router_keys - other.router_keys] == [65551]
    assert len(example.router_keys & other.router_keys) == 2
    assert isinstance((example.router_keys | other.router_keys)[0], rpki_ccr.RouterKey)


def test_mixed_operands_raise_type_error(example: Ccr) -> None:
    assert example.roa_payloads is not None and example.trust_anchors is not None
    with pytest.raises(TypeError):
        example.roa_payloads - example.trust_anchors  # type: ignore[operator]
    with pytest.raises(TypeError):
        example.roa_payloads & 1  # type: ignore[operator]
    with pytest.raises(TypeError):
        example - example.roa_payloads  # type: ignore[operator]
    with pytest.raises(TypeError):
        example & example  # type: ignore[operator]


def test_ccr_subtraction_and_negation(example: Ccr, multi_location_der: bytes) -> None:
    new = Ccr.decode(multi_location_der)
    report = new - example
    direct = example.diff(new)
    for attr in VIEWS:
        assert repr(getattr(report, attr)) == repr(getattr(direct, attr))
    assert repr(report) == repr(direct)
    assert report.before_produced_at == example.produced_at
    assert report.after_produced_at == new.produced_at

    reverse = -report
    other_way = example - new
    assert repr(reverse) == repr(other_way)
    assert reverse.before_produced_at == new.produced_at
    assert reverse.manifests is not None and other_way.manifests is not None
    assert [c.kind for c in reverse.manifests.issuers] == [c.kind for c in other_way.manifests.issuers]
    assert [c.kind for c in reverse.manifests.issuers] == ["updated", "added", "added", "updated"]
    assert reverse.roa_payloads is not None and report.roa_payloads is not None
    assert reverse.roa_payloads.added == report.roa_payloads.removed
    assert repr(-(-report)) == repr(report)
    assert repr(report.reversed()) == repr(-report)
    assert repr(-report.roa_payloads) == "RoaPayloadDiff(added=5, removed=2, unchanged=0)"
    assert report.manifests is not None
    change = report.manifests.issuers[1]
    assert (change.kind, (-change).kind) == ("removed", "added")
    assert (-change).after == change.before
    assert bool(-report) == bool(report)
    assert not (-(example - example))
