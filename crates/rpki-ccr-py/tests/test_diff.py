"""Ccr.diff."""

import pytest

import rpki_ccr
from rpki_ccr import AspaPayloadSet, Ccr, ManifestInstance, Vrp

TA1 = "25F8CCFCEFC046D8DCD00FC0E444E0AA7B790F96"
CA4 = "A2DF042FE8B0006311E894851AC11411307B6043"


def test_identical(example: Ccr) -> None:
    diff = example.diff(example)
    assert not diff
    assert diff.before_produced_at == diff.after_produced_at == example.produced_at
    assert diff.manifests is not None and not diff.manifests
    assert (diff.manifests.unchanged, diff.manifests.unchanged_issuers) == (4, 4)
    assert diff.manifests.issuers == []
    assert diff.roa_payloads is not None and diff.roa_payloads.unchanged == 5
    assert diff.aspa_payloads is not None and diff.aspa_payloads.unchanged == 3
    assert diff.trust_anchors is not None and diff.trust_anchors.unchanged == 2
    assert diff.router_keys is not None and diff.router_keys.unchanged == 3
    assert repr(diff) == "CcrDiff(manifests=+0/-0, roa_payloads=+0/-0, aspa_payloads=+0/-0/~0, trust_anchors=+0/-0, router_keys=+0/-0)"


def test_example_to_multi_location(example: Ccr, multi_location_der: bytes) -> None:
    after = Ccr.decode(multi_location_der)
    diff = example.diff(after)
    assert diff
    m = diff.manifests
    assert m is not None
    assert (len(m.added), len(m.removed), m.unchanged, m.unchanged_issuers) == (2, 4, 0, 0)
    assert [(c.aki.hex().upper()[:4], c.kind, len(c.before), len(c.after)) for c in m.issuers] == [
        ("25F8", "updated", 1, 1),
        ("A2DF", "removed", 1, 0),
        ("E731", "removed", 1, 0),
        ("FACB", "updated", 1, 1),
    ]
    assert m.issuers[0].before[0].manifest_number == 0x0101
    assert m.issuers[0].after[0].manifest_number == 42
    assert repr(m.issuers[1]).startswith("IssuerChange(aki='A2DF")
    assert repr(m) == "ManifestDiff(added=2, removed=4, unchanged=0, issuers=4, unchanged_issuers=0)"

    v = diff.roa_payloads
    assert v is not None and v
    assert [str(x) for x in v.added] == ["192.0.2.0/24-25 AS 64496", "2001:db8::/32 AS 64496"]
    assert len(v.removed) == 5 and v.unchanged == 0
    assert isinstance(v.added[0], Vrp)
    assert repr(v) == "RoaPayloadDiff(added=2, removed=5, unchanged=0)"

    a = diff.aspa_payloads
    assert a is not None
    assert (len(a.added), len(a.removed), len(a.updated), a.unchanged) == (0, 3, 0, 0)
    assert isinstance(a.removed[0], AspaPayloadSet)
    t = diff.trust_anchors
    assert t is not None and not t and t.unchanged == 2
    r = diff.router_keys
    assert r is not None and len(r.removed) == 3 and isinstance(r.removed[0], rpki_ccr.RouterKey)

    reverse = after.diff(example)
    assert reverse.roa_payloads is not None
    assert reverse.roa_payloads.added == v.removed
    assert reverse.manifests is not None and reverse.manifests.issuers[1].kind == "added"


def test_issuer_update_and_provider_changes(example: Ccr) -> None:
    assert example.manifests is not None
    instances = list(example.manifests)
    (old_index,) = [i for i, mi in enumerate(instances) if mi.aki.hex().upper() == CA4]
    replacement = ManifestInstance(
        hash=bytes(range(32)),
        size=1001,
        aki=bytes.fromhex(CA4),
        manifest_number=0x1322,
        this_update=example.produced_at,
        locations=instances[old_index].locations,
    )
    instances[old_index] = replacement
    after = Ccr(
        example.produced_at,
        manifests=instances,
        roa_payloads=example.roa_payloads,
        aspa_payloads=[
            AspaPayloadSet(64512, [64496]),
            AspaPayloadSet(65536, [65540, 65545, 65546]),
            AspaPayloadSet(65550, [0]),
        ],
        trust_anchors=example.trust_anchors,
        router_keys=example.router_keys,
    )
    diff = example.diff(after)
    m = diff.manifests
    assert m is not None
    assert (len(m.added), len(m.removed), m.unchanged, m.unchanged_issuers) == (1, 1, 3, 3)
    assert m.added == [replacement]
    (change,) = m.issuers
    assert (change.aki, change.kind) == (bytes.fromhex(CA4), "updated")
    assert change.before[0].manifest_number == 0x1321
    assert change.after == [replacement]

    a = diff.aspa_payloads
    assert a is not None
    assert [s.customer_asn for s in a.added] == [64512]
    assert [s.customer_asn for s in a.removed] == [64511]
    (update,) = a.updated
    assert (update.customer_asn, update.providers_added, update.providers_removed) == (65536, [65545, 65546], [65544])
    assert update.before.providers == [65540, 65544]
    assert repr(update) == "AspaUpdate(customer_asn=65536, providers_added=[65545, 65546], providers_removed=[65544])"
    assert repr(a) == "AspaPayloadDiff(added=1, removed=1, updated=1, unchanged=1)"
    assert diff.roa_payloads is not None and not diff.roa_payloads
    assert diff.trust_anchors is not None and not diff.trust_anchors
    assert diff.router_keys is not None and not diff.router_keys
    assert diff


def test_absent_aspects(example: Ccr) -> None:
    only_tas = Ccr(example.produced_at, trust_anchors=example.trust_anchors)
    with_vrps = Ccr(example.produced_at, trust_anchors=example.trust_anchors, roa_payloads=[Vrp(1, "10.0.0.0/8")])
    diff = only_tas.diff(with_vrps)
    assert diff.manifests is None and diff.aspa_payloads is None and diff.router_keys is None
    assert diff.roa_payloads is not None and [str(v) for v in diff.roa_payloads.added] == ["10.0.0.0/8 AS 1"]
    assert diff.trust_anchors is not None and not diff.trust_anchors
    assert diff and not only_tas.diff(only_tas)
    with pytest.raises(TypeError):
        only_tas.diff("not a ccr")  # type: ignore[arg-type]
