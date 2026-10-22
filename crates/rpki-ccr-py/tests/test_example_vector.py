"""Every value of the specification's Appendix B dump, as seen from Python."""

import base64
import collections.abc
from datetime import datetime, timezone

import pytest

import rpki_ccr

TA1 = "25F8CCFCEFC046D8DCD00FC0E444E0AA7B790F96"
TA2 = "FACBD02CA47E3BD9666FCBD823B37DEDD0BCEE00"
CA3 = "E7315EA515D7C20538681249D3E30D6777162585"
CA4 = "A2DF042FE8B0006311E894851AC11411307B6043"

SPKI = [
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE64mxtNmdKd1bxIjgWrGJutr11LDeA56L8cc1NLL/WW9RZ+rbi+G4rFSvfrEjxzRPt6tcNWpgEINq7tOR7J5dAg==",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKjqTNoxSLK3UnLMNj2AdN/5sk5SITnYWK5e/JebKlJPFFxmBrOXWQyijRQBFFus7GtLLIZBYgp4K/u8o2/D4ig==",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4Xt6+dRDhjmH0QVmXlUPndJeXyzlMcsco6WkrjBf6NoX6gYahESgCm67xkBK4ZxhvCZRFWLxqH8cgT/Pgvl94w==",
]


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def test_header(example: rpki_ccr.Ccr) -> None:
    assert example.version == 0
    assert example.hash_algorithm == "sha256"
    assert example.produced_at == datetime(2026, 5, 15, 0, 0, 10, tzinfo=timezone.utc)
    assert example.produced_at.tzinfo is not None
    assert example.extensions == []
    assert repr(example) == (
        "Ccr(produced_at=2026-05-15T00:00:10Z, manifests=4, roa_payloads=5, "
        "aspa_payloads=3, trust_anchors=2, router_keys=3)"
    )


def test_manifest_state(example: rpki_ccr.Ccr) -> None:
    state = example.manifests
    assert state is not None
    assert isinstance(state, collections.abc.Sequence)
    assert b64(state.hash) == "Y41AjkpiFr/AzR2/c8cItZOmICwuIaZOGqYdKaonbBI="
    assert state.most_recent_update == datetime(2026, 5, 15, 0, 0, 9, tzinfo=timezone.utc)
    assert len(state) == 4

    expected = [
        ("KF60zgHHRNmQSUXcsAcAPB2cB7kvToWUF60GADJuG5E=", 1001, CA4, 0x1321, 1778803209,
         "rsync://example.net/ca4/QksbQZMC7YWsNrREt4l4dWAQ1sE.mft", []),
        ("PH84tOOYN8EterYimODMa4sDj9HkMeyTNyCsy/9Q/48=", 2040, TA2, 0x0203, 1778803207,
         "rsync://example.net/ca2/z0nzVS7SOB_9y6tapHk7-YuKkm8.mft", []),
        ("vee5m+i2FKhzHwldksC2IX0WlVcHHVu3B8qAMnk+/Xo=", 3995, CA3, 0x0508, 1778803208,
         "rsync://example.net/ca3/sbhFzz4wTqsFo2NVRM8mWfsPBKQ.mft", []),
        ("48JkKNPGfzSWjkALB4rFbaktXGSFaAV5qj0gj7zCCFY=", 1729, TA1, 0x0101, 1778803206,
         "rsync://example.net/ca1/OaVUOIDSaLzUbeiz6VPogXxsK5o.mft", [CA4, CA3]),
    ]
    for instance, (hash_, size, aki, number, this_update, sia, subordinates) in zip(state, expected):
        assert b64(instance.hash) == hash_
        assert instance.size == size
        assert instance.aki.hex().upper() == aki
        assert instance.manifest_number == number
        assert instance.this_update == datetime.fromtimestamp(this_update, timezone.utc)
        assert [location.uri for location in instance.locations] == [sia]
        assert all(location.is_signed_object for location in instance.locations)
        assert instance.locations[0].access_method == "1.3.6.1.5.5.7.48.11"
        assert [ski.hex().upper() for ski in instance.subordinates] == subordinates

    first = state[0]
    assert str(first) == (
        "hash:KF60zgHHRNmQSUXcsAcAPB2cB7kvToWUF60GADJuG5E= size:1001 "
        "aki:A2DF042FE8B0006311E894851AC11411307B6043 seqnum:1321 thisupdate:1778803209 "
        "sia:rsync://example.net/ca4/QksbQZMC7YWsNrREt4l4dWAQ1sE.mft"
    )
    assert str(state[3]).endswith(
        " subordinates:A2DF042FE8B0006311E894851AC11411307B6043,E7315EA515D7C20538681249D3E30D6777162585"
    )
    assert repr(first).startswith("ManifestInstance(hash='285eb4ce")
    assert repr(state).startswith("ManifestState(len=4, most_recent_update=2026-05-15T00:00:09Z, hash='638d")


def test_roa_payload_state(example: rpki_ccr.Ccr) -> None:
    state = example.roa_payloads
    assert state is not None
    assert b64(state.hash) == "D7GXkab9xejDm5KqaoYNDnApeP+5BX/9ExEBesfHTHo="
    assert [str(vrp) for vrp in state] == [
        "192.0.2.0/24 AS 0",
        "198.51.100.0/24-28 AS 65536",
        "2001:db8::/48 AS 65536",
        "3fff::/32 AS 65550",
        "3fff::/32 AS 65551",
    ]
    vrp = state[1]
    assert (vrp.asn, str(vrp.prefix), vrp.max_length) == (65536, "198.51.100.0/24", 28)
    assert vrp.prefix.address.version == 4
    assert state[2].prefix.address.version == 6
    assert repr(vrp) == "Vrp(asn=65536, prefix='198.51.100.0/24', max_length=28)"
    assert repr(state) == "RoaPayloadState(len=5, hash='0fb19791a6fdc5e8c39b92aa6a860d0e702978ffb9057ffd1311017ac7c74c7a')"


def test_aspa_payload_state(example: rpki_ccr.Ccr) -> None:
    state = example.aspa_payloads
    assert state is not None
    assert b64(state.hash) == "JzffEMksigs1JT58SSU+Yhq0UAiy27wg3beHrAslFFM="
    assert [(s.customer_asn, s.providers) for s in state] == [
        (64511, [64496]),
        (65536, [65540, 65544]),
        (65550, [0]),
    ]
    assert repr(state[1]) == "AspaPayloadSet(customer_asn=65536, providers=[65540, 65544])"


def test_trust_anchor_state(example: rpki_ccr.Ccr) -> None:
    state = example.trust_anchors
    assert state is not None
    assert b64(state.hash) == "DuZCxMlR+Gx9e3jABEpX/YGGHtWvfQH1vquOP43XAxE="
    assert [ski.hex().upper() for ski in state] == [TA1, TA2]
    assert bytes.fromhex(TA2) in state
    assert state.index(bytes.fromhex(TA2)) == 1


def test_router_key_state(example: rpki_ccr.Ccr) -> None:
    state = example.router_keys
    assert state is not None
    assert b64(state.hash) == "57BYFM3TNz47lJ6rbykyP58kkXVe/dOKFSLgOVi1GsE="
    assert [(key.asn, key.ski.hex().upper(), b64(key.spki.der)) for key in state] == [
        (65542, "88C5DE295A3276D69E9BB7469BD46EF972DE32AC", SPKI[0]),
        (65542, "BE16E74E10F4BDF3F8C2618B024A9457DFBF89FA", SPKI[1]),
        (65551, "4602B621B017681E61EE1F4A5EFC1D02C3B46F2C", SPKI[2]),
    ]
    for key in state:
        assert key.spki.is_p256_ec
        assert key.spki.algorithm == "1.2.840.10045.2.1"
        assert key.spki.parameters == bytes.fromhex("06082a8648ce3d030107")
        assert len(key.spki.public_key) == 65
        assert bytes(key.spki) == key.spki.der
    assert repr(state[0]).startswith("RouterKey(asn=65542, ski='88C5DE29")


def test_multi_location_fixture(multi_location_der: bytes) -> None:
    ccr = rpki_ccr.Ccr.decode(multi_location_der)
    assert ccr.manifests is not None
    by_aki = {instance.aki.hex().upper(): instance for instance in ccr.manifests}
    a = by_aki[TA1]
    assert [location.uri for location in a.locations] == [
        "https://example.net/ca1/a.mft",
        "rsync://example.net/ca1/a.mft",
    ]
    assert a.manifest_number == 42
    b = by_aki[TA2]
    assert [(location.access_method, location.uri) for location in b.locations] == [
        ("1.3.6.1.5.5.7.48.11", "https://example.net/ca2/b.mft"),
        ("1.3.6.1.5.5.7.48.11", "rsync://example.net/ca2/b.mft"),
        ("1.3.6.1.5.5.7.48.13", "https://example.net/notification.xml"),
    ]
    assert not b.locations[2].is_signed_object
    assert repr(b.locations[2]) == (
        "AccessDescription('https://example.net/notification.xml', access_method='1.3.6.1.5.5.7.48.13')"
    )
    assert ccr.aspa_payloads is None
    assert ccr.router_keys is None
    with pytest.raises(AttributeError):
        ccr.produced_at = datetime.now(timezone.utc)  # type: ignore[misc]
