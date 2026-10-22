"""Encoding: round trips, building from scratch, validation on encode."""

import base64
import gzip
from datetime import datetime, timezone

import pytest

import rpki_ccr
from rpki_ccr import AspaPayloadSet, Ccr, ManifestInstance, RouterKey, SubjectPublicKeyInfo, Vrp
from test_example_vector import CA3, CA4, SPKI, TA1, TA2


def t(hour: int, minute: int, second: int) -> datetime:
    return datetime(2026, 5, 15, hour, minute, second, tzinfo=timezone.utc)


def digest(b64: str) -> bytes:
    return base64.b64decode(b64)


def test_round_trip(example_der: bytes, example: Ccr) -> None:
    assert example.to_der() == example_der
    assert Ccr.decode(example.to_der()) == example
    compressed = example.to_der_gzip()
    assert compressed[:2] == b"\x1f\x8b"
    assert gzip.decompress(compressed) == example_der
    assert Ccr.decode(compressed) == example


def test_build_example_vector_from_scratch(example_der: bytes) -> None:
    # Inputs are unsorted and contain duplicates and mergeable sets.
    manifests = [
        ManifestInstance(
            hash=digest("48JkKNPGfzSWjkALB4rFbaktXGSFaAV5qj0gj7zCCFY="),
            size=1729,
            aki=bytes.fromhex(TA1),
            manifest_number=0x0101,
            this_update=t(0, 0, 6),
            locations=["rsync://example.net/ca1/OaVUOIDSaLzUbeiz6VPogXxsK5o.mft"],
            subordinates=[bytes.fromhex(CA3), bytes.fromhex(CA4), bytes.fromhex(CA3)],
        ),
        ManifestInstance(
            hash=digest("vee5m+i2FKhzHwldksC2IX0WlVcHHVu3B8qAMnk+/Xo="),
            size=3995,
            aki=bytes.fromhex(CA3),
            manifest_number=0x0508,
            this_update=t(0, 0, 8),
            locations=[rpki_ccr.AccessDescription("rsync://example.net/ca3/sbhFzz4wTqsFo2NVRM8mWfsPBKQ.mft")],
        ),
        ManifestInstance(
            hash=digest("KF60zgHHRNmQSUXcsAcAPB2cB7kvToWUF60GADJuG5E="),
            size=1001,
            aki=bytes.fromhex(CA4),
            manifest_number=0x1321,
            this_update=t(0, 0, 9),
            locations=["rsync://example.net/ca4/QksbQZMC7YWsNrREt4l4dWAQ1sE.mft"],
        ),
        ManifestInstance(
            hash=digest("PH84tOOYN8EterYimODMa4sDj9HkMeyTNyCsy/9Q/48="),
            size=2040,
            aki=bytes.fromhex(TA2),
            manifest_number=0x0203,
            this_update=t(0, 0, 7),
            locations=["rsync://example.net/ca2/z0nzVS7SOB_9y6tapHk7-YuKkm8.mft"],
        ),
    ]
    vrps = [
        Vrp(65551, "3fff::/32"),
        Vrp(65536, "2001:db8::/48", 48),
        Vrp(65536, "198.51.100.0/24", 28),
        Vrp(0, "192.0.2.0/24"),
        Vrp(65550, rpki_ccr.Prefix("3fff::/32")),
        Vrp(0, "192.0.2.0/24", 24),
    ]
    aspas = [
        AspaPayloadSet(65550, [0]),
        AspaPayloadSet(65536, [65544]),
        AspaPayloadSet(64511, [64496]),
        AspaPayloadSet(65536, (65544, 65540)),
    ]
    trust_anchors = [bytes.fromhex(TA2), bytes.fromhex(TA1), bytes.fromhex(TA2)]
    router_keys = [
        RouterKey(65551, bytes.fromhex("4602B621B017681E61EE1F4A5EFC1D02C3B46F2C"), base64.b64decode(SPKI[2])),
        RouterKey(65542, bytes.fromhex("BE16E74E10F4BDF3F8C2618B024A9457DFBF89FA"), SubjectPublicKeyInfo(base64.b64decode(SPKI[1]))),
        RouterKey(65542, bytes.fromhex("88C5DE295A3276D69E9BB7469BD46EF972DE32AC"), base64.b64decode(SPKI[0])),
    ]
    ccr = Ccr(
        t(0, 0, 10),
        manifests=manifests,
        roa_payloads=iter(vrps),
        aspa_payloads=aspas,
        trust_anchors=trust_anchors,
        router_keys=router_keys,
    )
    assert ccr.to_der() == example_der
    assert ccr == Ccr.decode(example_der)
    assert hash(ccr) == hash(Ccr.decode(example_der))


def test_build_multi_location_fixture(multi_location_der: bytes) -> None:
    notify = "1.3.6.1.5.5.7.48.13"
    a = ManifestInstance(
        hash=rpki_ccr_sha256(b"manifest a"),
        size=1500,
        aki=bytes.fromhex(TA1),
        manifest_number=42,
        this_update=t(0, 0, 5),
        locations=["rsync://example.net/ca1/a.mft", "https://example.net/ca1/a.mft"],
        subordinates=[bytes.fromhex(CA4)],
    )
    b = ManifestInstance(
        hash=rpki_ccr_sha256(b"manifest b"),
        size=2000,
        aki=bytes.fromhex(TA2),
        manifest_number=0x01FF,
        this_update=t(0, 0, 9),
        locations=[
            "rsync://example.net/ca2/b.mft",
            rpki_ccr.AccessDescription("https://example.net/notification.xml", notify),
            "https://example.net/ca2/b.mft",
        ],
    )
    ccr = Ccr(
        t(0, 0, 10),
        manifests=[a, b],
        roa_payloads=[Vrp(64496, "192.0.2.0/24", 25), Vrp(64496, "2001:db8::/32")],
        trust_anchors=[bytes.fromhex(TA1), bytes.fromhex(TA2)],
    )
    assert ccr.to_der() == multi_location_der


def rpki_ccr_sha256(data: bytes) -> bytes:
    import hashlib

    return hashlib.sha256(data).digest()


def test_views_can_feed_a_new_ccr(example: Ccr) -> None:
    assert example.manifests is not None and example.roa_payloads is not None
    rebuilt = Ccr(
        example.produced_at,
        manifests=example.manifests,
        roa_payloads=example.roa_payloads,
        aspa_payloads=example.aspa_payloads,
        trust_anchors=example.trust_anchors,
        router_keys=example.router_keys,
    )
    assert rebuilt == example
    assert rebuilt.to_der() == example.to_der()


def test_empty_aspects() -> None:
    ccr = Ccr(t(0, 0, 10), manifests=[], roa_payloads=[], aspa_payloads=[], router_keys=[])
    assert ccr.manifests is not None and len(ccr.manifests) == 0
    assert ccr.manifests.most_recent_update == datetime(1970, 1, 1, tzinfo=timezone.utc)
    assert ccr.roa_payloads is not None and list(ccr.roa_payloads) == []
    assert ccr.trust_anchors is None
    assert Ccr.decode(ccr.to_der()) == ccr
    with pytest.raises(rpki_ccr.InvalidValueError):
        Ccr(t(0, 0, 10), trust_anchors=[])


def test_encoding_validates_by_default(example_der: bytes) -> None:
    tampered = bytearray(example_der)
    tampered[752] ^= 1  # inside the ManifestState digest
    tampered = bytes(tampered)
    lenient = Ccr.decode(tampered, verify_hashes=False)
    with pytest.raises(rpki_ccr.HashMismatchError) as info:
        lenient.to_der()
    assert info.value.aspect == "manifests"
    with pytest.raises(rpki_ccr.HashMismatchError):
        lenient.validate()
    lenient.validate(verify_hashes=False)
    assert lenient.to_der(verify_hashes=False) == tampered
    with pytest.raises(rpki_ccr.HashMismatchError):
        lenient.to_der_gzip()
    assert gzip.decompress(lenient.to_der_gzip(verify_hashes=False)) == tampered
