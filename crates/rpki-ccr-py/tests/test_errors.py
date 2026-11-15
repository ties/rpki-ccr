"""Exceptions and their attributes."""

import gzip
import pathlib
from datetime import datetime, timedelta, timezone

import pytest

import rpki_ccr
from rpki_ccr import AspaPayloadSet, Ccr, ManifestInstance, Vrp

T = datetime(2026, 5, 15, 0, 0, 10, tzinfo=timezone.utc)


def test_hash_mismatch(example_der: bytes) -> None:
    tampered = bytearray(example_der)
    tampered[752] ^= 1
    with pytest.raises(rpki_ccr.HashMismatchError) as info:
        Ccr.decode(bytes(tampered))
    err = info.value
    assert isinstance(err, rpki_ccr.Error) and isinstance(err, ValueError)
    assert err.aspect == "manifests"
    assert len(err.declared) == 32 and len(err.computed) == 32
    assert err.declared != err.computed
    assert "ManifestState: hash mismatch" in str(err)
    ccr = Ccr.decode(bytes(tampered), verify_hashes=False)
    assert ccr.manifests is not None
    assert ccr.manifests.hash == err.declared


def test_not_sorted(example_der: bytes) -> None:
    # Swap the two trust anchor SKIs (22-byte TLVs at 1039 and 1061).
    data = bytearray(example_der)
    first, second = bytes(data[1039:1061]), bytes(data[1061:1083])
    data[1039:1061], data[1061:1083] = second, first
    with pytest.raises(rpki_ccr.HashMismatchError) as hash_info:
        Ccr.decode(bytes(data))
    assert hash_info.value.aspect == "trust_anchors"
    with pytest.raises(rpki_ccr.NotSortedError) as info:
        Ccr.decode(bytes(data), verify_hashes=False)
    assert (info.value.aspect, info.value.what, info.value.index) == (
        "trust_anchors",
        "trust anchor key identifier",
        1,
    )
    ccr = Ccr.decode(bytes(data), verify_hashes=False, check_ordering=False)
    assert ccr.trust_anchors is not None
    assert [s.hex() for s in ccr.trust_anchors] == [second[2:].hex(), first[2:].hex()]
    with pytest.raises(rpki_ccr.NotSortedError):
        ccr.to_der(verify_hashes=False)


def test_der_and_gzip_errors(example_der: bytes) -> None:
    with pytest.raises(rpki_ccr.DerError):
        Ccr.decode(example_der[:100])
    with pytest.raises(rpki_ccr.DerError):
        Ccr.decode(example_der + b"\x00")
    with pytest.raises(rpki_ccr.GzipError):
        Ccr.decode(gzip.compress(example_der)[:-8])
    with pytest.raises(rpki_ccr.Error):
        Ccr.decode(b"")


def test_file_errors(tmp_path: pathlib.Path) -> None:
    missing = tmp_path / "missing.ccr"
    with pytest.raises(FileNotFoundError) as info:
        Ccr.from_file(missing)
    assert info.value.filename == str(missing)
    assert info.value.errno == 2


def test_invalid_values() -> None:
    with pytest.raises(rpki_ccr.InvalidValueError, match="aki must be 20 bytes, got 19"):
        ManifestInstance(hash=bytes(32), size=1000, aki=bytes(19), manifest_number=1, this_update=T, locations=["rsync://a"])
    with pytest.raises(rpki_ccr.InvalidValueError, match="hash must be 32 bytes"):
        ManifestInstance(hash=bytes(31), size=1000, aki=bytes(20), manifest_number=1, this_update=T, locations=["rsync://a"])
    # The draft's lower bound on size (1000 in -11) was dropped afterwards and is not enforced.
    assert ManifestInstance(hash=bytes(32), size=1, aki=bytes(20), manifest_number=1, this_update=T, locations=["rsync://a"]).size == 1
    with pytest.raises(rpki_ccr.InvalidValueError, match="location"):
        ManifestInstance(hash=bytes(32), size=1000, aki=bytes(20), manifest_number=1, this_update=T, locations=[])
    with pytest.raises(rpki_ccr.InvalidValueError, match="maximum is 20"):
        ManifestInstance(hash=bytes(32), size=1000, aki=bytes(20), manifest_number=1 << 159, this_update=T, locations=["rsync://a"])
    big = ManifestInstance(hash=bytes(32), size=1000, aki=bytes(20), manifest_number=(1 << 159) - 1, this_update=T, locations=["rsync://a"])
    assert big.manifest_number == (1 << 159) - 1
    with pytest.raises((OverflowError, ValueError)):
        ManifestInstance(hash=bytes(32), size=1000, aki=bytes(20), manifest_number=-1, this_update=T, locations=["rsync://a"])
    with pytest.raises(rpki_ccr.InvalidValueError):
        ManifestInstance(hash=bytes(32), size=1000, aki=bytes(20), manifest_number=1, this_update=T, locations=["rsync://exämple"])
    with pytest.raises(rpki_ccr.InvalidValueError, match="fractional"):
        ManifestInstance(hash=bytes(32), size=1000, aki=bytes(20), manifest_number=1, this_update=T + timedelta(microseconds=5), locations=["rsync://a"])
    with pytest.raises(TypeError):
        ManifestInstance(hash=bytes(32), size=1000, aki=bytes(20), manifest_number=1, this_update=T.replace(tzinfo=None), locations=["rsync://a"])
    with pytest.raises(rpki_ccr.InvalidValueError):
        AspaPayloadSet(1, [])
    with pytest.raises(rpki_ccr.InvalidValueError, match="AS 0"):
        AspaPayloadSet(1, [0, 2])
    with pytest.raises(rpki_ccr.InvalidValueError, match="own provider list"):
        AspaPayloadSet(1, [1, 2])
    with pytest.raises(rpki_ccr.InvalidValueError, match="at least one state aspect"):
        Ccr(T)
    with pytest.raises(rpki_ccr.InvalidValueError, match="fractional"):
        Ccr(T + timedelta(microseconds=1), trust_anchors=[bytes(20)])
    with pytest.raises(rpki_ccr.InvalidValueError):
        Ccr(T, trust_anchors=[bytes(21)])
    with pytest.raises(rpki_ccr.InvalidValueError, match="invalid object identifier"):
        rpki_ccr.AccessDescription("rsync://a", "not.an.oid")
    with pytest.raises(rpki_ccr.InvalidValueError):
        rpki_ccr.SubjectPublicKeyInfo(bytes.fromhex("3000") + b"\x00")
    with pytest.raises(rpki_ccr.DerError):
        rpki_ccr.SubjectPublicKeyInfo(bytes.fromhex("3000"))
    with pytest.raises(TypeError):
        Ccr(T, roa_payloads=[Vrp(1, "10.0.0.0/8"), "10.0.0.0/8"])


def test_consistency_error() -> None:
    late = ManifestInstance(hash=bytes(32), size=1000, aki=bytes(20), manifest_number=1, this_update=T + timedelta(seconds=1), locations=["rsync://a"])
    with pytest.raises(rpki_ccr.ConsistencyError) as info:
        Ccr(T, manifests=[late])
    assert info.value.aspect == "manifests"
    assert "producedAt" in str(info.value)
