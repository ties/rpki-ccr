"""Gzip input and file reading."""

import gzip
import os
import pathlib
import time

import pytest

from rpki_ccr import Ccr


def test_gzip_input(example_der: bytes, example: Ccr) -> None:
    assert Ccr.decode(gzip.compress(example_der)) == example
    two_members = gzip.compress(example_der[:700]) + gzip.compress(example_der[700:])
    assert Ccr.decode(two_members) == example


def test_from_file(tmp_path: pathlib.Path, example_der: bytes, example: Ccr) -> None:
    plain = tmp_path / "example.ccr"
    plain.write_bytes(example_der)
    compressed = tmp_path / "example.ccr.gz"
    compressed.write_bytes(gzip.compress(example_der))
    assert Ccr.from_file(plain) == example
    assert Ccr.from_file(str(plain)) == example
    assert Ccr.from_file(compressed) == example
    assert Ccr.from_file(os.fspath(compressed), verify_hashes=False) == example


@pytest.mark.skipif("RPKI_CCR_FILE" not in os.environ, reason="set RPKI_CCR_FILE to a real-world CCR")
def test_real_world_file() -> None:
    path = os.environ["RPKI_CCR_FILE"]
    data = pathlib.Path(path).read_bytes()
    start = time.perf_counter()
    ccr = Ccr.decode(data)
    decoded = time.perf_counter() - start
    assert ccr.roa_payloads is not None and ccr.manifests is not None
    start = time.perf_counter()
    count = sum(1 for _ in ccr.roa_payloads)
    iterated = time.perf_counter() - start
    assert count == len(ccr.roa_payloads)
    start = time.perf_counter()
    assert ccr.to_der() == (gzip.decompress(data) if data[:2] == b"\x1f\x8b" else data)
    encoded = time.perf_counter() - start
    print(f"\n{path}: decode {decoded:.2f}s, iterate {count} VRPs {iterated:.2f}s, "
          f"{len(ccr.manifests)} manifests, validate+encode {encoded:.2f}s")
