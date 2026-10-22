"""pickle, copy and multiprocessing support."""

import copy
import multiprocessing
import pickle
from concurrent.futures import ProcessPoolExecutor

import pytest

import rpki_ccr
from rpki_ccr import Ccr


def round_trip(obj):  # type: ignore[no-untyped-def]
    for protocol in range(2, pickle.HIGHEST_PROTOCOL + 1):
        restored = pickle.loads(pickle.dumps(obj, protocol))
        assert restored == obj
        assert type(restored) is type(obj)
    assert copy.copy(obj) == obj
    assert copy.deepcopy(obj) == obj


def test_pickle_everything(example: Ccr, example_der: bytes) -> None:
    assert example.manifests is not None and example.roa_payloads is not None
    assert example.aspa_payloads is not None and example.router_keys is not None
    round_trip(example)
    round_trip(example.manifests)
    round_trip(example.roa_payloads)
    round_trip(example.aspa_payloads)
    round_trip(example.trust_anchors)
    round_trip(example.router_keys)
    round_trip(example.manifests[3])
    round_trip(example.manifests[3].locations[0])
    round_trip(example.roa_payloads[1])
    round_trip(example.roa_payloads[1].prefix)
    round_trip(example.aspa_payloads[1])
    round_trip(example.router_keys[0])
    round_trip(example.router_keys[0].spki)
    round_trip({example.roa_payloads[1]: 1})

    # A leniently decoded, non-conforming object survives pickling as is.
    tampered = bytearray(example_der)
    tampered[752] ^= 1
    lenient = Ccr.decode(bytes(tampered), verify_hashes=False)
    assert pickle.loads(pickle.dumps(lenient)) == lenient


def test_exceptions_pickle(example_der: bytes) -> None:
    tampered = bytearray(example_der)
    tampered[752] ^= 1
    with pytest.raises(rpki_ccr.HashMismatchError) as info:
        Ccr.decode(bytes(tampered))
    restored = pickle.loads(pickle.dumps(info.value))
    assert isinstance(restored, rpki_ccr.HashMismatchError)
    assert restored.aspect == "manifests"
    assert restored.declared == info.value.declared


def test_multiprocessing(example: Ccr) -> None:
    from _pickle_helper import instance_size

    assert example.manifests is not None
    context = multiprocessing.get_context("spawn")
    with ProcessPoolExecutor(max_workers=2, mp_context=context) as pool:
        sizes = list(pool.map(instance_size, example.manifests))
    assert sizes == [instance.size for instance in example.manifests]
