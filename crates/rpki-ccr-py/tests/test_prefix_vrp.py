"""Prefix and Vrp value types."""

import ipaddress

import pytest

import rpki_ccr
from rpki_ccr import Prefix, Vrp


def test_prefix_constructors() -> None:
    p = Prefix("192.0.2.0/24")
    assert Prefix(ipaddress.ip_network("192.0.2.0/24")) == p
    assert Prefix("192.0.2.0", 24) == p
    assert Prefix(ipaddress.ip_address("192.0.2.0"), 24) == p
    assert Prefix(p) == p
    assert str(p) == "192.0.2.0/24"
    assert repr(p) == "Prefix('192.0.2.0/24')"
    assert p.address == ipaddress.ip_address("192.0.2.0")
    assert p.address.version == 4
    assert p.length == 24
    assert p.network() == ipaddress.ip_network("192.0.2.0/24")
    v6 = Prefix("2001:db8::/32")
    assert v6.address.version == 6
    assert v6.network() == ipaddress.ip_network("2001:db8::/32")
    assert Prefix("::/0").length == 0
    assert Prefix("255.255.255.255/32").length == 32


def test_prefix_rejects_bad_input() -> None:
    with pytest.raises(rpki_ccr.InvalidValueError):
        Prefix("192.0.2.1/24")  # host bits set
    with pytest.raises(rpki_ccr.InvalidValueError):
        Prefix("192.0.2.0/33")
    with pytest.raises(rpki_ccr.InvalidValueError):
        Prefix("not a prefix")
    with pytest.raises(rpki_ccr.InvalidValueError):
        Prefix("192.0.2.0", 33)
    with pytest.raises(TypeError):
        Prefix(42)  # type: ignore[call-overload]
    with pytest.raises(OverflowError):
        Prefix("192.0.2.0", 300)


def test_prefix_ordering_and_hashing() -> None:
    prefixes = [Prefix("2001:db8::/32"), Prefix("198.51.100.0/24"), Prefix("192.0.2.0/25"), Prefix("192.0.2.0/24")]
    assert sorted(prefixes) == [Prefix("192.0.2.0/24"), Prefix("192.0.2.0/25"), Prefix("198.51.100.0/24"), Prefix("2001:db8::/32")]
    assert len({Prefix("192.0.2.0/24"), Prefix("192.0.2.0/24")}) == 1
    assert Prefix("192.0.2.0/24") < Prefix("2001:db8::/32")
    assert (Prefix("192.0.2.0/24") == "192.0.2.0/24") is False


def test_vrp() -> None:
    vrp = Vrp(65536, "198.51.100.0/24", 28)
    assert (vrp.asn, vrp.prefix, vrp.max_length) == (65536, Prefix("198.51.100.0/24"), 28)
    assert str(vrp) == "198.51.100.0/24-28 AS 65536"
    assert repr(vrp) == "Vrp(asn=65536, prefix='198.51.100.0/24', max_length=28)"
    assert Vrp(0, Prefix("192.0.2.0/24")).max_length == 24
    assert str(Vrp(0, ipaddress.ip_network("192.0.2.0/24"))) == "192.0.2.0/24 AS 0"
    assert Vrp(1, "10.0.0.0/8") == Vrp(1, "10.0.0.0/8", 8)
    assert sorted([Vrp(2, "10.0.0.0/8"), Vrp(1, "10.0.0.0/8", 9), Vrp(1, "10.0.0.0/8")]) == [
        Vrp(1, "10.0.0.0/8"),
        Vrp(1, "10.0.0.0/8", 9),
        Vrp(2, "10.0.0.0/8"),
    ]
    with pytest.raises(rpki_ccr.InvalidValueError):
        Vrp(1, "10.0.0.0/8", 7)
    with pytest.raises(rpki_ccr.InvalidValueError):
        Vrp(1, "10.0.0.0/8", 33)
    with pytest.raises(OverflowError):
        Vrp(1 << 32, "10.0.0.0/8")


def test_access_description() -> None:
    sia = rpki_ccr.AccessDescription("rsync://example.net/a.mft")
    assert sia.is_signed_object
    assert sia.access_method == rpki_ccr.AccessDescription.SIGNED_OBJECT == "1.3.6.1.5.5.7.48.11"
    assert repr(sia) == "AccessDescription('rsync://example.net/a.mft')"
    notify = rpki_ccr.AccessDescription("https://example.net/n.xml", "1.3.6.1.5.5.7.48.13")
    assert not notify.is_signed_object
    assert sorted([notify, sia]) == [sia, notify]
    with pytest.raises(rpki_ccr.InvalidValueError):
        rpki_ccr.AccessDescription("")
