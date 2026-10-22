"""Parser and encoder for RPKI Canonical Cache Representation (CCR) files.

A CCR (draft-ietf-sidrops-rpki-ccr) is a DER-encoded snapshot of a validated
RPKI cache. Every object here is immutable, hashable, comparable and
picklable. Key identifiers (20 bytes) and digests (32 bytes) are ``bytes``,
OIDs are dotted strings, AS numbers and manifest numbers are ``int`` and
times are timezone-aware UTC ``datetime`` objects.
"""

from __future__ import annotations

import datetime
import ipaddress
import os
from collections.abc import Iterable, Iterator, Sequence
from typing import final, overload

__version__: str

__all__ = [
    "AccessDescription",
    "AspaPayloadSet",
    "AspaPayloadState",
    "Ccr",
    "ConsistencyError",
    "DerError",
    "DuplicateError",
    "Error",
    "GzipError",
    "HashMismatchError",
    "InvalidValueError",
    "ManifestInstance",
    "ManifestState",
    "NotSortedError",
    "Prefix",
    "RoaPayloadState",
    "RouterKey",
    "RouterKeyState",
    "SubjectPublicKeyInfo",
    "TrustAnchorState",
    "Vrp",
    "__version__",
    "AspaPayloadDiff",
    "AspaUpdate",
    "CcrDiff",
    "IssuerChange",
    "ManifestDiff",
    "RoaPayloadDiff",
    "RouterKeyDiff",
    "TrustAnchorDiff",
]

class Error(ValueError):
    """Base class of every CCR error."""

class DerError(Error):
    """The input is not a well-formed CCR; the message carries the byte offset."""

class GzipError(Error):
    """Gzip decompression failed."""

class HashMismatchError(Error):
    """A state aspect's digest does not match its payload."""

    aspect: str
    """The ``Ccr`` attribute name of the aspect, e.g. ``"manifests"``."""
    declared: bytes
    """The digest stored in the file."""
    computed: bytes
    """The digest computed over the payload."""

class NotSortedError(Error):
    """A sequence is not in ascending order."""

    aspect: str
    what: str
    index: int

class DuplicateError(Error):
    """A sequence contains a duplicate."""

    aspect: str
    what: str
    index: int

class ConsistencyError(Error):
    """A cross-field rule of the specification does not hold."""

    aspect: str

class InvalidValueError(Error):
    """A value given to a constructor violates the specification."""

@final
class Prefix:
    """An IP prefix: an address with all host bits zero and a prefix length.

    Ordering is by address family (IPv4 first), address, then length.
    """

    @overload
    def __new__(
        cls,
        spec: str | ipaddress.IPv4Network | ipaddress.IPv6Network | Prefix,
        length: None = None,
    ) -> Prefix: ...
    @overload
    def __new__(
        cls,
        spec: str | ipaddress.IPv4Address | ipaddress.IPv6Address,
        length: int,
    ) -> Prefix: ...
    @property
    def address(self) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
        """The network address; its ``.version`` is the address family."""
    @property
    def length(self) -> int:
        """The prefix length in bits."""
    def network(self) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
        """The prefix as an ``ipaddress`` network."""
    def __lt__(self, other: Prefix, /) -> bool: ...
    def __le__(self, other: Prefix, /) -> bool: ...
    def __gt__(self, other: Prefix, /) -> bool: ...
    def __ge__(self, other: Prefix, /) -> bool: ...
    def __hash__(self) -> int: ...
    def __eq__(self, other: object, /) -> bool: ...
    def __copy__(self) -> Prefix: ...
    def __deepcopy__(self, memo: dict[int, object], /) -> Prefix: ...

@final
class Vrp:
    """A Validated ROA Payload. Ordering is by ASN, prefix, then max_length."""

    def __new__(
        cls,
        asn: int,
        prefix: Prefix | str | ipaddress.IPv4Network | ipaddress.IPv6Network,
        max_length: int | None = None,
    ) -> Vrp: ...
    @property
    def asn(self) -> int:
        """The origin AS number."""
    @property
    def prefix(self) -> Prefix: ...
    @property
    def max_length(self) -> int:
        """The maximum length; equal to the prefix length when not specified."""
    def __lt__(self, other: Vrp, /) -> bool: ...
    def __le__(self, other: Vrp, /) -> bool: ...
    def __gt__(self, other: Vrp, /) -> bool: ...
    def __ge__(self, other: Vrp, /) -> bool: ...
    def __hash__(self) -> int: ...
    def __eq__(self, other: object, /) -> bool: ...
    def __copy__(self) -> Vrp: ...
    def __deepcopy__(self, memo: dict[int, object], /) -> Vrp: ...

@final
class AccessDescription:
    """An SIA access description: an access method OID and a URI.

    Ordering is by access method, then URI.
    """

    SIGNED_OBJECT: str
    """The ``id-ad-signedObject`` access method, ``1.3.6.1.5.5.7.48.11``."""

    def __new__(cls, uri: str, access_method: str = ...) -> AccessDescription: ...
    @property
    def uri(self) -> str: ...
    @property
    def access_method(self) -> str:
        """The access method as a dotted OID."""
    @property
    def is_signed_object(self) -> bool: ...
    def __lt__(self, other: AccessDescription, /) -> bool: ...
    def __le__(self, other: AccessDescription, /) -> bool: ...
    def __gt__(self, other: AccessDescription, /) -> bool: ...
    def __ge__(self, other: AccessDescription, /) -> bool: ...
    def __hash__(self) -> int: ...
    def __eq__(self, other: object, /) -> bool: ...
    def __copy__(self) -> AccessDescription: ...
    def __deepcopy__(self, memo: dict[int, object], /) -> AccessDescription: ...

@final
class ManifestInstance:
    """A current manifest together with its issuer's subordinate CA certificates.

    ``str()`` gives the line format of the specification's Appendix B and of
    ``rpki-client -f``. Locations given as strings use ``id-ad-signedObject``;
    locations are sorted by (access method, URI) and subordinates are sorted
    and deduplicated, as the Rust constructor does.
    """

    def __new__(
        cls,
        *,
        hash: bytes,
        size: int,
        aki: bytes,
        manifest_number: int,
        this_update: datetime.datetime,
        locations: Iterable[AccessDescription | str],
        subordinates: Iterable[bytes] | None = None,
    ) -> ManifestInstance: ...
    @property
    def hash(self) -> bytes:
        """The SHA-256 digest of the manifest object."""
    @property
    def size(self) -> int:
        """The size of the manifest object in octets (at least 1000)."""
    @property
    def aki(self) -> bytes:
        """The 20-byte key identifier of the manifest issuer."""
    @property
    def manifest_number(self) -> int: ...
    @property
    def this_update(self) -> datetime.datetime: ...
    @property
    def locations(self) -> list[AccessDescription]:
        """The SIA access descriptions of the manifest's EE certificate."""
    @property
    def subordinates(self) -> list[bytes]:
        """The 20-byte key identifiers of the subordinate CA certificates."""
    def __hash__(self) -> int: ...
    def __eq__(self, other: object, /) -> bool: ...
    def __copy__(self) -> ManifestInstance: ...
    def __deepcopy__(self, memo: dict[int, object], /) -> ManifestInstance: ...

@final
class AspaPayloadSet:
    """The provider set of one customer AS (sorted, deduplicated; AS 0 only alone)."""

    def __new__(cls, customer_asn: int, providers: Iterable[int]) -> AspaPayloadSet: ...
    @property
    def customer_asn(self) -> int: ...
    @property
    def providers(self) -> list[int]: ...
    def __hash__(self) -> int: ...
    def __eq__(self, other: object, /) -> bool: ...
    def __copy__(self) -> AspaPayloadSet: ...
    def __deepcopy__(self, memo: dict[int, object], /) -> AspaPayloadSet: ...

@final
class SubjectPublicKeyInfo:
    """A subject public key with its algorithm identifier, parsed from DER."""

    def __new__(cls, der: bytes) -> SubjectPublicKeyInfo: ...
    @property
    def der(self) -> bytes:
        """The complete DER encoding."""
    @property
    def algorithm(self) -> str:
        """The algorithm as a dotted OID."""
    @property
    def parameters(self) -> bytes | None:
        """The DER encoding of the algorithm parameters, if present."""
    @property
    def public_key(self) -> bytes:
        """The ``subjectPublicKey`` octets."""
    @property
    def is_p256_ec(self) -> bool:
        """Whether this is an ECDSA P-256 key as required for BGPsec."""
    def __bytes__(self) -> bytes: ...
    def __hash__(self) -> int: ...
    def __eq__(self, other: object, /) -> bool: ...
    def __copy__(self) -> SubjectPublicKeyInfo: ...
    def __deepcopy__(self, memo: dict[int, object], /) -> SubjectPublicKeyInfo: ...

@final
class RouterKey:
    """A BGPsec router key together with its AS number."""

    def __new__(cls, asn: int, ski: bytes, spki: SubjectPublicKeyInfo | bytes) -> RouterKey: ...
    @property
    def asn(self) -> int: ...
    @property
    def ski(self) -> bytes:
        """The 20-byte subject key identifier of the router certificate."""
    @property
    def spki(self) -> SubjectPublicKeyInfo: ...
    def __hash__(self) -> int: ...
    def __eq__(self, other: object, /) -> bool: ...
    def __copy__(self) -> RouterKey: ...
    def __deepcopy__(self, memo: dict[int, object], /) -> RouterKey: ...

@final
class ManifestState(Sequence[ManifestInstance]):
    """The manifest state of a CCR: a sequence of ``ManifestInstance``, ascending by hash."""

    @property
    def hash(self) -> bytes:
        """The digest declared over the DER-encoded instances."""
    @property
    def most_recent_update(self) -> datetime.datetime:
        """The most recent ``thisUpdate`` among the instances, or the POSIX epoch."""
    def __len__(self) -> int: ...
    @overload
    def __getitem__(self, index: int, /) -> ManifestInstance: ...
    @overload
    def __getitem__(self, index: slice, /) -> list[ManifestInstance]: ...
    def __iter__(self) -> Iterator[ManifestInstance]: ...
    def __contains__(self, item: object, /) -> bool: ...
    def index(self, item: ManifestInstance, start: int = 0, stop: int | None = None, /) -> int: ...
    def count(self, item: ManifestInstance) -> int: ...
    def __hash__(self) -> int: ...
    def __eq__(self, other: object, /) -> bool: ...

@final
class RoaPayloadState(Sequence[Vrp]):
    """The ROA payload state of a CCR: a flattened sequence of ``Vrp`` in encoded order."""

    @property
    def hash(self) -> bytes: ...
    def __len__(self) -> int: ...
    @overload
    def __getitem__(self, index: int, /) -> Vrp: ...
    @overload
    def __getitem__(self, index: slice, /) -> list[Vrp]: ...
    def __iter__(self) -> Iterator[Vrp]: ...
    def __contains__(self, item: object, /) -> bool: ...
    def index(self, item: Vrp, start: int = 0, stop: int | None = None, /) -> int: ...
    def count(self, item: Vrp) -> int: ...
    def __hash__(self) -> int: ...
    def __eq__(self, other: object, /) -> bool: ...

@final
class AspaPayloadState(Sequence[AspaPayloadSet]):
    """The ASPA payload state of a CCR: a sequence of ``AspaPayloadSet``, ascending by customer."""

    @property
    def hash(self) -> bytes: ...
    def __len__(self) -> int: ...
    @overload
    def __getitem__(self, index: int, /) -> AspaPayloadSet: ...
    @overload
    def __getitem__(self, index: slice, /) -> list[AspaPayloadSet]: ...
    def __iter__(self) -> Iterator[AspaPayloadSet]: ...
    def __contains__(self, item: object, /) -> bool: ...
    def index(self, item: AspaPayloadSet, start: int = 0, stop: int | None = None, /) -> int: ...
    def count(self, item: AspaPayloadSet) -> int: ...
    def __hash__(self) -> int: ...
    def __eq__(self, other: object, /) -> bool: ...

@final
class TrustAnchorState(Sequence[bytes]):
    """The trust anchor state of a CCR: a sequence of 20-byte key identifiers, ascending."""

    @property
    def hash(self) -> bytes: ...
    def __len__(self) -> int: ...
    @overload
    def __getitem__(self, index: int, /) -> bytes: ...
    @overload
    def __getitem__(self, index: slice, /) -> list[bytes]: ...
    def __iter__(self) -> Iterator[bytes]: ...
    def __contains__(self, item: object, /) -> bool: ...
    def index(self, item: bytes, start: int = 0, stop: int | None = None, /) -> int: ...
    def count(self, item: bytes) -> int: ...
    def __hash__(self) -> int: ...
    def __eq__(self, other: object, /) -> bool: ...

@final
class RouterKeyState(Sequence[RouterKey]):
    """The router key state of a CCR: a flattened sequence of ``RouterKey`` in encoded order."""

    @property
    def hash(self) -> bytes: ...
    def __len__(self) -> int: ...
    @overload
    def __getitem__(self, index: int, /) -> RouterKey: ...
    @overload
    def __getitem__(self, index: slice, /) -> list[RouterKey]: ...
    def __iter__(self) -> Iterator[RouterKey]: ...
    def __contains__(self, item: object, /) -> bool: ...
    def index(self, item: RouterKey, start: int = 0, stop: int | None = None, /) -> int: ...
    def count(self, item: RouterKey) -> int: ...
    def __hash__(self) -> int: ...
    def __eq__(self, other: object, /) -> bool: ...

@final
class Ccr:
    """A Canonical Cache Representation.

    Build one from Python values with the constructor (aspects set to ``None``
    are absent; empty iterables are present and empty), or read one with
    ``decode`` / ``from_file``. ``to_der`` validates before encoding; an
    object decoded with checks switched off is refused unless the same checks
    are switched off again.
    """

    def __new__(
        cls,
        produced_at: datetime.datetime,
        *,
        manifests: Iterable[ManifestInstance] | None = None,
        roa_payloads: Iterable[Vrp] | None = None,
        aspa_payloads: Iterable[AspaPayloadSet] | None = None,
        trust_anchors: Iterable[bytes] | None = None,
        router_keys: Iterable[RouterKey] | None = None,
    ) -> Ccr: ...
    @staticmethod
    def decode(
        data: bytes,
        *,
        verify_hashes: bool = True,
        check_ordering: bool = True,
        check_consistency: bool = True,
    ) -> Ccr:
        """Decodes a CCR file, plain DER or gzip-compressed."""
    @staticmethod
    def from_file(
        path: str | os.PathLike[str],
        *,
        verify_hashes: bool = True,
        check_ordering: bool = True,
        check_consistency: bool = True,
    ) -> Ccr:
        """Reads and decodes a CCR file; file errors raise ``OSError``."""
    @property
    def version(self) -> int:
        """The format version, always 0."""
    @property
    def hash_algorithm(self) -> str:
        """The digest algorithm, always ``"sha256"``."""
    @property
    def produced_at(self) -> datetime.datetime: ...
    @property
    def manifests(self) -> ManifestState | None: ...
    @property
    def roa_payloads(self) -> RoaPayloadState | None: ...
    @property
    def aspa_payloads(self) -> AspaPayloadState | None: ...
    @property
    def trust_anchors(self) -> TrustAnchorState | None: ...
    @property
    def router_keys(self) -> RouterKeyState | None: ...
    @property
    def extensions(self) -> list[bytes]:
        """The raw DER of state aspects unknown to this library, usually empty."""
    def validate(
        self,
        *,
        verify_hashes: bool = True,
        check_ordering: bool = True,
        check_consistency: bool = True,
    ) -> None:
        """Validates the current contents, raising the same exceptions as ``decode``."""
    def to_der(
        self,
        *,
        verify_hashes: bool = True,
        check_ordering: bool = True,
        check_consistency: bool = True,
    ) -> bytes:
        """Validates, then encodes as DER (byte-exact for decoded objects)."""
    def to_der_gzip(
        self,
        *,
        verify_hashes: bool = True,
        check_ordering: bool = True,
        check_consistency: bool = True,
    ) -> bytes:
        """Validates, then encodes as gzip-compressed DER."""
    def diff(self, after: Ccr) -> CcrDiff:
        """The changes from this (older) CCR to ``after``: a linear merge over
        the canonical sequences; aspects with equal digests are skipped."""
    def __hash__(self) -> int: ...
    def __eq__(self, other: object, /) -> bool: ...

@final
class IssuerChange:
    """The manifests of one issuer (AKI) before and after."""

    @property
    def aki(self) -> bytes: ...
    @property
    def kind(self) -> str:
        """``"added"``, ``"removed"`` or ``"updated"``."""
    @property
    def before(self) -> list[ManifestInstance]:
        """The issuer's manifest instances in the older CCR (usually one)."""
    @property
    def after(self) -> list[ManifestInstance]:
        """The issuer's manifest instances in the newer CCR (usually one)."""
    def __hash__(self) -> int: ...
    def __eq__(self, other: object, /) -> bool: ...

@final
class ManifestDiff:
    """The manifest difference: by hash (``added``/``removed``) and by issuer (``issuers``)."""

    @property
    def added(self) -> list[ManifestInstance]: ...
    @property
    def removed(self) -> list[ManifestInstance]: ...
    @property
    def unchanged(self) -> int: ...
    @property
    def issuers(self) -> list[IssuerChange]:
        """Issuers whose manifests changed, appeared or disappeared, ascending by AKI."""
    @property
    def unchanged_issuers(self) -> int: ...
    def __bool__(self) -> bool: ...

@final
class RoaPayloadDiff:
    """Added and removed VRPs."""

    @property
    def added(self) -> list[Vrp]: ...
    @property
    def removed(self) -> list[Vrp]: ...
    @property
    def unchanged(self) -> int: ...
    def __bool__(self) -> bool: ...

@final
class AspaUpdate:
    """A customer AS whose provider set changed."""

    @property
    def customer_asn(self) -> int: ...
    @property
    def before(self) -> AspaPayloadSet: ...
    @property
    def after(self) -> AspaPayloadSet: ...
    @property
    def providers_added(self) -> list[int]: ...
    @property
    def providers_removed(self) -> list[int]: ...
    def __hash__(self) -> int: ...
    def __eq__(self, other: object, /) -> bool: ...

@final
class AspaPayloadDiff:
    """The ASPA difference, keyed by customer AS."""

    @property
    def added(self) -> list[AspaPayloadSet]: ...
    @property
    def removed(self) -> list[AspaPayloadSet]: ...
    @property
    def updated(self) -> list[AspaUpdate]: ...
    @property
    def unchanged(self) -> int: ...
    def __bool__(self) -> bool: ...

@final
class TrustAnchorDiff:
    """Added and removed trust anchor key identifiers."""

    @property
    def added(self) -> list[bytes]: ...
    @property
    def removed(self) -> list[bytes]: ...
    @property
    def unchanged(self) -> int: ...
    def __bool__(self) -> bool: ...

@final
class RouterKeyDiff:
    """Added and removed router keys."""

    @property
    def added(self) -> list[RouterKey]: ...
    @property
    def removed(self) -> list[RouterKey]: ...
    @property
    def unchanged(self) -> int: ...
    def __bool__(self) -> bool: ...

@final
class CcrDiff:
    """The changes from an older CCR to a newer one, as returned by ``Ccr.diff``.

    An aspect absent on one side is compared as if it were empty; an aspect
    absent on both sides is ``None``. ``bool(diff)`` is true when anything changed.
    """

    @property
    def before_produced_at(self) -> datetime.datetime: ...
    @property
    def after_produced_at(self) -> datetime.datetime: ...
    @property
    def manifests(self) -> ManifestDiff | None: ...
    @property
    def roa_payloads(self) -> RoaPayloadDiff | None: ...
    @property
    def aspa_payloads(self) -> AspaPayloadDiff | None: ...
    @property
    def trust_anchors(self) -> TrustAnchorDiff | None: ...
    @property
    def router_keys(self) -> RouterKeyDiff | None: ...
    def __bool__(self) -> bool: ...
