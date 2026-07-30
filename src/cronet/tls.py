"""Control over the TLS ClientHello a session sends.

Chrome does two things that make its handshake unrepeatable on purpose: it
shuffles the ClientHello extensions on every connection, and it injects GREASE
values in several places. That is good for the web and awkward for anyone who
needs a handshake to come out the same way twice — reproducing a JA3 or JA4
fingerprint, or testing what a server does with a particular one.

A `TlsProfile` pins the parts that a fingerprint is computed from. Every field
is optional, and one left alone keeps Chromium's own behaviour, so a profile
setting one thing changes one thing.

Example:
    >>> from cronet import Session, TlsProfile
    >>> profile = TlsProfile(permute_extensions=False, grease=False)
    >>> with Session(tls=profile) as session:
    ...     session.get("https://example.com")

Values are IANA code points: cipher suites and extension types as they appear
on the wire, groups as in the TLS Supported Groups registry, signature
algorithms as in the SignatureScheme registry.
"""

from dataclasses import dataclass

# Extensions BoringSSL emits at a fixed place regardless of ordering, so naming
# one in `extension_order` cannot move it. Padding is always emitted last, and
# pre_shared_key must be last by the TLS specification.
UNORDERABLE_EXTENSIONS = frozenset({21, 41})

VERSIONS = frozenset({"1.2", "1.3"})

# What Chromium's SSLConfig can carry; it stores ALPN as a known protocol
# rather than as a free string.
ALPN_PROTOCOLS = frozenset({"h2", "http/1.1", "h3"})


@dataclass(frozen=True, slots=True)
class TlsProfile:
    """The shape of the ClientHello a session sends.

    Attributes:
        cipher_suites: Offered in exactly this order. A GREASE value is still
            prepended when `grease` allows it.
        extension_order: Extension types in the order they must appear. Any
            extension not named is emitted afterwards in BoringSSL's own order,
            so nothing disappears by being left out.
        supported_groups: The supported_groups extension, in this order.
        key_share_groups: Which groups carry a key share. Must be a subset of
            `supported_groups`, in the same relative order.
        signature_algorithms: The signature_algorithms extension, in order.
        alpn: Protocols to offer, from ALPN_PROTOCOLS.
        min_version: "1.2" or "1.3".
        max_version: "1.2" or "1.3".
        grease: False removes every GREASE value from the handshake; True
            forces them on. None keeps Chromium's behaviour, which is on.
        permute_extensions: False makes the extension order deterministic —
            necessary for a repeatable fingerprint, since Chromium shuffles by
            default. Setting `extension_order` implies it.
    """

    cipher_suites: tuple[int, ...] = ()
    extension_order: tuple[int, ...] = ()
    supported_groups: tuple[int, ...] = ()
    key_share_groups: tuple[int, ...] = ()
    signature_algorithms: tuple[int, ...] = ()
    alpn: tuple[str, ...] = ()
    min_version: str | None = None
    max_version: str | None = None
    grease: bool | None = None
    permute_extensions: bool | None = None

    def __post_init__(self) -> None:
        for name in ("min_version", "max_version"):
            value = getattr(self, name)
            if value is not None and value not in VERSIONS:
                raise ValueError(
                    f"{name} must be one of {sorted(VERSIONS)}, not {value!r}"
                )
        unknown = set(self.alpn) - ALPN_PROTOCOLS
        if unknown:
            raise ValueError(
                f"alpn may only contain {sorted(ALPN_PROTOCOLS)}; got {sorted(unknown)}"
            )
        unorderable = set(self.extension_order) & UNORDERABLE_EXTENSIONS
        if unorderable:
            raise ValueError(
                f"these extensions cannot be positioned: {sorted(unorderable)}; "
                "BoringSSL always emits them last"
            )
        if len(set(self.extension_order)) != len(self.extension_order):
            raise ValueError("extension_order names the same extension twice")

    def to_options(self) -> dict[str, object]:
        """This profile as the Cronet experimental option that carries it.

        Returns:
            A mapping with a single "tls_profile" key, or an empty mapping when
            the profile asks for nothing.
        """
        profile: dict[str, object] = {}
        if self.cipher_suites:
            profile["cipher_suites"] = list(self.cipher_suites)
        if self.extension_order:
            profile["extension_order"] = list(self.extension_order)
        if self.supported_groups:
            profile["supported_groups"] = list(self.supported_groups)
        if self.key_share_groups:
            profile["key_share_groups"] = list(self.key_share_groups)
        if self.signature_algorithms:
            profile["signature_algorithms"] = list(self.signature_algorithms)
        if self.alpn:
            profile["alpn"] = list(self.alpn)
        if self.min_version is not None:
            profile["min_version"] = self.min_version
        if self.max_version is not None:
            profile["max_version"] = self.max_version
        if self.grease is not None:
            profile["grease"] = self.grease
        # An explicit order is only meaningful if the shuffle is off, so asking
        # for one asks for that too unless the caller said otherwise.
        permute = self.permute_extensions
        if permute is None and self.extension_order:
            permute = False
        if permute is not None:
            profile["permute_extensions"] = permute
        return {"tls_profile": profile} if profile else {}


# A handshake that comes out identical every time: Chromium's own parameters,
# with the two sources of deliberate variation switched off. Useful when a
# fingerprint has to be stable — for comparing runs, or for pinning one.
DETERMINISTIC = TlsProfile(permute_extensions=False, grease=False)
