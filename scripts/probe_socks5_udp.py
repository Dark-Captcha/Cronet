#!/usr/bin/env python3
"""Ask a SOCKS5 proxy whether it will relay UDP, and prove it end to end.

Carrying HTTP/3 through a proxy needs the proxy to answer the SOCKS5
UDP ASSOCIATE command (RFC 1928, 0x03) and then relay datagrams. Chromium never
sends that command, so the only way to know whether a vendor supports it is to
ask outside Chromium — which is what this does.

Worth running before any work on the Chromium side: rebuilding the library to
send UDP ASSOCIATE is expensive, and a vendor whose UDP support is switched off,
or sold only at a higher tier, would waste all of it.

Three things are checked in order, and the first failure stops the rest:

    1. the proxy completes a SOCKS5 greeting, and says which authentication
       methods it will take,
    2. it accepts UDP ASSOCIATE and names a relay address,
    3. a real QUIC packet sent through that relay comes back answered — which
       is the only result that proves datagrams actually flow.

Usage:
    scripts/probe_socks5_udp.py socks5://user:password@host:1080
    scripts/probe_socks5_udp.py socks5://host:1080 --target www.google.com
"""

import argparse
import ipaddress
import secrets
import socket
import struct
import sys
import urllib.parse

VERSION = 0x05
AUTH_NONE = 0x00
AUTH_USERNAME_PASSWORD = 0x02
AUTH_UNACCEPTABLE = 0xFF
AUTH_SUBNEGOTIATION_VERSION = 0x01

COMMAND_UDP_ASSOCIATE = 0x03
ADDRESS_IPV4 = 0x01
ADDRESS_DOMAIN = 0x03
ADDRESS_IPV6 = 0x04

AUTH_NAMES = {
    AUTH_NONE: "none",
    AUTH_USERNAME_PASSWORD: "username/password (RFC 1929)",
    AUTH_UNACCEPTABLE: "no acceptable method",
}

# What the proxy says when it will not relay UDP. 0x07 is the one that means
# "command not supported"; the rest are its other refusals, named so the report
# can say which.
REPLY_NAMES = {
    0x00: "succeeded",
    0x01: "general failure",
    0x02: "connection not allowed by ruleset",
    0x03: "network unreachable",
    0x04: "host unreachable",
    0x05: "connection refused",
    0x06: "TTL expired",
    0x07: "command not supported",
    0x08: "address type not supported",
}


# How many datagrams to send before calling a relay unresponsive.
ATTEMPTS = 3


class ProbeFailed(Exception):
    """The proxy did not get far enough for the next question to be asked."""


def receive_exactly(connection: socket.socket, count: int) -> bytes:
    """Exactly `count` bytes, or an error naming what was missing."""
    data = b""
    while len(data) < count:
        chunk = connection.recv(count - len(data))
        if not chunk:
            raise ProbeFailed(
                f"the proxy closed the connection after {len(data)} of "
                f"{count} expected bytes"
            )
        data += chunk
    return data


def greet(connection: socket.socket, offer_credentials: bool) -> int:
    """Open the SOCKS5 conversation.

    Args:
        connection: An open TCP connection to the proxy.
        offer_credentials: Whether to offer username/password as well as none.

    Returns:
        The authentication method the proxy chose.

    Raises:
        ProbeFailed: The proxy is not speaking SOCKS5, or accepted no method.
    """
    methods = [AUTH_NONE, AUTH_USERNAME_PASSWORD] if offer_credentials else [AUTH_NONE]
    connection.sendall(bytes([VERSION, len(methods), *methods]))
    version, chosen = receive_exactly(connection, 2)
    if version != VERSION:
        raise ProbeFailed(f"expected SOCKS5, the proxy answered version {version}")
    if chosen == AUTH_UNACCEPTABLE:
        raise ProbeFailed(
            "the proxy accepted none of the methods offered"
            + ("" if offer_credentials else " — try passing credentials")
        )
    return chosen


def authenticate(connection: socket.socket, username: str, password: str) -> None:
    """Run the RFC 1929 username/password exchange.

    Raises:
        ProbeFailed: The proxy rejected the credentials.
    """
    name, secret = username.encode(), password.encode()
    connection.sendall(
        bytes([AUTH_SUBNEGOTIATION_VERSION, len(name)])
        + name
        + bytes([len(secret)])
        + secret
    )
    _version, status = receive_exactly(connection, 2)
    if status != 0x00:
        raise ProbeFailed(f"the proxy rejected the credentials (status {status})")


def request_udp_associate(connection: socket.socket) -> tuple[str, int]:
    """Ask for a UDP relay, and read back where to send datagrams.

    The requested address is all zeroes, which is how a client says it does not
    know in advance which local port it will send from — what every real client
    does, and what a proxy has to accept for UDP to be usable at all.

    Returns:
        The relay's host and port.

    Raises:
        ProbeFailed: The proxy refused, naming its reply code.
    """
    connection.sendall(
        bytes([VERSION, COMMAND_UDP_ASSOCIATE, 0x00, ADDRESS_IPV4, 0, 0, 0, 0, 0, 0])
    )
    version, reply, _reserved, address_type = receive_exactly(connection, 4)
    if version != VERSION:
        raise ProbeFailed(f"the proxy answered version {version}, not SOCKS5")
    if reply != 0x00:
        raise ProbeFailed(
            f"the proxy refused UDP ASSOCIATE: {REPLY_NAMES.get(reply, reply)}"
            + (
                " — this proxy does not relay UDP, so it cannot carry HTTP/3"
                if reply == 0x07
                else ""
            )
        )

    if address_type == ADDRESS_IPV4:
        host = socket.inet_ntoa(receive_exactly(connection, 4))
    elif address_type == ADDRESS_IPV6:
        host = socket.inet_ntop(socket.AF_INET6, receive_exactly(connection, 16))
    elif address_type == ADDRESS_DOMAIN:
        length = receive_exactly(connection, 1)[0]
        host = receive_exactly(connection, length).decode()
    else:
        raise ProbeFailed(
            f"the proxy named an address type this cannot read: {address_type}"
        )

    port = struct.unpack("!H", receive_exactly(connection, 2))[0]
    return host, port


def encapsulate(target_host: str, target_port: int, payload: bytes) -> bytes:
    """`payload` wrapped in the SOCKS5 UDP request header (RFC 1928 §7)."""
    address = ipaddress.ip_address(target_host)
    kind = ADDRESS_IPV4 if address.version == 4 else ADDRESS_IPV6
    return (
        bytes([0x00, 0x00, 0x00, kind])
        + address.packed
        + struct.pack("!H", target_port)
        + payload
    )


def strip_header(datagram: bytes) -> bytes:
    """The payload of a relayed datagram, with its SOCKS5 header removed."""
    if len(datagram) < 10:
        raise ProbeFailed(
            f"the relay returned {len(datagram)} bytes, too few to be wrapped"
        )
    address_type = datagram[3]
    if address_type == ADDRESS_IPV4:
        start = 10
    elif address_type == ADDRESS_IPV6:
        start = 22
    elif address_type == ADDRESS_DOMAIN:
        start = 5 + datagram[4] + 2
    else:
        raise ProbeFailed(f"the relay used an unreadable address type: {address_type}")
    return datagram[start:]


def quic_probe() -> tuple[bytes, bytes]:
    """A QUIC packet every server answers, and the id its answer must echo.

    A long header carrying a version no server implements draws a Version
    Negotiation packet back, so this proves a QUIC round trip without a
    handshake or any crypto.

    QUIC is used rather than something simpler because it is the traffic that
    matters here, and because a relay may carry it and nothing else: a proxy
    sold as "HTTP/3 support" often forwards port 443 alone, and would fail a
    DNS probe while carrying HTTP/3 perfectly well.
    """
    source_id = secrets.token_bytes(8)
    packet = (
        bytes([0xC0])  # long header, fixed bit set
        + struct.pack("!I", 0x1A2A3A4A)  # a version deliberately unknown
        + bytes([8])
        + secrets.token_bytes(8)  # destination connection id
        + bytes([len(source_id)])
        + source_id
    )
    # A QUIC Initial under 1200 bytes is dropped without a reply.
    return packet.ljust(1200, b"\x00"), source_id


def relay_a_datagram(relay: tuple[str, int], target: str, timeout: float) -> str:
    """Send one QUIC packet through the relay and read the answer.

    Args:
        relay: Where the proxy said to send datagrams.
        target: The QUIC server to reach, as a host name.
        timeout: Seconds to wait for the answer.

    Returns:
        A line describing what came back.

    Raises:
        ProbeFailed: Nothing came back, or it was not a QUIC answer.
    """
    # Resolved to IPv4 on purpose: relays are commonly IPv4-only, and an IPv6
    # destination is then dropped without a reply — which would read as "this
    # proxy cannot carry HTTP/3" when the truth is narrower than that.
    sockaddr = socket.getaddrinfo(target, 443, socket.AF_INET)[0][4]
    address = str(sockaddr[0])

    # Retried because a residential relay drops the occasional first datagram
    # while it picks an exit node, and one lost packet would otherwise read as
    # "this proxy cannot carry HTTP/3" — the wrong answer to the one question
    # this tool exists to settle. UDP has no retransmission of its own.
    answer = b""
    for attempt in range(1, ATTEMPTS + 1):
        packet, _source_id = quic_probe()
        datagram = encapsulate(address, 443, packet)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.settimeout(timeout / ATTEMPTS)
            udp.sendto(datagram, relay)
            try:
                answer, _source = udp.recvfrom(4096)
                break
            except TimeoutError:
                if attempt == ATTEMPTS:
                    raise ProbeFailed(
                        f"the relay accepted the datagram but no QUIC answer "
                        f"came back from {target} ({address}) in {ATTEMPTS} "
                        f"attempts over {timeout}s — the association was "
                        "granted and then not honoured"
                    ) from None

    payload = strip_header(answer)
    if len(payload) < 5:
        raise ProbeFailed(
            f"the relayed answer was {len(payload)} bytes, too short to be QUIC"
        )
    if not payload[0] & 0x80:
        raise ProbeFailed("the relayed answer was not a QUIC long header")
    version = struct.unpack("!I", payload[1:5])[0]
    if version != 0:
        raise ProbeFailed(
            f"expected a Version Negotiation packet, got QUIC version 0x{version:08x}"
        )
    return (
        f"a QUIC Version Negotiation answer came back from {target}, "
        f"{len(payload)} bytes — datagrams travel both ways"
    )


def probe(url: str, target: str, timeout: float) -> int:
    """Run the three checks against `url`, printing each. Returns an exit code."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("socks5", "socks5h"):
        print(f"  {url!r} is not a socks5:// URL", file=sys.stderr)
        return 2
    if not parts.hostname or not parts.port:
        print(f"  {url!r} needs a host and a port", file=sys.stderr)
        return 2

    username = urllib.parse.unquote(parts.username or "")
    password = urllib.parse.unquote(parts.password or "")
    print(f"proxy    : {parts.hostname}:{parts.port}")
    print(f"credentials: {'yes, as ' + username if username else 'none'}")
    print()

    try:
        with socket.create_connection((parts.hostname, parts.port), timeout) as control:
            control.settimeout(timeout)

            chosen = greet(control, offer_credentials=bool(username))
            method = AUTH_NAMES.get(chosen, chosen)
            print(f"  [1/3] greeting  : accepted, method = {method}")
            if chosen == AUTH_USERNAME_PASSWORD:
                if not username:
                    raise ProbeFailed(
                        "the proxy demands credentials and none were given"
                    )
                authenticate(control, username, password)
                print("        authentication: accepted")

            relay = request_udp_associate(control)
            print(f"  [2/3] UDP ASSOCIATE: accepted, relay at {relay[0]}:{relay[1]}")

            # The control connection must stay open, so the relay is used from
            # inside this block: a proxy drops the association when it closes.
            print(f"  [3/3] {relay_a_datagram(relay, target, timeout)}")
    except ProbeFailed as failure:
        print(f"  FAILED: {failure}")
        print()
        print("This proxy cannot carry HTTP/3.")
        return 1
    except OSError as failure:
        print(f"  FAILED: could not reach the proxy: {failure}")
        return 1

    print()
    print("This proxy relays UDP, so it could carry HTTP/3 once Chromium is")
    print("taught to ask — see patches/README.md.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Ask a SOCKS5 proxy whether it will relay UDP for HTTP/3.",
    )
    parser.add_argument("url", help="socks5://[user:password@]host:port")
    parser.add_argument(
        "--target",
        default="cloudflare-quic.com",
        help="a QUIC server to reach through the relay (default: cloudflare-quic.com)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="seconds to wait for each step (default: 10)",
    )
    arguments = parser.parse_args()
    return probe(arguments.url, arguments.target, arguments.timeout)


if __name__ == "__main__":
    sys.exit(main())
