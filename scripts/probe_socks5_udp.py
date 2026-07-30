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
    3. a real DNS query sent through that relay comes back answered — which is
       the only result that proves datagrams actually flow.

Usage:
    scripts/probe_socks5_udp.py socks5://user:password@host:1080
    scripts/probe_socks5_udp.py socks5://host:1080 --resolver 8.8.8.8
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


def dns_query(name: str) -> tuple[bytes, int]:
    """A minimal DNS A-record query, and the transaction id to match it by.

    A DNS query is used rather than a QUIC Initial because a resolver answers
    one packet with one packet, so a reply is unambiguous proof that datagrams
    travelled both ways. QUIC would prove the same thing far less clearly.
    """
    transaction_id = secrets.randbelow(0x10000)
    question = b"".join(bytes([len(part)]) + part.encode() for part in name.split("."))
    return (
        struct.pack("!HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0)
        + question
        + b"\x00"
        + struct.pack("!HH", 1, 1),
        transaction_id,
    )


def relay_a_datagram(relay: tuple[str, int], resolver: str, timeout: float) -> str:
    """Send one DNS query through the relay and read the answer.

    Returns:
        A line describing what came back.

    Raises:
        ProbeFailed: Nothing came back, or it was not the answer asked for.
    """
    query, transaction_id = dns_query("example.com")
    datagram = encapsulate(resolver, 53, query)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.settimeout(timeout)
        udp.sendto(datagram, relay)
        try:
            answer, _source = udp.recvfrom(4096)
        except TimeoutError as expired:
            raise ProbeFailed(
                f"the relay accepted the datagram but nothing came back within "
                f"{timeout}s — the association was granted and then not honoured"
            ) from expired

    payload = strip_header(answer)
    if len(payload) < 4:
        raise ProbeFailed(
            f"the relayed answer was {len(payload)} bytes, too short for DNS"
        )
    returned_id, flags = struct.unpack("!HH", payload[:4])
    if returned_id != transaction_id:
        raise ProbeFailed(
            f"the answer carried transaction id {returned_id}, not {transaction_id}"
        )
    answers = struct.unpack("!H", payload[6:8])[0]
    return (
        f"a DNS answer came back through the relay, "
        f"{answers} record(s), flags 0x{flags:04x}"
    )


def probe(url: str, resolver: str, timeout: float) -> int:
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
            print(f"  [3/3] {relay_a_datagram(relay, resolver, timeout)}")
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
        "--resolver",
        default="1.1.1.1",
        help="the DNS server to reach through the relay (default: 1.1.1.1)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="seconds to wait for each step (default: 10)",
    )
    arguments = parser.parse_args()
    return probe(arguments.url, arguments.resolver, arguments.timeout)


if __name__ == "__main__":
    sys.exit(main())
